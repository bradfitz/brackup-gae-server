#!/usr/bin/env python
#
# brackup's AppEngine target server-side target.
#
# Copyright 2009 Brad Fitzpatrick <brad@danga.com>
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

import cgi
import datetime
import logging
import mimetypes
import os
import re
import time
import urllib

from google.appengine.api import images
from google.appengine.api import users
from google.appengine.ext import blobstore
from google.appengine.ext import db
from google.appengine.ext import webapp
from google.appengine.ext.webapp import blobstore_handlers
from google.appengine.ext.webapp import template


import wsgiref.handlers


class UserInfo(db.Model):
  """Information about a particular user and their media library."""
  user = db.UserProperty(auto_current_user_add=True)
  upload_password = db.StringProperty(indexed=False)


def get_user_info():
  """Get UserInfo for currently logged in user.

  This will insert the new user if it does not already exist in datastore.

  Returns:
    UserInfo record for user if user is logged in, else None.
  """
  user = users.get_current_user()
  if user is None:
    return None
  else:
    return UserInfo.get_or_insert(key_name='user:%s' % user.email())



def get_authed_user(request):
  """Gets the user from the 'user_email' and 'password' HTTP fields.

  Not from cookies.

  Returns:
    UserInfo for user on success, else None.
  """
  claimed_email = request.get("user_email")
  if not claimed_email:
    return None
  user = UserInfo.get_by_key_name('user:%s' % claimed_email)
  if (user and
      user.upload_password and
      user.upload_password == request.get("password")):
    return user
  return None


class Backup(db.Model):
  """A backup."""
  owner = db.ReferenceProperty(UserInfo, required=True)

  creation = db.DateTimeProperty(auto_now_add=True)
  title = db.StringProperty(indexed=False)

  is_encrypted = db.BooleanProperty(indexed=False);
  manifest = blobstore.BlobReferenceProperty();

  @property
  def display_url(self):
    return '/backup/%s' % self.key().id()

  @property
  def date_yyyy_mm_dd(self):
    """Or empty string."""
    return str(self.creation)[0:10]

  @property
  def title_or_empty_string(self):
    """The real title, or the empty string if none."""
    if not self.title:
      return ""
    return self.title


class Chunk(db.Model):
  """Some chunk, maybe encrypted, maybe split, maybe joined.

  Just dumb bytes to AppEngine.
  """

  # The key is the algorithm, colon, and the lowercase hex digest:
  # "sha1:f1d2d2f924e986ac86fdf7b36c94bcdf32beec15"

  # The actual bytes.
  blob = blobstore.BlobReferenceProperty(indexed=False)

  # Size.  (already in the blobinfo, but denormalized for speed,
  # avoiding extra lookups)
  size = db.IntegerProperty(indexed=False)

  # User emails which reference this chunk.
  owners = db.StringListProperty(indexed=False)


class MainHandler(webapp.RequestHandler):

  def get(self):
    # Provide login/logout URLs.
    user_info = get_user_info()
    is_admin = False
    has_password = False

    if user_info is None:
      login_url = users.create_login_url('/')
    else:
      login_url = users.create_logout_url('/')
      is_admin = users.is_current_user_admin()
      has_password = bool(user_info.upload_password)

    # Render view.
    self.response.out.write(template.render('main.html', {
        "login_url": login_url,
        "user_info": user_info,
        "is_admin": is_admin,
        "has_password": has_password,
        }, debug=True))


class ChangePasswordHandler(webapp.RequestHandler):

  def post(self):
    # Provide login/logout URLs.
    user_info = get_user_info()
    if not user_info or not users.is_current_user_admin:
      self.error(403)
      return

    user_info.upload_password = self.request.get("password") or ""
    user_info.put()
    self.redirect("/");


class ListChunksHandler(webapp.RequestHandler):
  """Return chunks that the server has."""

  def get(self):
    user = get_authed_user(self.request)
    if not user:
      self.error(403)
      return

    chunks = Chunk.all().order('__key__')
    if self.request.get("start"):
      chunks = chunks.filter('__key__ >',
                             db.Key.from_path(Chunk.kind(),
                                              self.request.get("start")))
    chunks = chunks.fetch(1000)

    self.response.headers['Content-Type'] = 'text/plain'
    user_email = self.request.get("user_email")
    for chunk in chunks:
      if chunk.size is not None and user_email in chunk.owners:
        self.response.out.write("%s %d\n" % (chunk.key().name(),
                                             chunk.size))


class GetUploadUrlHandler(webapp.RequestHandler):
  """Handler to return a URL for a script to get an upload URL."""

  def get(self):
    user = get_authed_user(self.request)
    if not user:
      self.error(403)
      return

    count = 1
    if self.request.get("count"):
      count = int(self.request.get("count"))
    lines = ""
    for x in range(0, count):
      lines = lines + blobstore.create_upload_url('/upload') + "\n"
    self.response.headers['Content-Type'] = 'text/plain'
    self.response.out.write(lines)


class UploadHandler(blobstore_handlers.BlobstoreUploadHandler):
  """Handle blobstore post, as forwarded by notification agent."""

  def store_media(self, upload_files, error_messages):
    """Store media information.

    Writes a MediaObject to the datastore for the uploaded file.

    Args:
      upload_files: List of BlobInfo records representing the uploads.
      error_messages: Empty list for storing error messages to report to user.
    """
    if not upload_files:
      error_messages.append('Form is missing upload file field')

    if len(upload_files) != 1:
      error_messages.append('Form has more than one file.')

    def get_param(name, error_message=None):
      """Convenience function to get a parameter from request.

      Returns:
        String value of field if it exists, else ''.  If the key does not exist
        at all, it will return None.
      """
      try:
        value = self.request.params[name]
        if isinstance(value, cgi.FieldStorage):
          value = value.value
        return value or ''
      except KeyError:
        error_messages.append(error_message)
        return None

    size = int(get_param('size'))
    algo_digest = get_param('algo_digest')

    effective_user = None
    user_email = get_param("user_email")
    if user_email:
      claimed_user = UserInfo.get_by_key_name('user:%s' % user_email)
      if (claimed_user and
          claimed_user.upload_password and
          claimed_user.upload_password == get_param('password')):
        effective_user = claimed_user
      
    if not effective_user:
      error_messages.append("No user or correct 'password' argument.")
      return

    if not algo_digest.startswith("sha1"):
      error_messages.append("Only sha1 supported for now.")
      return

    if len(algo_digest) != (len("sha1:") + 40):
      error_messages.append("Bogus length of algo_digest.")
      return

    blob_info, = upload_files

    if size != blob_info.size:
      error_messages.append(
        "Declared size (%d) doesn't match actual size (%d)." %
        (size, blob_info.size))
      return

    # Upload it
    delete_blob = [False]

    def add_chunk_txn():
      chunk = Chunk.get_by_key_name(algo_digest)
      dirty = False
      if not chunk:
        dirty = True
        chunk = Chunk(key_name=algo_digest)
      if chunk.blob:
        delete_blob[0] = True
      else:
        chunk.blob = blob_info.key()
        chunk.size = size
        dirty = True

        # Add owner to this chunk's set of owners.
        if user_email not in chunk.owners:
          chunk.owners.append(user_email)
          dirty = True
        if dirty:
          chunk.put()
    db.run_in_transaction(add_chunk_txn)

    if delete_blob[0]:
      blobstore.delete(blob_info.key())

  def post(self):
    """Do upload post."""
    error_messages = []

    upload_files = self.get_uploads('file')

    self.store_media(upload_files, error_messages)

    if error_messages:
      blobstore.delete(upload_files)
      error_messages = tuple(urllib.quote(m) for m in error_messages)
      error_messages = tuple('error_message=%s' % m for m in error_messages)
      self.redirect('/error?%s' % '&'.join(error_messages))

    # Dummy URL without a handler.  The brackup client just looks at
    # the text of the "Location" header, but doesn't actually try to
    # fetch it:
    self.redirect('/success')

def main():
  application = webapp.WSGIApplication(
      [('/', MainHandler),
       ('/change_password', ChangePasswordHandler),
       ('/get_upload_urls', GetUploadUrlHandler),
       ('/upload', UploadHandler),
       ('/list_chunks', ListChunksHandler),
       ],
      debug=True)
  wsgiref.handlers.CGIHandler().run(application)


if __name__ == '__main__':
  main()
