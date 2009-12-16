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

# Notes:
#    FooKind.all().order('__key__').filter('_key_ >', 'blah')
#  where blah is:
#    db.Key.from_path(FooKind.kind(), 'sha:1111')

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
  blob = blobstore.BlobReferenceProperty()

  # Size.  (redundant; already in the blobinfo)
  size = db.IntegerProperty()


class MainHandler(webapp.RequestHandler):

  def get(self):
    # Provide login/logout URLs.
    user_info = get_user_info()
    if user_info is None:
      login_url = users.create_login_url('/')
    else:
      login_url = users.create_logout_url('/')

    # Render view.
    self.response.out.write(template.render('main.html', {
        "login_url": login_url,
        "user_info": user_info,
        }, debug=True))


class GetUploadUrlHandler(webapp.RequestHandler):
  """Handler to return a URL for a script to get an upload URL."""

  def get(self):
    effective_user = None
    claimed_email = self.request.get("user_email")
    if claimed_email:
      claimed_user = UserInfo.get_by_key_name('user:%s' % claimed_email)
      if claimed_user and \
         claimed_user.upload_password and \
         claimed_user.upload_password == self.request.get("password"):
        effective_user = claimed_user

    if effective_user:
      count = 1
      if self.request.get("count"):
        count = int(self.request.get("count"))
      lines = ""
      for x in range(0, count):
        lines = lines + blobstore.create_upload_url('/upload') + "\n"
      self.response.headers['Content-Type'] = 'text/plain'
      self.response.out.write(lines)
    else:
      self.error(403)


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
    claimed_email = get_param("user_email")
    if claimed_email:
      claimed_user = UserInfo.get_by_key_name('user:%s' % claimed_email)
      if claimed_user and \
             claimed_user.upload_password and \
             claimed_user.upload_password == get_param('password'):
        effective_user = claimed_user
        user_email = claimed_email
      
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
        "Declared size (%d) doesn't match actual size (%d)." % \
           (size, blob_info.size))
      return

    # Upload it
    chunk = Chunk.get_or_insert(key_name=algo_digest)
    if chunk.blob:
      error_messages.append("Already exists.")
      return
    chunk.blob = blob_info.key()
    chunk.size = size
    chunk.put()

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
       ('/get_upload_urls', GetUploadUrlHandler),
       ('/upload', UploadHandler),  # returns a new upload URL
       ],
      debug=True)
  wsgiref.handlers.CGIHandler().run(application)


if __name__ == '__main__':
  main()
