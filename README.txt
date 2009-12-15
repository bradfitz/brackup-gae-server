This is an AppEngine server to hold Brackup blobs on Google's infrastructure.

I assume first that you're familiar with Brackup:

  http://code.google.com/p/brackup/

Some instructions:

* appengine/ is the AppEngine server component.  Go to
  http://appspot.com/ to make an AppID ("bob-brackup").  Then get the
  1.3.0 or higher App Engine SDK, tweak
  brackup-gae-server/app.yaml file to match your AppID, then
  "appcfg.py update ." to upload the app to your account.

  -- Now, go to https://<your_appid>.appspot.com/ and login.  This
     makes your UserInfo entity in the database.  That's all.

  -- Now, go back to http://appspot.com/, click your App, then click
     "Datastore Viewer" on the left.  Find your UserInfo entity, click
     it, and modify its "upload_password" to some password you'll use
     for uploading.  Don't use your Google password.  Choose type
     "string".

  -- Now, configure Brackup::Target::GoogleAppEngine's [target] section
     config in brackup with your AppId, email, and password.
