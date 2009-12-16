This is an AppEngine server to hold Brackup blobs on Google's infrastructure.

    ************************************************************
    **   WARNING: in-development!  as of 2009-12-15.          **
    **                                                        **
    **   email brad@danga.com if you want to help, but it     **
    **   it should be done soon, I hope.                      **
    ************************************************************

I assume first that you're familiar with Brackup:

  http://code.google.com/p/brackup/

To install and use:

* Fetch the AppEngine 1.3.0+ SDK from:
  http://code.google.com/appengine/downloads.html

* Go to http://appspot.com/ to make an AppID ("bob-brackup").

* modify this project's app.yaml to match your newly-created AppID

* Run:
  $APPENGINE_SDK/appcfg.py update $BRACKUP_GAE_SERVER_DIR

* Now, go to https://<your_appid>.appspot.com/ and login and set your
  upload password.  (the app will prompt you to do that.)

* Now, configure your ~/.brackup.conf [target] section with your
  email, password, and server's URL.  For docs, run:
  perldoc Brackup::Target::GoogleAppEngine

* Enjoy!

This comes with no warranty of any kind.  I trust you've audited the code.


