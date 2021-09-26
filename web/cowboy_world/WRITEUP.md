# Cowboy World Write Up

This web challenge is a simple SQL injection challenge with a small twist.

Firstly, when you go to the provide challenge URL you will be greeted with a poorly built web app with a login.

However, `robots.txt` has an entry to `/sad.eml`. If you open up the email it says that a `sadcowboy` is only allowed inside this application.

If you put `sadcowboy` as the username and put a simple SQLi injection into the password field like `xyz' OR '1'='1'-- -`

Once you have successfully performed an SQLi on the login page then you will be greeted with the flag.