# -*- coding: utf-8 -*-
"""Initial setup instructions & config for local deploy"""
# pylint: disable=pointless-string-statement

"""
First, you need to setup everything locally, by uncommenting and setting up
all these environment variables, but you shouldn't commit them to the repo or
to the production server, since having private information in a source code
is a bad smell practice.
It would be better to set them up as the environment variables during your
production deploy process, so nobody having access to the source code will not
have credentials for your instance.

After setting up on your machine, you can ignore these local changes by command
git update-index --assume-unchanged $THIS_FILE

Then you need to create own 'client app' for Slack here:
https://api.slack.com/apps/new

The only important field there is 'Redirect URI(s)',
which should point to your production & local servers with '/login' part, like:

https://your_domain.here/login
http://127.0.0.1:8080/login

After submitting this 'create app' form you'll get two important credentials:
Client ID & client secret, you'll need them to authenticate your team members,
so put these values to environment as:
"""
# os.environ['SLACK_CLIENT_ID'] = '1234567890.0987654321'
# os.environ['SLACK_CLIENT_SECRET'] = 'beef0123456789dead'
"""
The next step is getting base token & your team ID,
go to the https://api.slack.com/docs/oauth-test-tokens for generating first,
then to the https://api.slack.com/methods/auth.test/test for getting second:
"""
# os.environ['SLACK_TEAM_TOKEN'] = 'beef-123456-0987dead'
# os.environ['SLACK_TEAM_ID'] = 'T999XXX88'
"""
We're almost done here, now you need to put your MongoDB instance uri
(if you don't know what is it, try to use free quota at https://mlab.com/),
encrypting key (it can be any random, but constant input), plus optional key
for https://rollbar.com/ service (crash reporting), which you can skip:
"""
# os.environ['MONGO_URI'] = ''
# os.environ['CRYPTO_KEY'] = ''
# os.environ['ROLLBAR_KEY'] = ''
"""
That's it, I hope it's done quickly & easily. But wait, couple more optional
environment variables: DEBUG_SERVER (set to '1') to enable stacktrace & debug
on production server, and PORT to override port number in production (like if
using Heroku to deploy with). Ask me if you still have any questions.
"""
