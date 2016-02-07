#!/usr/bin/env python

import os

import flask
from flask.ext.pymongo import PyMongo
from slacker import Slacker

import credentials  # local deploy settings

AUTH_LINK = 'https://slack.com/oauth/authorize?team=T064J5B38&client_id=6154181110.20526331843&scope=identify,channels:history,channels:read,files:read,groups:history,groups:read,im:history,im:read,users:read'
LOGIN_LINK = 'https://slack.com/oauth/authorize?team=T064J5B38&client_id=6154181110.20526331843&scope=identify'

def is_local_deploy():
    return 'LOCAL' == os.environ.get('PORT', 'LOCAL')

def is_production_deploy():
    return '1' == os.environ.get('PRODUCTION', '0')

def redirect_to_https():
    if 'http'==flask.request.headers.get('X-Forwarded-Proto', 'https'):
        url = flask.request.url.replace('http://', 'https://', 1)
        return flask.redirect(url, code=301)

app = flask.Flask(__name__)
app.config['MONGO_URI'] = os.environ['MONGOLAB_URI']
app.before_request(redirect_to_https)
mongo = PyMongo(app)

@app.route('/')
def index():
    if 'code' not in flask.request.args.keys():
        return flask.redirect(LOGIN_LINK)
    oauth = Slacker.oauth.access(
        client_id='6154181110.20526331843',
        client_secret=os.environ['SLACK_SECRET'],
        code=flask.request.args['code']).body
    if 'ok' not in oauth.keys():
        return flask.redirect(LOGIN_LINK)
    client = Slacker(oauth['access_token'])
    user_info = client.auth.test().body
    return str(oauth) + '<br />' + str(user_info)

if __name__ == "__main__":
    if is_local_deploy():
        app.run(port=8080, debug=True)
    else:
        app.run(host='0.0.0.0', 
                port=int(os.environ['PORT']), 
                debug=not is_production_deploy())
