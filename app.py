#!/usr/bin/env python

import os

from flask import Flask, request, redirect
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
    if 'http'==request.headers.get('X-Forwarded-Proto', 'https'):
        url = request.url.replace('http://', 'https://', 1)
        return redirect(url, code=301)

app = Flask(__name__)
app.config['MONGO_URI'] = os.environ['MONGOLAB_URI']
app.before_request(redirect_to_https)
mongo = PyMongo(app)
#slack = Slacker('<your-slack-api-token-goes-here>')

@app.route('/')
def index():
    return redirect(LOGIN_LINK)

@app.route('/auth')
def auth():
    response = Slacker.oauth.access(
        client_id='6154181110.20526331843',
        client_secret=os.environ['SLACK_SECRET'],
        code=request.args['code'])
    #slack = Slacker(request.args['code'])
    return str(response.body)

@app.route('/crash')
def crash_page():
    raise ValueError('Crash here', 'as planned')


if __name__ == "__main__":
    if is_local_deploy():
        app.run(port=8080, debug=True)
    else:
        app.run(host='0.0.0.0', 
                port=int(os.environ['PORT']), 
                debug=not is_production_deploy())
