#!/usr/bin/env python

import os
import sys

from flask import Flask, request, redirect
from flask.ext.pymongo import PyMongo

import credentials  # local deploy settings

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
    return 'Hi there, ' + sys.version

@app.route('/auth')
def auth():
    return str(request.args)

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
