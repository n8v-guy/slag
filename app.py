#!/usr/bin/env python

import atexit
import json
import os
import time
import threading
from zipfile import ZipFile

import flask
from flask.ext.pymongo import PyMongo
from slacker import Slacker

import credentials  # local deploy settings

SLACK_CLIENT_ID = '6154181110.20526331843'
AUTH_LINK = 'https://slack.com/oauth/authorize?team=T064J5B38&client_id=6154181110.20526331843&scope=identify,channels:history,channels:read,files:read,groups:history,groups:read,im:history,im:read,users:read'
LOGIN_LINK = 'https://slack.com/oauth/authorize?team=T064J5B38&client_id=6154181110.20526331843&scope=identify'

app = flask.Flask(__name__)
mongo = PyMongo(app)

timer_thread = threading.Thread()
timer_string = 'START<br/>'

def redirect_msg(url, msg):
    return flask.render_template('redirect.htm',
                                 url_to=url,
                                 message=msg)

@app.route('/')
def index():
    m = mongo
    b = 7/(3-3)
    if flask.request.args.get('code') is None and \
       flask.request.cookies.get('token') is None:
        return redirect_msg(LOGIN_LINK, 'Logging in')
    token = flask.request.cookies.get('token')
    if flask.request.cookies.get('token') is None:
        try:
            oauth = Slacker.oauth.access(
                client_id=SLACK_CLIENT_ID,
                client_secret=os.environ['SLACK_SECRET'],
                code=flask.request.args['code']).body
        except Exception as e:
            oauth = {}
        if oauth.get('ok') is None:
            return redirect_msg(LOGIN_LINK, 'Auth required')
        token = oauth['access_token']
    client = Slacker(token)
    user_info = client.auth.test().body
    response = flask.make_response(str(user_info))
    next_year = time.strftime("%a, %d-%b-%Y %T GMT",
                              time.gmtime(time.time()+365*24*60*60))
    response.set_cookie('token', token, expires=next_year)
    return response

@app.route('/upload')
def upload():
    def import_zip_thread():
        global timer_string
        with ZipFile('archive.zip') as archive:
            with archive.open('channels.json') as channels:
                chans = json.loads(channels.read())
                for chan in chans:
                    mongo.db['channels']
                    timer_string += chan['purpose']['value'] + '<br/>'
                    time.sleep(1)

    def stop_timer_thread():
        global yourThread
        timer_thread.cancel()

    global timer_thread
    if not timer_thread.is_alive():
        timer_thread = threading.Timer(0, import_zip_thread, ())
        timer_thread.start()
        atexit.register(stop_timer_thread)
    return timer_string

def is_local_deploy():
    return 'LOCAL' == os.environ.get('PORT', 'LOCAL')

def is_production_deploy():
    return '1' == os.environ.get('PRODUCTION', '0')

def redirect_to_https():
    if 'http'==flask.request.headers.get('X-Forwarded-Proto', 'https'):
        url = flask.request.url.replace('http://', 'https://', 1)
        return flask.redirect(url, code=301)

if __name__ == "__main__":
    app.config['MONGO_URI'] = os.environ['MONGOLAB_URI']
    app.before_request(redirect_to_https)
    if is_local_deploy():
        app.run(port=8080, debug=True)
    else:
        app.run(host='0.0.0.0', 
                port=int(os.environ['PORT']), 
                debug=not is_production_deploy())
