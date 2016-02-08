#!/usr/bin/env python
# -*- coding: utf-8 -*-

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
app.config['MONGO_URI'] = os.environ['MONGOLAB_URI']
mongo = PyMongo(app)

timer_thread = threading.Thread()
timer_string = 'START<br/>'

def redirect_msg(url, msg):
    return flask.render_template('redirect.htm',
                                 url_to=url,
                                 message=msg)

@app.route('/')
def index():
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
    response = flask.make_response(
        redirect_msg('/search', 'Auth success'))
    next_year = time.strftime("%a, %d-%b-%Y %T GMT",
                              time.gmtime(time.time()+365*24*60*60))
    mongo.db.logins.insert_one({'_id': time.time(), 
                                'user': user_info['user'],
                                'token': token})
    response.set_cookie('token', token, expires=next_year)
    response.set_cookie('user', user_info['user'], expires=next_year)
    return response

@app.route('/search')
def search():
    if flask.request.cookies.get('token') is None:
        return redirect_msg(LOGIN_LINK, 'Auth required')
    q = flask.request.args.get('q')
    mongo.db.search.insert_one({'_id': time.time(), 
                                'user': flask.request.cookies.get('user'),
                                'q': q})
    if q is None:
        return flask.render_template('search.htm', results=[], q='')
    res = mongo.db.messages.find({'$text': {'$search': q}})
    return flask.render_template('search.htm', results=res[:10], q=q)

@app.route('/import')
def import_zip_thread():
    global timer_string
    ret = 'Done! <br/>'
    with ZipFile('archive.zip') as archive, app.app_context():
        with archive.open('users.json') as users_list:
            users = json.loads(users_list.read())
            bulk = mongo.db.users.initialize_ordered_bulk_op()
            for user in users:
                is_deleted = user['deleted']
                bulk.find({'_id': user['id']}).upsert().update(
                    {'$set': {'name': user['profile']['real_name'], 
                              'login': user['name'],
                              'is_admin': not is_deleted and user['is_admin'],
                              'avatar': user['profile']['image_24'],
                              'mail': user['profile']['email']}})
            result = bulk.execute()
        with archive.open('channels.json') as channels:
            chans = json.loads(channels.read())
            bulk = mongo.db.channels.initialize_ordered_bulk_op()
            for chan in chans:
                bulk.find({'_id': chan['id']}).upsert().update(
                    {'$set': {'name': chan['name'], 
                              'is_archived': chan['is_archived']}})
            result = bulk.execute()
            # import messages
            fnames = filter(lambda n: not n.endswith('/'), archive.namelist())
            bulk = mongo.db.messages.initialize_ordered_bulk_op()
            for chan in chans:
                chan_name, chan_id = chan['name'], chan['id']
                files = filter(lambda n: n.startswith(chan_name+'/'), fnames)
                for f in files:
                    with archive.open(f) as day_export:
                        msgs = json.loads(day_export.read())
                        for msg in msgs:
                            if msg.get('subtype') is None:
                                bulk.find({'_id': msg['ts']}).upsert().update(
                                    {'$set': {'text': msg['text'],
                                              'from': msg['user'],
                                              'channel': chan_id}})
            result = bulk.execute()
    mongo.db.messages.ensure_index([('text', 'text')],
                                   default_language='ru')
    return ret


@app.route('/upload')
def upload():
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
