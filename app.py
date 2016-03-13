#!/usr/bin/env python
# -*- coding: utf-8 -*-

import json
import os
import time
from zipfile import ZipFile

import flask
import flask.ext.pymongo
import pymongo
from slacker import Slacker

import credentials  # local deploy settings

SLACK_TEAM_ID = 'T064J5B38'
SLACK_CLIENT_ID = '6154181110.20526331843'
LOGIN_LINK = ('https://slack.com/oauth/authorize?team=' + SLACK_TEAM_ID +
              '&client_id=' + SLACK_CLIENT_ID + '&scope=identify')
TOKEN_LINK = ('https://slack.com/oauth/authorize?team=' + SLACK_TEAM_ID +
              '&client_id=' + SLACK_CLIENT_ID + '&scope=identify,' +
              'channels:history,channels:read,files:read,'
              'groups:history,groups:read,im:history,im:read,users:read')

app = flask.Flask(__name__)
# TODO eliminate MongoLab mentions
app.config['MONGO_URI'] = os.environ['MONGOLAB_URI']
mongo = flask.ext.pymongo.PyMongo(app)


def is_local_deploy():
    return 'LOCAL' == os.environ.get('PORT', 'LOCAL')


def is_production_deploy():
    return '1' == os.environ.get('PRODUCTION', '0')


def redirect_to_https():
    if 'http' == flask.request.headers.get('X-Forwarded-Proto', 'https'):
        url = flask.request.url.replace('http://', 'https://', 1)
        return flask.redirect(url, code=301)


def redirect_msg(url, msg):
    return flask.render_template('redirect.htm', url_to=url, message=msg)


@app.route('/<path:filename>')  
def send_file(filename):  
    return flask.send_from_directory(app.static_folder, filename)


@app.route('/')
def index():
    if flask.request.args.get('code') is None and \
       flask.request.cookies.get('token') is None:
        return redirect_msg(LOGIN_LINK, 'Auth required')
    token = flask.request.cookies.get('token')
    if flask.request.cookies.get('token') is None:
        try:
            oauth = Slacker.oauth.access(
                client_id=SLACK_CLIENT_ID,
                client_secret=os.environ['SLACK_SECRET'],
                code=flask.request.args['code']).body
        except Exception as e:
            oauth = {}
        # TODO check if our team selected
        if oauth.get('ok') is None:
            return redirect_msg(LOGIN_LINK, 'Auth required')
        token = oauth['access_token']
    client = Slacker(token)
    # TODO check exceptions
    user_info = client.auth.test().body
    response = flask.make_response(
        redirect_msg('/browse', 'Auth success'))
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
    q = flask.request.args.get('q', '')       # query
    p = int(flask.request.args.get('p', 0))   # results page
    n = int(flask.request.args.get('n', 50))  # number of results
    mongo.db.search.insert_one({'_id': time.time(), 
                                'user': flask.request.cookies.get('user'),
                                'q': q})
    results = []
    if q == '':
        return flask.render_template('search.htm', **locals())
    query = mongo.db.import_messages\
        .find({'$text': {'$search': q}}, 
              sort=[('ts', pymongo.DESCENDING)],
              skip=p*n,
              limit=n)
    total = query.count()
    users, streams = {}, {}
    for res in tuple(query):
        # resolving externals
        if res['from'] not in users:
            users[res['from']] = mongo.db.import_users.find_one(res['from'])
        if res['to'] not in streams:
            streams[res['to']] = mongo.db.import_streams.find_one(res['to'])
        res['from'] = users[res['from']]
        res['to'] = streams[res['to']]
        res['ts'] = time.ctime(res['ts'])
        results.append(res)
    return flask.render_template('search.htm', **locals())


@app.route('/browse')
def browse():
    if flask.request.cookies.get('token') is None:
        return redirect_msg(LOGIN_LINK, 'Auth required')
    s = flask.request.args.get('s', '')       # stream
    p = int(flask.request.args.get('p', 0))   # results page
    n = int(flask.request.args.get('n', 1000))# number of results
    mongo.db.browse.insert_one({'_id': time.time(), 
                                'user': flask.request.cookies.get('user'),
                                's': s})
    results = []
    if s == '':
        f = flask.request.args.get('filter', 'active')
        filters = {'all': {}, 'active': {'active': True}, 'archive': {'active': False}, }
        if f not in filters: f = 'active'
        channels = list(mongo.db.import_streams.find(filters[f], sort=[('name', pymongo.ASCENDING)]))
        return flask.render_template('browse.htm', **locals())
    query = mongo.db.import_messages\
        .find({'to': s}, 
              sort=[('ts', pymongo.DESCENDING)],
              skip=p*n,
              limit=n)
    total = query.count()
    users, streams = {}, {}
    for res in tuple(query):
        # resolving externals
        if res['from'] not in users:
            users[res['from']] = mongo.db.import_users.find_one(res['from'])
        if res['to'] not in streams:
            streams[res['to']] = mongo.db.import_streams.find_one(res['to'])
        res['from'] = users[res['from']]
        res['to'] = streams[res['to']]
        res['ts'] = time.ctime(res['ts'])
        results.append(res)
    return flask.render_template('stream.htm', **locals())


@app.route('/import')
def import_zip_thread():
    # TODO add logging around
    with ZipFile('archive.zip') as archive:
        # import users
        with archive.open('users.json') as users_list:
            users = json.loads(users_list.read())
            bulk = mongo.db.import_users.initialize_ordered_bulk_op()
            for user in users:
                bulk.find({'_id': user['id']}).upsert().update(
                    {'$set': {'name': user['profile']['real_name'], 
                              'login': user['name'],
                              'avatar': user['profile']['image_48']}})
            result = bulk.execute()
        # import channels
        with archive.open('channels.json') as channel_list:
            channels = json.loads(channel_list.read())
            bulk = mongo.db.import_streams.initialize_ordered_bulk_op()
            for channel in channels:
                pins = []
                if 'pins' in channel:
                    for pin in channel['pins']:
                        ts = pin['id'].split('.')[0]
                        msg_id = ts + '/' + pin['user']
                        pins.append(msg_id)
                bulk.find({'_id': channel['id']}).upsert().update(
                    {'$set': {'name': channel['name'],
                              'type': 0, # public channel
                              'active': not channel['is_archived'],
                              'topic': channel['topic']['value'],
                              'pins': pins}})
            result = bulk.execute()
            mongo.db.import_streams.create_index('type')
            mongo.db.import_streams.create_index('active')
            # import messages
            files = filter(lambda n: not n.endswith('/'), archive.namelist())
            bulk = mongo.db.import_messages.initialize_ordered_bulk_op()
            for channel in channels:
                continue
                chan_name, chan_id = channel['name'], channel['id']
                for filename in filter(lambda n: n.startswith(chan_name+'/'), files):
                    with archive.open(filename) as day_export:
                        msgs = json.loads(day_export.read())
                        for msg in msgs:
                            if msg.get('subtype') is not None:
                                continue
                            ts = msg['ts'].split('.')[0]
                            msg_id = ts + '/' + msg['user']
                            bulk.find({'_id': msg_id}).upsert().update(
                                {'$set': {'ts': long(ts),
                                          'msg': msg['text'],
                                          'from': msg['user'],
                                          'to': chan_id}})
            #result = bulk.execute()
            mongo.db.import_messages.create_index('ts')
            mongo.db.import_messages.create_index('to')
            mongo.db.import_messages.create_index([('msg', 'text')], default_language='ru')
    skip_fileds = ['upserted', 'modified', 'matched', 'removed', 'inserted']
    for field in skip_fileds:
        result.pop(field, None)
    return 'Import complete!<br />' + str(result)

if __name__ == "__main__":
    app.config['PREFERRED_URL_SCHEME'] = 'https'
    app.before_request(redirect_to_https)
    if is_local_deploy():
        app.run(port=8080, debug=True)
    else:
        app.run(host='0.0.0.0', 
                port=int(os.environ['PORT']), 
                debug=not is_production_deploy())
