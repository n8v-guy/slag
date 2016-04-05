#!/usr/bin/env python
# -*- coding: utf-8 -*-
# pylint: disable=fixme,missing-docstring,unused-variable,invalid-name

from __future__ import print_function, division

import atexit
import json
import os
import threading
import time
from zipfile import ZipFile

import flask
import flask_pymongo
import pymongo
import schedule
from slacker import Slacker, Error

# noinspection PyUnresolvedReferences
import credentials  # noqa # pylint: disable=unused-import
import markup
import mongo_store
import store

# TODO ask and save these after app deploy
SLACK_TEAM_ID = 'T064J5B38'
SLACK_CLIENT_ID = '6154181110.20526331843'
BASIC_LINK = ('https://slack.com/oauth/authorize?team=' + SLACK_TEAM_ID +
              '&client_id=' + SLACK_CLIENT_ID + '&scope=team:read,' +
              'users:read,channels:read,channels:history,pins:read,emoji:read')
LOGIN_LINK = ('https://slack.com/oauth/authorize?team=' + SLACK_TEAM_ID +
              '&client_id=' + SLACK_CLIENT_ID + '&scope=identify')
TOKEN_LINK = ('https://slack.com/oauth/authorize?team=' + SLACK_TEAM_ID +
              '&client_id=' + SLACK_CLIENT_ID + '&scope=identify,files:read,' +
              'channels:read,channels:history,groups:history,groups:read,'
              'im:history,im:read,mpim:read,mpim:history,stars:read')

app = flask.Flask(__name__)
# TODO eliminate MongoLab mentions
app.config['MONGO_URI'] = os.environ['MONGOLAB_URI']
mongo = flask_pymongo.PyMongo(app)
with app.app_context() as ctx:
    tokens = store.TokenStore(mongo.db.tokens, ctx,
                              key=os.environ['CRYPTO_KEY'])
    people = mongo_store.MongoStore(mongo.db.users, ctx)
    streams = mongo_store.MongoStore(mongo.db.streams, ctx)


def is_production():
    return __name__ == 'app'


def url_for(endpoint):
    url = flask.url_for(endpoint, _external=True)
    if is_production():
        url = url.replace('http://', 'https://', 1)
    return url


def redirect_page(url, msg):
    return flask.render_template('redirect.htm', url_to=url, message=msg)


def basic_page(title, html):
    return flask.render_template('basic.htm', title=title, html=html)


def cookies_expire_date():
    """:returns: now plus one year date in cookie-expected time format"""
    return time.strftime("%a, %d-%b-%Y %T GMT",
                         time.gmtime(time.time() + 365 * 24 * 60 * 60))


@app.route('/<path:filename>')
def send_file(filename):
    return flask.send_from_directory(app.static_folder, filename)


@app.route('/users')
def active_users():
    domain = flask.request.args.get('domain')
    if domain:
        domain = '@' + domain
    active = []
    with ZipFile('archive.zip') as archive:
        # import users
        with archive.open('users.json') as all_users:
            users = json.loads(all_users.read())
            for user in users:
                if 'deleted' not in user or not user['deleted']:
                    user_login = user['name']
                    if domain:
                        mail = user['profile'].get('email', '')
                        if mail.endswith(domain):
                            user_login = mail.split('@')[0]
                    active.append(user_login)
    return ' '.join([user+'@' for user in active])


@app.route('/')
def index():
    if tokens.is_known_user(flask.request.cookies.get('auth')):
        return flask.redirect('/browse', 302)
    return redirect_page('/login', 'Auth required')


@app.route('/login')
def login():
    # if logging in is not in progress
    if not flask.request.args.get('code'):
        auth = '&redirect_uri='+url_for('login')
        return basic_page(
            'Login',
            '<div class="jumbotron" align="center">'
            '  <h1>You have to authenticate first:</h1>'
            '  <a class="btn btn-default btn-lg" href="{}">'
            '    <img src="https://slack.com/favicon.ico" width="24"/>'
            '    Basic (public channels)'
            '  </a>'
            '  &nbsp;'
            '  <a class="btn btn-default btn-lg" href="{}">'
            '    <img src="https://slack.com/favicon.ico" width="24"/>'
            '    Advanced (import private messaging)'
            '  </a>'
            '</div>'.format(LOGIN_LINK+auth, TOKEN_LINK+auth)
        )
    # login part
    try:
        oauth = Slacker.oauth.access(
            client_id=SLACK_CLIENT_ID,
            client_secret=os.environ['SLACK_SECRET'],
            code=flask.request.args['code'],
            redirect_uri=url_for('login')
        ).body
    except Error:
        oauth = {}
    # TODO check if our team selected
    if oauth.get('ok') is None:
        return basic_page('Auth failed', str(oauth))
    token = oauth['access_token']
    client = Slacker(token)
    # TODO check exceptions
    user_info = client.auth.test().body
    response = flask.make_response(
        redirect_page('/browse', 'Auth success'))
    scope = oauth['scope'].split(',')
    auth_key = tokens.upsert(token, user=user_info, full_access=len(scope) > 1)
    response.set_cookie('auth', auth_key, expires=cookies_expire_date())
    return response


@app.route('/logout')
def logout():
    user_info = get_user_info()
    response = flask.make_response(
        redirect_page('https://slack.com', 'Bye'))
    mongo.db.z_logouts.insert_one({'_id': time.time(),
                                   'user': user_info['login']})
    response.delete_cookie('auth')
    # TODO delete db token data
    return response


# TODO remove after 1 month (after May 5th)
@app.route('/new_auth')
def new_auth():
    response = flask.redirect('/', 302)
    token = flask.request.cookies.get('token')
    if tokens.is_known_token(token):
        auth_key = tokens.get_key_by_known_token(token)
        response.set_cookie('auth', auth_key, expires=cookies_expire_date())
    response.delete_cookie('token')
    response.delete_cookie('user')
    return response


@app.route('/search')
def search():
    user_info = get_user_info()
    q = flask.request.args.get('q', '')        # query
    s = flask.request.args.get('s', '')        # stream
    c = flask.request.args.get('c', '')        # context
    p = int(flask.request.args.get('p', 0))    # results page
    n = int(flask.request.args.get('n', 100))  # number of results
    mongo.db.z_search.insert_one({'_id': time.time(),
                                  'user': user_info['login'],
                                  'q': q})
    results = []
    if q == '':
        return flask.render_template('search.htm', **locals())
    condition = {'$text': {'$search': q}}
    if c != '':
        ts = ts_from_message_uid(c)
        condition = {'ts': {'$lt': ts+60*60, '$gt': ts-60*60}, 'to': s}
    elif s != '':
        condition = {'$text': {'$search': q}, 'to': s}
    query = mongo.db.messages\
        .find(condition,
              sort=[('ts', pymongo.DESCENDING)],
              skip=p*n,
              limit=n)
    total = query.count()
    for res in query:
        res['from'] = people.get_row(res['from'])
        res['to'] = streams.get_row(res['to'])
        res['ctx'] = message_uid(res['from']['_id'], str(res['ts']))
        res['ts'] = time.ctime(res['ts'])
        res['msg'] = flask.Markup(
            markup.Markup(res['msg'], people, streams))
        results.append(res)
    return flask.render_template('search.htm', **locals())


def get_user_info():
    enc_key = flask.request.cookies.get('auth')
    assert tokens.is_known_user(enc_key)
    return tokens[enc_key]


@app.route('/browse')
def browse():
    user_info = get_user_info()
    s = flask.request.args.get('s', '')         # stream
    p = int(flask.request.args.get('p', 0))     # results page
    n = int(flask.request.args.get('n', 1000))  # number of results
    mongo.db.z_browse.insert_one({'_id': time.time(),
                                  'user': user_info['login'],
                                  's': s})
    results = []
    if s == '':
        f = flask.request.args.get('filter')
        my_channels = people[user_info['user']].get('channels')
        if f == 'my' and user_info['full_access'] and my_channels:
            channels = [streams.get_row(k) for k, v in streams.items()
                        if k in my_channels]
        elif f == 'all':
            channels = [streams.get_row(k) for k, v in streams.items()
                        if v['type'] == 0]
        elif f == 'archive':
            channels = [streams.get_row(k) for k, v in streams.items()
                        if v['type'] == 0 and not v['active']]
        else:  # by default, f == 'active':
            f = 'active'
            channels = [streams.get_row(k) for k, v in streams.items()
                        if v['type'] == 0 and v['active']]
        return flask.render_template('browse.htm', **locals())
    query = mongo.db.messages\
        .find({'to': s},
              sort=[('ts', pymongo.DESCENDING)],
              skip=p*n,
              limit=n)
    total = query.count()
    for res in query:
        # TODO optimize MongoStore class to save '_id' field in values
        res['from'] = people.get_row(res['from'])
        res['to'] = streams.get_row(res['to'])
        res['ts'] = time.ctime(res['ts'])
        res['msg'] = flask.Markup(
            markup.Markup(res['msg'], people, streams))
        results.append(res)
    return flask.render_template('stream.htm', **locals())


def message_uid(stream, timestamp):
    return stream + '_' + timestamp


def ts_from_message_uid(msg_uid):
    print(msg_uid)
    return float(msg_uid.split('_')[1])


@app.route('/import', methods=['GET', 'POST'])
def upload():
    # TODO check admin rights here
    if is_production():
        return redirect_page('/browse', 'Access denied')
    archive = flask.request.files.get('archive')
    if archive and archive.filename.endswith('.zip'):
        archive.save('archive.zip')
        return redirect_page('/import_db', archive.filename + ' saved')
    return basic_page(
        'Archive upload',
        '<form action="" method="POST" enctype="multipart/form-data">'
        ' <div class="input-group input-group-lg col-md-7" align="center">'
        '  <span class="input-group-addon">Select .zip archive</span>'
        '   <input type="file" name="archive" class="form-control"/>'
        '   <span class="input-group-btn">'
        '    <input type="submit" class="btn btn-primary" value="Import"/>'
        '   </span>'
        '  </span>'
        ' </div>'
        '</form>')


def import_users(archive):
    with archive.open('users.json') as users_list:
        users = json.loads(users_list.read())
        bulk = mongo.db.users.initialize_ordered_bulk_op()
        for user in users:
            bulk.find({'_id': user['id']}).upsert().update(
                {'$set': {'name': user['profile']['real_name'],
                          'login': user['name'],
                          'avatar': user['profile']['image_72']}})
        # manual insert for slackbot user
        bulk.find({'_id': 'USLACKBOT'}).upsert().update(
            {'$set': {'name': 'slackbot',
                      'login': 'slackbot',
                      'avatar': 'https://a.slack-edge.com/'
                                '0180/img/slackbot_72.png'}})
        bulk.execute()


def import_channels(channel_list):
    channels = json.loads(channel_list.read())
    bulk = mongo.db.streams.initialize_ordered_bulk_op()
    for channel in channels:
        pins = []
        if 'pins' in channel:
            for pin in channel['pins']:
                msg_uid = message_uid(channel['id'], pin['id'])
                pins.append(msg_uid)
        bulk.find({'_id': channel['id']}).upsert().update(
            {'$set': {'name': channel['name'],
                      'type': 0,  # public channel
                      'active': not channel['is_archived'],
                      'topic': channel['topic']['value'],
                      'purpose': channel['purpose']['value'],
                      'pins': pins}})
    bulk.execute()
    return channels


def import_messages(channels, archive):
    # TODO check additional useful fields for these types
    # TODO formatting at https://api.slack.com/docs/formatting/builder
    types_import = {
        # useful
        '', 'me_message',
        'file_share', 'file_mention',
        'reminder_add', 'reminder_delete',
        'channel_purpose', 'channel_topic', 'channel_name',
        # useless
        'bot_add', 'bot_remove',
        'channel_join', 'channel_leave',
        'channel_archive', 'channel_unarchive'}
    # format is not supported yet
    types_ignore = {'pinned_item', 'file_comment', 'bot_message'}
    files = [n for n in archive.namelist()
             if not n.endswith(os.path.sep)]
    bulk = mongo.db.messages.initialize_ordered_bulk_op()
    for channel in channels:
        chan_id = channel['id']
        for fname in [n for n in files
                      if n.startswith(channel['name'] + os.path.sep)]:
            with archive.open(fname) as day_export:
                msgs = json.loads(day_export.read())
                for msg in msgs:
                    stype = msg.get('subtype', '')
                    if stype not in types_import:
                        if stype not in types_ignore:
                            types_ignore.add(stype)
                        continue
                    msg_id = message_uid(channel['id'], msg['ts'])
                    bulk.find({'_id': msg_id}).upsert().update(
                        {'$set': {'ts': float(msg['ts']),
                                  'type': hash(stype),
                                  'msg': msg['text'],
                                  'from': msg['user'],
                                  'to': chan_id}})
    return bulk.execute(), types_ignore


@app.route('/import_db')
def import_db():
    # TODO convert this to background task
    # TODO check admin rights here
    if is_production():
        return redirect_page('/browse', 'Admin rights required')
    # TODO add logging around
    with ZipFile('archive.zip') as archive:
        import_users(archive)
        # import channels
        with archive.open('channels.json') as channel_list:
            channels = import_channels(channel_list)
            # import messages
            result, types_new = import_messages(channels, archive)
            mongo.db.messages.create_index('ts')
            mongo.db.messages.create_index('to')
            mongo.db.messages.create_index('type')
            mongo.db.messages.create_index('from')
            mongo.db.messages.create_index([('msg', 'text')],
                                           default_language='ru')
    skip_fields = ['upserted', 'modified', 'matched', 'removed', 'inserted']
    for field in skip_fields:
        result.pop(field, None)
    return basic_page('Archive import complete',
                      'Import complete!<br />' +
                      str(result) + '<br/>' +
                      str(types_new))


@app.before_request
def redirect_to_https():
    is_http = flask.request.is_secure or \
              flask.request.headers.get('X-Forwarded-Proto') == 'http'
    if is_http and is_production():
        url = flask.request.url.replace('http://', 'https://', 1)
        return flask.redirect(url, code=301)


@app.before_request
def check_auth():
    if tokens.is_known_user(flask.request.cookies.get('auth')):
        return
    if flask.request.path in ['/new_auth', '/login'] or \
       os.path.isfile(os.path.join(app.static_folder, flask.request.path[1:])):
        return
    if flask.request.cookies.get('token'):
        return flask.redirect('/new_auth', 302)
    return redirect_page('/login', 'Auth required')


class Scheduler(object):
    bg_task = None

    def __init__(self):
        # scheduler in background
        atexit.register(self.background_stop)
        self.setup_scheduler()
        self.background_task()

    @staticmethod
    def validate_tokens():
        print('Validating tokens')
        for token, enc_key in tokens.decrypt_keys_map().items():
            time.sleep(1)
            print('Check token', token)
            try:
                user_info = Slacker(token).auth.test().body
            except Error as err:
                print('Error for this token:', err)
                del tokens[enc_key]
                continue
            print('Valid token')
            tokens.upsert(token, user_info)

    @staticmethod
    def fetch_user_channels():
        print('Fetching user channels here')
        for token, enc_key in tokens.decrypt_keys_map().items():
            user_info = tokens[enc_key]
            if not user_info['full_access']:
                continue
            time.sleep(1)
            print('Fetch channels for', user_info['login'])
            try:
                all_ch = Slacker(token).channels.list(exclude_archived=1).body
            except Error as err:
                print('Fetch channels error:', err)
                continue
            print('Channels fetched')
            channels_list = [
                channel['id']
                for channel in all_ch['channels'] if channel['is_member']
                ]
            people.set_field(user_info['user'], 'channels', channels_list)

    def setup_scheduler(self):
        schedule.every(11).hours.do(self.fetch_user_channels)
        schedule.every(12).hours.do(self.validate_tokens)

    def background_task(self):
        schedule.run_pending()
        # restart with proper interval here
        self.bg_task = threading.Timer(schedule.idle_seconds(),
                                       self.background_task)
        self.bg_task.daemon = True  # thread dies with main
        self.bg_task.start()

    def background_stop(self):
        if self.bg_task:
            self.bg_task.cancel()
            self.bg_task.join()


def init_app():
    Scheduler()


if __name__ == "__main__":  # debug branch here
    # only for working child process (debug hierarchy)
    if 'WERKZEUG_RUN_MAIN' in os.environ:
        init_app()
    app.run(host='127.0.0.1', port=8080, debug=True)
else:  # __name__ == 'app' for gunicorn production
    init_app()
