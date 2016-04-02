#!/usr/bin/env python
# -*- coding: utf-8 -*-
# pylint: disable=fixme,missing-docstring,unused-variable,invalid-name

from __future__ import print_function, division

import atexit
import json
import os
import re
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
import crypto_util
import mongo_store

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


class TokenStorage(object):
    tokens = tuple()

    def __init__(self):
        pass

    def reload(self):
        with app.app_context():
            self.tokens = tuple(mongo.db.logins.distinct('token'))
        return self.tokens

    def tuple(self):
        return self.tokens

tokens = TokenStorage()


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


def user_name(user):
    return '@'+mongo.db.users.find_one(user[1:])['login']


def stream_name(stream):
    return '#'+mongo.db.streams.find_one(stream[1:])['name']


def parse_link(m):
    def link_page(url, title):
        if not title:
            title = url
        return wrap_html('<a href="'+url+'">'+title+'</a>')

    def link_user(user):
        return link_page('javascript:void(0)', user_name(user))

    def link_stream(stream):
        return link_page('javascript:void(0)', stream_name(stream))

    target = m.group(1)
    label = m.group(2)
    if target.startswith('@'):
        return link_user(target)
    if target.startswith('#'):
        return link_stream(target)
    if target.startswith('!'):
        return link_page('javascript:void(0)', '@'+target[1:])
    if target.startswith('http://') or \
       target.startswith('https://') or \
       target.startswith('mailto:'):
        return link_page(target, label)
    return m.group(0)


def wrap_html(text):
    return '||['+text+']||'


def re_iter(regexp, replace, s):
    cur, diff = 0, 0
    s_copy = s
    for res in HTML_RE.finditer(s_copy):
        l, h = res.start(), res.end()
        prev = s[cur:diff+l]
        part = re.sub(regexp, replace, prev)
        s = s[:cur] + part + s[diff+l:]
        diff += len(part)-len(prev)
        cur += len(part) + (h-l)
    return s[:cur] + re.sub(regexp, replace, s[cur:])


def markup(regexp, tag, s, code=False):
    def wrap_all(m):
        return wrap_html('<'+tag+'>'+raw_text(m.group(1))+'</'+tag+'>')

    def wrap_tags(m):
        return wrap_html('<'+tag+'>')+m.group(1)+wrap_html('</'+tag+'>')

    return re_iter(regexp, wrap_all if code else wrap_tags, s)


def raw_text(s):
    return s.replace('<', '&#60;')


def use_entities(s):
    return s.replace('<', '&lt;').replace('>', '&gt;')


def restore_html(m):
    return m.group(1).replace('&lt;', '<').replace('&gt;', '>')


HTML_RE = re.compile(r'\|\|\[(.+?)\]\|\|', re.MULTILINE | re.DOTALL)
LINK_RE = re.compile(r'\B<([^|>]+)\|?([^|>]+)?>\B')
BOLD_RE = re.compile(r'\B\*(.+?)\*\B')
ITAL_RE = re.compile(r'\b_(.+?)_\b')
STRK_RE = re.compile(r'\B~(.+?)~\B')
PREF_RE = re.compile(r'\B```(.+?)```\B[\n]?', re.MULTILINE | re.DOTALL)
CODE_RE = re.compile(r'\B`(.+?)`\B')
QUOT_RE = re.compile(r'^>(.+?)$[\n]?', re.MULTILINE)
LNGQ_RE = re.compile(r'>>>(.+)', re.MULTILINE | re.DOTALL)
MULQ_RE = re.compile(re.escape(wrap_html('</blockquote>')) +
                     re.escape(wrap_html('<blockquote>')), re.MULTILINE)


def parse_msg(msg):
    # TODO move parser to separate class with tests
    msg = msg.replace('&gt;', '>')  # it happens, not from user (&amp; then)
    # markup processing
    msg = markup(PREF_RE, 'pre', msg, True)
    msg = markup(LNGQ_RE, 'blockquote', msg)
    msg = markup(QUOT_RE, 'blockquote', msg)
    msg = re.sub(MULQ_RE, wrap_html('<br/>'), msg)
    msg = markup(CODE_RE, 'code', msg, True)
    msg = markup(STRK_RE, 'strike', msg)
    msg = markup(BOLD_RE, 'b', msg)
    msg = markup(ITAL_RE, 'i', msg)
    msg = re_iter(LINK_RE, parse_link, msg)
    # apply entities for sources
    msg = use_entities(msg)
    # restore markup
    msg = re.sub(HTML_RE, restore_html, msg)
    msg = msg.replace('\n', '<br/>')
    return flask.Markup(msg)


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
    if flask.request.cookies.get('token') in tokens.tuple():
        return flask.redirect('/browse', 302)
    auth = '&redirect_uri='+url_for('login')
    if is_production():
        auth = auth.replace('http://', 'https://', 1)
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


@app.route('/login')
def login():
    # if logging in is not in progress
    if not flask.request.args.get('code'):
        if flask.request.cookies.get('token') in tokens.tuple():
            return flask.redirect('/browse', 302)
        return redirect_page('/', 'Auth required')
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
    next_year = time.strftime("%a, %d-%b-%Y %T GMT",
                              time.gmtime(time.time()+365*24*60*60))
    mongo.db.logins.insert_one({'_id': time.time(),
                                'user': user_info['user'],
                                'token': token,
                                'scope': oauth['scope'].split(',')})
    mongo.db.logins.create_index('token')
    tokens.reload()
    response.set_cookie('token', token, expires=next_year)
    response.set_cookie('user', user_info['user'], expires=next_year)
    return response


@app.route('/logout')
def logout():
    response = flask.make_response(
        redirect_page('https://slack.com', 'Bye'))
    year_ago = time.strftime("%a, %d-%b-%Y %T GMT",
                             time.gmtime(time.time()-365*24*60*60))
    mongo.db.logouts.insert_one({'_id': time.time(),
                                 'user': flask.request.cookies.get('user')})
    response.set_cookie('token', '', expires=year_ago)
    response.set_cookie('user', '', expires=year_ago)
    return response


@app.route('/search')
def search():
    q = flask.request.args.get('q', '')        # query
    s = flask.request.args.get('s', '')        # stream
    c = flask.request.args.get('c', '')        # context
    p = int(flask.request.args.get('p', 0))    # results page
    n = int(flask.request.args.get('n', 100))  # number of results
    mongo.db.search.insert_one({'_id': time.time(),
                                'user': flask.request.cookies.get('user'),
                                'q': q})
    results = []
    if q == '':
        return flask.render_template('search.htm', **locals())
    condition = {'$text': {'$search': q}}
    if c != '':
        ts = ts_from_message_id(c)
        condition = {'ts': {'$lt': ts+60*60, '$gt': ts-60*60}, 'to': s}
    elif s != '':
        condition = {'$text': {'$search': q}, 'to': s}
    query = mongo.db.messages\
        .find(condition,
              sort=[('ts', pymongo.DESCENDING)],
              skip=p*n,
              limit=n)
    total = query.count()
    users, streams = {}, {}
    query = sorted(tuple(query),
                   key=lambda r: (r['ts'], r['ts_dot']), reverse=True)
    for res in query:
        # resolving externals
        if res['from'] not in users:
            users[res['from']] = mongo.db.users.find_one(res['from'])
        if res['to'] not in streams:
            streams[res['to']] = mongo.db.streams.find_one(res['to'])
        res['from'] = users[res['from']]
        res['to'] = streams[res['to']]
        res['ctx'] = message_id(str(res['ts'])+'.'+str(res['ts_dot']),
                                res['from']['_id'])
        res['ts'] = time.ctime(res['ts'])
        res['msg'] = parse_msg(res['msg'])
        results.append(res)
    return flask.render_template('search.htm', **locals())


@app.route('/browse')
def browse():
    s = flask.request.args.get('s', '')         # stream
    p = int(flask.request.args.get('p', 0))     # results page
    n = int(flask.request.args.get('n', 1000))  # number of results
    mongo.db.browse.insert_one({'_id': time.time(),
                                'user': flask.request.cookies.get('user'),
                                's': s})
    results = []
    if s == '':
        f = flask.request.args.get('filter', 'active')
        filters = {
            'all': {},
            'active': {'active': True},
            'archive': {'active': False},
        }
        if f not in filters:
            f = 'active'
        channels = list(mongo.db.streams.find(
            filters[f], sort=[('name', pymongo.ASCENDING)]))
        return flask.render_template('browse.htm', **locals())
    query = mongo.db.messages\
        .find({'to': s},
              sort=[('ts', pymongo.DESCENDING)],
              skip=p*n,
              limit=n)
    total = query.count()
    users, streams = {}, {}
    query = sorted(tuple(query),
                   key=lambda r: (r['ts'], r['ts_dot']), reverse=True)
    for res in query:
        # resolving externals
        if res['from'] not in users:
            users[res['from']] = mongo.db.users.find_one(res['from'])
        if res['to'] not in streams:
            streams[res['to']] = mongo.db.streams.find_one(res['to'])
        res['from'] = users[res['from']]
        res['to'] = streams[res['to']]
        res['ts'] = time.ctime(res['ts'])
        res['msg'] = parse_msg(res['msg'])
        results.append(res)
    return flask.render_template('stream.htm', **locals())


def message_id(timestamp, user):
    return timestamp + '/' + user


def ts_from_message_id(msg_id):
    return int(msg_id.split('/')[0].split('.')[0])


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
                msg_id = message_id(pin['id'], pin['user'])
                pins.append(msg_id)
        bulk.find({'_id': channel['id']}).upsert().update(
            {'$set': {'name': channel['name'],
                      'type': 0,  # public channel
                      'active': not channel['is_archived'],
                      'topic': channel['topic']['value'],
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
                    msg_id = message_id(msg['ts'], msg['user'])
                    bulk.find({'_id': msg_id}).upsert().update(
                        {'$set': {'ts': int(msg['ts'].split('.')[0]),
                                  # TODO: merge ts_dot and ts fields
                                  'ts_dot': int(msg['ts']
                                                .split('.')[1]),
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
    # TODO Check why 'nModified' is always appears in result (duplicates?)
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
    if flask.request.cookies.get('token') not in tokens.tuple() and \
       flask.request.path not in ['/', '/login'] and \
       not os.path.isfile(os.path.join(app.static_folder,
                                       flask.request.path[1:])):
        return redirect_page('/', 'Auth required')


class Scheduler(object):
    bg_task = None

    def __init__(self):
        # scheduler in background
        atexit.register(self.background_stop)
        self.setup_scheduler()
        self.background_task()

    def check_tokens(self):
        pass

    def fetch_messages(self):
        pass  # taking items from generator here

    def setup_scheduler(self):
        schedule.every(30).seconds.do(self.fetch_messages)
        schedule.every(12).hours.do(self.check_tokens)

    def background_task(self):
        schedule.run_pending()
        # restart with proper interval here
        self.bg_task = threading.Timer(schedule.idle_seconds(),
                                       self.background_task)
        self.bg_task.daemon = True  # thread dies with main
        self.bg_task.start()

    def background_stop(self):
        self.bg_task.cancel()
        self.bg_task.join()


def init_app():
    Scheduler()
    tokens.reload()


def encrypt_tokens():
    with app.app_context():
        all_tokens = tuple(mongo.db.logins.distinct('token'))
        cipher = crypto_util.AESCipher(os.environ['CRYPTO_KEY'])
        token_store = mongo_store.MongoStore(mongo.db.tokens)
        timestamp = time.time()
        for token in all_tokens:
            try:
                user = Slacker(token).auth.test().body
            except Error as error:
                print('Token {} problem: {}'.format(token, error))
                continue
            encrypted_token = cipher.encrypt(token)
            token_store[encrypted_token] = {
                'user': user['user_id'],
                'last_check': timestamp,
                'full_access': False,  # extended scope
                'login': user['user']  # duplicate field for debug purpose
            }


if __name__ == "__main__":  # debug branch here
    encrypt_tokens()
    # only for working child process (debug hierarchy)
    if 'WERKZEUG_RUN_MAIN' in os.environ:
        init_app()
    app.run(host='127.0.0.1', port=8080, debug=True)
else:  # __name__ == 'app' for gunicorn production
    init_app()
