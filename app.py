#!/usr/bin/env python
# -*- coding: utf-8 -*-
# pylint: disable=fixme,missing-docstring,unused-variable,invalid-name
# pylint: disable=too-many-public-methods

from __future__ import print_function, division

import atexit
import collections
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


class FlaskExt(flask.Flask):
    _HOOK_ROUTE_PROP = 'flask_ext_route'
    RouteArgs = collections.namedtuple('RouteArgs', ['args', 'kwargs'])

    @staticmethod
    def route(*args, **kwargs):
        def wrap(fn):
            route_rules = getattr(fn, FlaskExt._HOOK_ROUTE_PROP, [])
            route_rules.append(FlaskExt.RouteArgs(args, kwargs))
            setattr(fn, FlaskExt._HOOK_ROUTE_PROP, route_rules)
            return fn
        return wrap

    def _hook_routes(self):
        for field in [getattr(self, name) for name in dir(self)]:
            route_rules = getattr(field, FlaskExt._HOOK_ROUTE_PROP, [])
            for route_rule in route_rules:
                super(FlaskExt, self).route(
                    *route_rule.args, **route_rule.kwargs)(field)

    def __init__(self, resource_name):
        super(FlaskExt, self).__init__(resource_name)
        self._hook_routes()


class WebServer(FlaskExt):
    """Wrapper for web-server functionality"""
    def __init__(self):
        super(WebServer, self).__init__(__name__)
        self.before_request(WebServer.redirect_to_https)
        self.before_request(self.check_auth)
        # TODO eliminate MongoLab mentions
        self.config['MONGO_URI'] = os.environ['MONGOLAB_URI']
        self.mongo = flask_pymongo.PyMongo(self)
        self.scheduler = Scheduler(self)
        with self.app_context() as ctx:
            self.tokens = store.TokenStore(self.mongo.db.tokens, ctx,
                                           key=os.environ['CRYPTO_KEY'])
            self.people = mongo_store.MongoStore(self.mongo.db.users, ctx)
            self.streams = mongo_store.MongoStore(self.mongo.db.streams, ctx)

    @staticmethod
    def start():
        if __name__ == '__main__':  # if starting in debug mode
            # check main app process
            if os.environ.get('WERKZEUG_RUN_MAIN', 'false') == 'true':
                app = WebServer()
            else:  # lightweight starter for Werkzeug reloader
                app = flask.Flask(  # pylint: disable=redefined-variable-type
                    __name__)
            if WebServer.is_forced_debug():
                app.run(host='0.0.0.0', port=int(os.environ.get('PORT')),
                        debug=True)
            else:
                app.run(host='127.0.0.1', port=8080, debug=True)
        else:  # __name__ == 'app' for gunicorn production
            WebServer()

    @staticmethod
    def is_forced_debug():
        return os.environ.get('DEBUG_SERVER', '0') == '1'

    @staticmethod
    def is_production():
        return __name__ == 'app' or WebServer.is_forced_debug()

    @staticmethod
    def url_for(endpoint):
        url = flask.url_for(endpoint, _external=True)
        if WebServer.is_production():
            url = url.replace('http://', 'https://', 1)
        return url

    @staticmethod
    def redirect_page(url, msg):
        return flask.render_template('redirect.htm', url_to=url, message=msg)

    @staticmethod
    def basic_page(title, html):
        return flask.render_template('basic.htm', title=title, html=html)

    @staticmethod
    def cookies_expire_date():
        """:returns: now plus one year date in cookie-expected time format"""
        return time.strftime("%a, %d-%b-%Y %T GMT",
                             time.gmtime(time.time() + 365 * 24 * 60 * 60))

    @FlaskExt.route('/<path:filename>')
    def send_file(self, filename):
        return flask.send_from_directory(self.static_folder, filename)

    @staticmethod
    @FlaskExt.route('/users')
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
                    if 'deleted' in user and user['deleted']:
                        continue
                    user_login = user['name']
                    mail = user['profile'].get('email', '')
                    if domain and mail.endswith(domain):
                        user_login = mail.split('@')[0]
                    active.append(user_login)
        return ' '.join([user+'@' for user in active])

    @FlaskExt.route('/')
    def index(self):
        if self.tokens.is_known_user(flask.request.cookies.get('auth')):
            return flask.redirect('/browse', 302)
        return WebServer.redirect_page('/login', 'Auth required')

    @FlaskExt.route('/login')
    def login(self):
        if flask.request.args.get('code'):
            return self.login_oauth()
        # logging in is not in progress
        auth = '&redirect_uri=' + WebServer.url_for('login')
        return WebServer.basic_page(
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

    @FlaskExt.route('/logout')
    def logout(self):
        user_info = self.get_user_info()
        response = flask.make_response(
            WebServer.redirect_page('https://slack.com', 'Bye'))
        self.mongo.db.z_logouts.insert_one({'_id': time.time(),
                                            'user': user_info['login']})
        response.delete_cookie('auth')
        # TODO delete db token data
        return response

    # TODO remove after 1 month (after May 5th)
    @FlaskExt.route('/new_auth')
    def new_auth(self):
        response = flask.redirect('/', 302)
        token = flask.request.cookies.get('token')
        if self.tokens.is_known_token(token):
            auth_key = self.tokens.get_key_by_known_token(token)
            response.set_cookie('auth', auth_key,
                                expires=WebServer.cookies_expire_date())
        response.delete_cookie('token')
        response.delete_cookie('user')
        return response

    @FlaskExt.route('/search')
    def search(self):
        user_info = self.get_user_info()
        q = flask.request.args.get('q', '')        # query
        s = flask.request.args.get('s', '')        # stream
        c = flask.request.args.get('c', '')        # context
        p = int(flask.request.args.get('p', 0))    # results page
        n = int(flask.request.args.get('n', 100))  # number of results
        self.mongo.db.z_search.insert_one({'_id': time.time(),
                                           'user': user_info['login'],
                                           'q': q})
        results = []
        if q == '':
            return flask.render_template('search.htm', **locals())
        channels, f = self.filter_streams(user_info, 'all')
        channels = [chan['_id'] for chan in channels]
        condition = {'$text': {'$search': q}, 'to': {'$in': channels}}
        if c != '':
            ts = WebServer.ts_from_message_uid(c)
            condition = {'ts': {'$lt': ts+60*60, '$gt': ts-60*60}, 'to': s}
        elif s != '':
            condition = {'$text': {'$search': q}, 'to': s}
        query = self.mongo.db.messages.find(
            condition,
            sort=[('ts', pymongo.DESCENDING)],
            skip=p*n,
            limit=n)
        total = query.count()
        results = self.prepare_messages(query)
        return flask.render_template('search.htm', **locals())

    @FlaskExt.route('/browse')
    def browse(self):
        user_info = self.get_user_info()
        s = flask.request.args.get('s', '')         # stream
        p = int(flask.request.args.get('p', 0))     # results page
        n = int(flask.request.args.get('n', 1000))  # number of results
        self.mongo.db.z_browse.insert_one({'_id': time.time(),
                                           'user': user_info['login'],
                                           's': s})
        results = []
        if s == '':
            f = flask.request.args.get('filter', 'my')
            channels, f = self.filter_streams(user_info, f)
            return flask.render_template('browse.htm', **locals())
        query = self.mongo.db.messages.find(
            {'to': s},
            sort=[('ts', pymongo.DESCENDING)],
            skip=p*n,
            limit=n)
        total = query.count()
        results = self.prepare_messages(query)
        return flask.render_template('stream.htm', **locals())

    @staticmethod
    @FlaskExt.route('/import', methods=['GET', 'POST'])
    def upload():
        # TODO check admin rights here
        if WebServer.is_production():
            return WebServer.redirect_page('/browse', 'Access denied')
        archive = flask.request.files.get('archive')
        if archive and archive.filename.endswith('.zip'):
            archive.save('archive.zip')
            return WebServer.redirect_page('/import_db',
                                           archive.filename + ' saved')
        return WebServer.basic_page(
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

    @FlaskExt.route('/import_db')
    def import_db(self):
        # TODO convert this to background task
        # TODO check admin rights here
        if WebServer.is_production():
            return WebServer.redirect_page('/browse', 'Access denied')
        # TODO add logging around
        with ZipFile('archive.zip') as archive:
            self.import_users(archive)
            # import channels
            with archive.open('channels.json') as channel_list:
                channels = self.import_channels(channel_list)
                # import messages
                result, types_new = self.import_messages(channels, archive)
                self.mongo.db.messages.create_index('ts')
                self.mongo.db.messages.create_index('to')
                self.mongo.db.messages.create_index('type')
                self.mongo.db.messages.create_index('from')
                self.mongo.db.messages.create_index([('msg', 'text')],
                                                    default_language='ru')
        skip_fields = ['upserted', 'modified', 'matched']
        for field in skip_fields:
            result.pop(field, None)
        return WebServer.basic_page('Archive import complete',
                                    'Import complete!<br />' +
                                    str(result) + '<br/>' +
                                    str(types_new))

    @staticmethod
    def redirect_to_https():
        is_http = flask.request.is_secure or \
                  flask.request.headers.get('X-Forwarded-Proto') == 'http'
        if is_http and WebServer.is_production():
            url = flask.request.url.replace('http://', 'https://', 1)
            return flask.redirect(url, code=301)

    def check_auth(self):
        if self.tokens.is_known_user(flask.request.cookies.get('auth')):
            return
        if flask.request.path in ['/new_auth', '/login'] or \
           os.path.isfile(os.path.join(self.static_folder,
                                       flask.request.path[1:])):
            return
        if flask.request.cookies.get('token'):
            return flask.redirect('/new_auth', 302)
        return self.redirect_page('/login', 'Auth required')

    def login_oauth(self):
        try:
            oauth = Slacker.oauth.access(
                client_id=SLACK_CLIENT_ID,
                client_secret=os.environ['SLACK_SECRET'],
                code=flask.request.args['code'],
                redirect_uri=WebServer.url_for('login')
            ).body
        except Error as err:
            self.mongo.db.z_errors.insert_one({'_id': time.time(),
                                               'ctx': 'oauth',
                                               'msg': str(err)})
            return WebServer.basic_page('OAuth error',
                                        'OAuth error: ' + str(err))
        token = oauth['access_token']
        try:
            api_user_info = Slacker(token).auth.test().body
            assert api_user_info['team_id'] == SLACK_TEAM_ID
        except Error as err:
            self.mongo.db.z_errors.insert_one({'_id': time.time(),
                                               'ctx': 'auth.test',
                                               'msg': str(err)})
            return WebServer.basic_page('Auth error',
                                        'Auth error: ' + str(err))
        except AssertionError:  # noinspection PyUnboundLocalVariable
            return WebServer.basic_page('Wrong team',
                                        'Wrong team: ' + api_user_info['team'])
        return self.login_success(oauth, token, api_user_info)

    def login_success(self, oauth, token, api_user_info):
        response = flask.redirect('/browse', 302)
        access = oauth['scope'].count(',') > 0
        auth_key = self.tokens.upsert(token,
                                      user=api_user_info, full_access=access)
        self.mongo.db.z_logins.insert_one({'_id': time.time(),
                                           'user': api_user_info['user']})
        response.set_cookie('auth', auth_key,
                            expires=WebServer.cookies_expire_date())
        self.channels_fetch(token, self.tokens.get_key_by_known_token(token))
        return response

    def prepare_messages(self, query):
        results = []
        for res in query:
            # TODO optimize MongoStore class to save '_id' field in values
            res['from'] = self.people.get_row(res['from'])
            res['to'] = self.streams.get_row(res['to'])
            res['ctx'] = self.message_uid(res['from']['_id'], str(res['ts']))
            res['ts'] = time.ctime(res['ts'])
            res['msg'] = flask.Markup(
                markup.Markup(res['msg'], self.people, self.streams))
            results.append(res)
        return results

    def get_user_info(self):
        enc_key = flask.request.cookies.get('auth')
        assert self.tokens.is_known_user(enc_key)
        return self.tokens[enc_key]

    def filter_streams(self, user_info, filter_name):
        my_channels = self.people[user_info['user']].get('channels')
        if filter_name == 'my' and user_info['full_access'] and my_channels:
            channels = [self.streams.get_row(k)
                        for k, v in self.streams.items()
                        if k in my_channels]
        elif filter_name == 'all':
            channels = [self.streams.get_row(k)
                        for k, v in self.streams.items()
                        if v['type'] == 0]
        elif filter_name == 'archive':
            channels = [self.streams.get_row(k)
                        for k, v in self.streams.items()
                        if v['type'] == 0 and not v['active']]
        else:
            filter_name = 'active'  # set default
            channels = [self.streams.get_row(k)
                        for k, v in self.streams.items()
                        if v['type'] == 0 and v['active']]
        channels.sort(key=lambda ch: ch['name'])
        return channels, filter_name

    @staticmethod
    def message_uid(stream, timestamp):
        return stream + '_' + timestamp

    @staticmethod
    def ts_from_message_uid(msg_uid):
        return float(msg_uid.split('_')[1])

    def import_users(self, archive):
        with archive.open('users.json') as users_list:
            users = json.loads(users_list.read())
            bulk = self.mongo.db.users.initialize_ordered_bulk_op()
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

    def import_channels(self, channel_list):
        channels = json.loads(channel_list.read())
        bulk = self.mongo.db.streams.initialize_ordered_bulk_op()
        for channel in channels:
            pins = []
            if 'pins' in channel:
                for pin in channel['pins']:
                    msg_uid = WebServer.message_uid(channel['id'], pin['id'])
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

    def import_messages(self, channels, archive):
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
        bulk = self.mongo.db.messages.initialize_ordered_bulk_op()
        for channel in channels:
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
                        msg_id = WebServer.message_uid(channel['id'],
                                                       msg['ts'])
                        bulk.find({'_id': msg_id}).upsert().update(
                            {'$set': {'ts': float(msg['ts']),
                                      'type': hash(stype),
                                      'msg': msg['text'],
                                      'from': msg['user'],
                                      'to': channel['id']}})
        return bulk.execute(), types_ignore

    def tokens_validation(self):
        print('Validating tokens')
        for token, enc_key in self.tokens.decrypt_keys_map().items():
            time.sleep(1)
            print('Check token', token)
            try:
                user_info = Slacker(token).auth.test().body
            except Error as err:
                self.mongo.db.z_errors.insert_one({'_id': time.time(),
                                                   'ctx': 'tokens_validation',
                                                   'msg': str(err)})
                print('Error for this token:', err)
                del self.tokens[enc_key]
                continue
            print('Valid token')
            self.tokens.upsert(token, user_info)

    def channels_fetch_all(self):
        print('Fetching user channels here')
        for token, enc_key in self.tokens.decrypt_keys_map().items():
            time.sleep(1)
            self.channels_fetch(token, enc_key)

    def channels_fetch(self, token, enc_key):
        user_info = self.tokens[enc_key]
        if not user_info['full_access']:
            return
        print('Fetch channels for', user_info['login'])
        try:
            all_ch = Slacker(token).channels.list(exclude_archived=1).body
        except Error as err:
            self.mongo.db.z_errors.insert_one({'_id': time.time(),
                                               'ctx': 'channels_fetch',
                                               'msg': str(err)})
            print('Fetch channels error:', err)
            return
        channels_list = [
            channel['id']
            for channel in all_ch['channels'] if channel['is_member']
            ]
        self.people.set_field(user_info['user'], 'channels', channels_list)
        print('Channels fetched')


class Scheduler(object):
    bg_task = None

    def __init__(self, server):
        # scheduler in background
        atexit.register(self.background_stop)
        self.setup_scheduler(server)
        self.background_task()

    @staticmethod
    def setup_scheduler(server):
        schedule.every(11).hours.do(server.channels_fetch_all)
        schedule.every(12).hours.do(server.tokens_validation)

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


WebServer.start()
