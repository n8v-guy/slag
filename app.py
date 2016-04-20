#!/usr/bin/env python
# -*- coding: utf-8 -*-
# pylint: disable=fixme,missing-docstring

import collections
import functools
import os
import time

import flask
import flask_pymongo
import rollbar
import rollbar.contrib.flask
from slacker import Slacker, Error

# noinspection PyUnresolvedReferences
import credentials  # noqa # pylint: disable=unused-import
import slack_archive
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
        def wrap(method):
            route_rules = getattr(method, FlaskExt._HOOK_ROUTE_PROP, [])
            route_rules.append(FlaskExt.RouteArgs(args, kwargs))
            setattr(method, FlaskExt._HOOK_ROUTE_PROP, route_rules)
            return method
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
        self.setup_rollbar()
        self.before_request(WebServer._redirect_to_https)
        self.before_request(self._check_auth)
        # TODO eliminate MongoLab mentions
        self.config['MONGO_URI'] = os.environ['MONGOLAB_URI']
        self.mongo = flask_pymongo.PyMongo(self)
        with self.app_context() as ctx:
            self.tokens = store.TokenStore(self.mongo.db.tokens, ctx,
                                           key=os.environ['CRYPTO_KEY'])
            self.archive = slack_archive.SlackArchive(
                self.mongo.db, ctx, self.tokens, os.environ['SLACK_TOKEN'])

    @staticmethod
    def start():
        if WebServer.is_production():
            host = '0.0.0.0'
            port = int(os.environ.get('PORT'))
        else:
            host = '127.0.0.1'
            port = 8080
        # __name__ == 'app' for gunicorn production
        debug = (__name__ == '__main__')

        if debug and os.environ.get('WERKZEUG_RUN_MAIN', 'false') != 'true':
            # lightweight starter for Werkzeug reloader
            app = flask.Flask(__name__)
        else:
            app = WebServer()  # pylint: disable=redefined-variable-type
        app.run(host=host, port=port, debug=debug)

    def setup_rollbar(self):
        # extend reports with user context
        # pylint: disable=too-many-ancestors
        class CustomRequest(flask.Request):
            @property
            def rollbar_person(self):
                return {'id': self.cookies.get('auth')}
        self.request_class = CustomRequest

        # setup Rollbar error reporting
        self.before_first_request(
            functools.partial(WebServer.init_rollbar, self))

    @staticmethod
    def init_rollbar(app):
        """init rollbar module"""
        rollbar.init(
            # access token for the demo app: https://rollbar.com/demo
            os.environ['ROLLBAR_KEY'],
            # environment name
            'production' if WebServer.is_production() else 'flasktest',
            # server root directory, makes tracebacks prettier
            root=os.path.dirname(os.path.realpath(__file__)),
            # flask already sets up logging
            allow_logging_basic_config=False)

        # send exceptions from `app` to rollbar, using flask's signal system.
        flask.got_request_exception.connect(
            rollbar.contrib.flask.report_exception,
            app)

    @staticmethod
    def _is_forced_debug():
        return os.environ.get('DEBUG_SERVER', '0') == '1'

    @staticmethod
    def is_production():
        return __name__ == 'app' or WebServer._is_forced_debug()

    @staticmethod
    def url_for(endpoint):
        url = flask.url_for(endpoint, _external=True)
        if WebServer.is_production():
            url = url.replace('http://', 'https://', 1)
        return url

    @staticmethod
    def _redirect_page(url, msg):
        return flask.render_template('redirect.htm', url_to=url, message=msg)

    @staticmethod
    def _basic_page(title, html):
        return flask.render_template('basic.htm', title=title, html=html)

    @staticmethod
    def cookies_expire_date():
        """:returns: now plus one year date in cookie-expected time format"""
        return time.strftime("%a, %d-%b-%Y %T GMT",
                             time.gmtime(time.time() + 365 * 24 * 60 * 60))

    @FlaskExt.route('/<path:filename>')
    def send_file(self, filename):
        return flask.send_from_directory(self.static_folder, filename)

    @FlaskExt.route('/users')
    def users(self):
        domain = flask.request.args.get('domain')
        return self.archive.users_list(domain)

    @FlaskExt.route('/')
    def index(self):
        if self.tokens.is_known_user(flask.request.cookies.get('auth')):
            return flask.redirect('/browse', 302)
        return WebServer._redirect_page('/login', 'Auth required')

    @FlaskExt.route('/login')
    def login(self):
        if flask.request.args.get('code'):
            return self._login_oauth()
        # logging in is not in progress
        auth = '&redirect_uri=' + WebServer.url_for('login')
        return WebServer._basic_page(
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
        enc_key = flask.request.cookies.get('auth')
        user_info = self.tokens[enc_key]
        response = flask.make_response(
            WebServer._redirect_page('https://slack.com', 'Bye'))
        self.mongo.db.z_logouts.insert_one({'_id': time.time(),
                                            'user': user_info['login']})
        response.delete_cookie('auth')
        del self.tokens[enc_key]
        return response

    @FlaskExt.route('/search')
    def search(self):
        """3 cases here: search everywhere/in channel/by message"""
        user = self.tokens[flask.request.cookies.get('auth')]
        query = flask.request.args.get('q', '')
        stream = flask.request.args.get('s', '')
        context = flask.request.args.get('c', '')
        page = int(flask.request.args.get('p', 0))
        self.mongo.db.z_search.insert_one({'_id': time.time(),
                                           'user': user['login'],
                                           'q': query})
        results = []
        if query == '':
            return flask.render_template('search.htm', results=results)
        if context != '':
            results = self.archive.find_messages_around(context, stream, page)
        elif stream != '':
            results = self.archive.find_messages_in_stream(query, stream, page)
        else:
            channels, _ = self.archive.filter_streams(user, 'all')
            channels = [chan['_id'] for chan in channels]
            results = self.archive.find_messages(query, channels, page)
        return flask.render_template(
            'search.htm', results=results, total=len(results), q=query,
            s=stream, c=context, p=page,
            n=slack_archive.MESSAGES_NUMBER_PER_SEARCH_REQUEST)

    @FlaskExt.route('/browse')
    def browse(self):
        user_info = self.tokens[flask.request.cookies.get('auth')]
        stream = flask.request.args.get('s', '')
        page = int(flask.request.args.get('p', 0))
        self.mongo.db.z_browse.insert_one({'_id': time.time(),
                                           'user': user_info['login'],
                                           's': stream})
        if stream == '':
            filter_name = flask.request.args.get('filter', 'my')
            channels, filter_name = self.archive.filter_streams(user_info,
                                                                filter_name)
            return flask.render_template('browse.htm', channels=channels,
                                         f=filter_name)
        results = self.archive.stream_messages(stream, page)
        return flask.render_template(
            'stream.htm', results=results, total=len(results), s=stream,
            p=page, n=slack_archive.MESSAGES_NUMBER_PER_STREAM_REQUEST)

    @staticmethod
    @FlaskExt.route('/import', methods=['GET', 'POST'])
    def upload():
        # TODO check admin rights here
        if WebServer.is_production():
            return WebServer._redirect_page('/browse', 'Access denied')
        archive = flask.request.files.get('archive')
        if archive and archive.filename.endswith('.zip'):
            archive.save(slack_archive.LOCAL_ARCHIVE_FILE)
            return WebServer._redirect_page('/import_db',
                                            archive.filename + ' saved')
        return WebServer._basic_page(
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
        # TODO check admin rights here
        if WebServer.is_production():
            return WebServer._redirect_page('/browse', 'Access denied')
        result, types_new = self.archive.import_archive()
        return WebServer._basic_page('Archive import complete',
                                     'Import complete!<br />' +
                                     str(result) + '<br/>' +
                                     str(types_new))

    @staticmethod
    def _redirect_to_https():
        is_http = flask.request.is_secure or \
                  flask.request.headers.get('X-Forwarded-Proto') == 'http'
        if is_http and WebServer.is_production():
            url = flask.request.url.replace('http://', 'https://', 1)
            return flask.redirect(url, code=301)

    def _check_auth(self):
        if self.tokens.is_known_user(flask.request.cookies.get('auth')):
            return
        if flask.request.path in ['/login'] or \
           os.path.isfile(os.path.join(self.static_folder,
                                       flask.request.path[1:])):
            return
        return self._redirect_page('/login', 'Auth required')

    def _login_oauth(self):
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
            return WebServer._basic_page('OAuth error',
                                         'OAuth error: ' + str(err))
        token = oauth['access_token']
        identity_only = oauth['scope'].count(',') == 1
        return self._login_with_token(token, identity_only)

    def _login_with_token(self, token, identity_only):
        try:
            api_auth = Slacker(token).auth.test().body
            assert api_auth['team_id'] == SLACK_TEAM_ID
        except Error as err:
            self.mongo.db.z_errors.insert_one({'_id': time.time(),
                                               'ctx': 'auth.test',
                                               'msg': str(err)})
            return WebServer._basic_page('Auth error',
                                         'Auth error: ' + str(err))
        except AssertionError:
            return WebServer._basic_page('Wrong team',
                                         'Wrong team: ' + api_auth['team'])
        return self._login_success(token, api_auth, identity_only)

    def _login_success(self, token, api_user_info, identity_only):
        response = flask.redirect('/browse', 302)
        auth_key = self.tokens.upsert(token,
                                      user=api_user_info,
                                      full_access=not identity_only)
        self.mongo.db.z_logins.insert_one({'_id': time.time(),
                                           'user': api_user_info['user']})
        response.set_cookie('auth', auth_key,
                            expires=WebServer.cookies_expire_date())
        self.archive.streams_fetch(token)
        return response


WebServer.start()
