# pylint: disable=fixme,missing-docstring
from __future__ import print_function

import atexit
import json
import os
import time
import threading
import zipfile

import schedule
from slacker import Slacker, Error

import markup
import mongo_store

LOCAL_ARCHIVE_FILE = 'archive.zip'
MESSAGES_NUMBER_PER_STREAM_REQUEST = 1000
MESSAGES_NUMBER_PER_SEARCH_REQUEST = 100


class Scheduler(object):
    bg_task = None

    def __init__(self, server):
        # scheduler in background
        atexit.register(self.background_stop)
        self.setup_scheduler(server)
        self.background_task()

    @staticmethod
    def setup_scheduler(server):
        # TODO: user-oriented handling on timer
        schedule.every(30).minutes.do(server.channels_fetch_all)
        schedule.every(30).minutes.do(server.tokens_validation)

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


class SlackArchive(object):

    def __init__(self, db, ctx, tokens):
        self.database = db
        self.ctx = ctx
        self.people = mongo_store.MongoStore(self.database.users, ctx)
        self.streams = mongo_store.MongoStore(self.database.streams, ctx)
        self.tokens = tokens
        self.scheduler = Scheduler(self)

    def prepare_messages(self, query):
        results = []
        for res in query:
            res['from'] = self.people[res['from']]
            res['to'] = self.streams[res['to']]
            res['ctx'] = SlackArchive.message_uid(res['from']['_id'],
                                                  str(res['ts']))
            res['ts'] = time.ctime(res['ts'])
            res['msg'] = markup.Markup(res['msg'], self.people, self.streams)
            results.append(res)
        return results

    def filter_streams(self, user_info, filter_name):
        my_channels = self.people[user_info['user']].get('channels')
        if filter_name == 'my' and user_info['full_access'] and my_channels:
            channels = [self.streams[k]
                        for k, v in self.streams.items()
                        if k in my_channels]
        elif filter_name == 'all':
            channels = [self.streams[k]
                        for k, v in self.streams.items()
                        if v['type'] == 0]
        elif filter_name == 'archive':
            channels = [self.streams[k]
                        for k, v in self.streams.items()
                        if v['type'] == 0 and not v['active']]
        else:
            filter_name = 'active'  # set default
            channels = [self.streams[k]
                        for k, v in self.streams.items()
                        if v['type'] == 0 and v['active']]
        channels.sort(key=lambda ch: ch['name'])
        return channels, filter_name

    @staticmethod
    def message_uid(stream, timestamp):
        return stream + '_' + timestamp

    @staticmethod
    def ts_from_message_uid(msg_uid):
        try:
            return float(msg_uid.split('_')[-1])
        except ValueError:  # failed on parsing float
            # TODO add error logging here
            return 0

    def import_users(self, archive):
        with archive.open('users.json') as users_list:
            users = json.loads(users_list.read())
            bulk = self.database.users.initialize_ordered_bulk_op()
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
        bulk = self.database.streams.initialize_ordered_bulk_op()
        for channel in channels:
            pins = []
            if 'pins' in channel:
                for pin in channel['pins']:
                    msg_uid = SlackArchive.message_uid(channel['id'],
                                                       pin['id'])
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
        bulk = self.database.messages.initialize_ordered_bulk_op()
        for channel in channels:
            for fname in [n for n in files
                          if n.startswith(channel['name'] + os.path.sep)]:
                with archive.open(fname) as day_export:
                    SlackArchive.import_messages_day(
                        bulk, channel, day_export, types_ignore, types_import)
        return bulk.execute(), types_ignore

    @staticmethod
    def import_messages_day(bulk, channel, day_export,
                            types_ignore, types_import):
        msgs = json.loads(day_export.read())
        for msg in msgs:
            stype = msg.get('subtype', '')
            if stype not in types_import:
                if stype not in types_ignore:
                    types_ignore.add(stype)
                continue
            msg_id = SlackArchive.message_uid(channel['id'],
                                              msg['ts'])
            bulk.find({'_id': msg_id}).upsert().update(
                {'$set': {'ts': float(msg['ts']),
                          'type': hash(stype),
                          'msg': msg['text'],
                          'from': msg['user'],
                          'to': channel['id']}})

    def tokens_validation(self):
        print('Validating tokens')
        for token, enc_key in self.tokens.decrypt_keys_map().items():
            time.sleep(1)
            print('Check token', token)
            try:
                user_info = Slacker(token).auth.test().body
            except Error as err:
                self.database.z_errors.insert_one({'_id': time.time(),
                                                   'ctx': 'tokens_validation',
                                                   'msg': str(err)})
                print('Error for this token:', err)
                del self.tokens[enc_key]
                continue
            print('Valid token')
            self.tokens.upsert(token, user_info)

    def channels_fetch_all(self):
        print('Fetching user channels here')
        for token in self.tokens.decrypt_keys_map().keys():
            time.sleep(1)
            self.channels_fetch(token)

    def channels_fetch(self, token):
        enc_key = self.tokens.get_key_by_known_token(token)
        user_info = self.tokens[enc_key]
        if user_info['full_access']:
            print('Fetch channels for', user_info['login'])
            try:
                all_ch = Slacker(token).channels.list(exclude_archived=1).body
                self.people.set_field(user_info['user'], 'channels',
                                      SlackArchive.filter_channel_ids(all_ch))
            except Error as err:
                self.database.z_errors.insert_one({'_id': time.time(),
                                                   'ctx': 'channels_fetch',
                                                   'msg': str(err)})
                print('Fetch channels error:', err)
                # full access was revoked
                if str(err) == 'missing_scope':
                    # TODO: sync field names between tokens storage and API
                    self.tokens.set_field(user_info['user'],
                                          'full_access', False)

    @staticmethod
    def filter_channel_ids(channels):
        return [
            channel['id']
            for channel in channels['channels']
            if channel['is_member']
            ]

    def import_archive(self):
        # TODO convert this to background task
        # TODO add logging around
        with zipfile.ZipFile(LOCAL_ARCHIVE_FILE) as archive:
            self.import_users(archive)
            self.people.reload()
            # import channels
            with archive.open('channels.json') as channel_list:
                channels = self.import_channels(channel_list)
                self.streams.reload()
                # import messages
                result, types_new = self.import_messages(channels, archive)
                self.database.messages.create_index('ts')
                self.database.messages.create_index('to')
                self.database.messages.create_index('type')
                self.database.messages.create_index('from')
                self.database.messages.create_index([('msg', 'text')],
                                                    default_language='ru')
        skip_fields = ['upserted', 'modified', 'matched']
        for field in skip_fields:
            result.pop(field, None)
        return result, types_new

    @staticmethod
    def users_list(domain):
        if domain:
            domain = '@' + domain
        active = []
        with zipfile.ZipFile(LOCAL_ARCHIVE_FILE) as archive:
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
        return ' '.join([user + '@' for user in active])

    def stream_messages(self, stream, page):
        query = self.database.messages.find(
            {'to': stream},
            sort=[('ts', -1)],
            skip=page * MESSAGES_NUMBER_PER_STREAM_REQUEST,
            limit=MESSAGES_NUMBER_PER_STREAM_REQUEST)
        return self.prepare_messages(query)

    def find_messages(self, query, streams, page):
        condition = {'$text': {'$search': query}, 'to': {'$in': streams}}
        return self._search_messages(condition, page)

    def find_messages_around(self, context, stream, page):
        timestamp = SlackArchive.ts_from_message_uid(context)
        condition = {'ts': {'$lt': timestamp + 60 * 60,
                            '$gt': timestamp - 60 * 60},
                     'to': stream}
        return self._search_messages(condition, page)

    def find_messages_in_stream(self, query, stream, page):
        condition = {'$text': {'$search': query}, 'to': stream}
        return self._search_messages(condition, page)

    def _search_messages(self, condition, page):
        query = self.database.messages.find(
            condition,
            sort=[('ts', -1)],
            skip=page * MESSAGES_NUMBER_PER_SEARCH_REQUEST,
            limit=MESSAGES_NUMBER_PER_SEARCH_REQUEST)
        return self.prepare_messages(query)
