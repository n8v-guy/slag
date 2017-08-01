# pylint: disable=fixme,missing-docstring
from __future__ import absolute_import, division, print_function
import functools
import json
import logging
import os
import random
import time
import zipfile

from slacker import Slacker, Error

import markup
import mongo_store
import scheduler


LOCAL_ARCHIVE_FILE = 'archive.zip'
MESSAGES_NUMBER_PER_STREAM_REQUEST = 1000
MESSAGES_NUMBER_PER_SEARCH_REQUEST = 100


class SlackArchive(object):
    PUBLIC = 0
    PRIVATE = 1  # no MPIMs here
    DIRECT = 2  # MPIMs are here

    def __init__(self, mongo, ctx, tokens, api_key):
        self.mongo = mongo
        self.log = SlackArchive.get_logger()
        self.people = mongo_store.MongoStore(self.mongo.db.users, ctx)
        self.streams = mongo_store.MongoStore(self.mongo.db.streams, ctx)
        self.tokens = tokens
        self.api_handle = Slacker(api_key)
        self.scheduler = scheduler.Scheduler(ctx, mongo)
        self._setup_scheduler()
        self.scheduler.start()

    def _setup_scheduler(self):
        self.scheduler.every(25).minutes.do(self.people_fetch_all)
        self.scheduler.every(25).minutes.do(self.tokens_validation)
        self.scheduler.every(25).minutes.do(self.fetch_public_messages)
        self.scheduler.every(25).minutes.do(self.fetch_private_messages)
        self.scheduler.every(25).minutes.do(self.update_streams_properties)

    @staticmethod
    def get_logger():
        log = logging.getLogger(__name__)
        if not log.handlers:
            log.setLevel(logging.INFO)
            log_handler = logging.StreamHandler()
            log_handler.setFormatter(
                logging.Formatter('%(levelname)-7s | %(message)-99s | '
                                  '%(filename)s:%(lineno)d | '
                                  '%(asctime)s | %(funcName)s | '
                                  '%(threadName)s'))
            log.addHandler(log_handler)
        return log

    @staticmethod
    def api_call_delay():
        time.sleep(0.25)

    def _prepare_messages(self, query):
        results = []
        for res in query:
            res['from'] = self.people[res['from']]
            res['to'] = self.streams[res['to']]
            res['ctx'] = SlackArchive._message_uid(res['from']['_id'],
                                                   str(res['ts']))
            res['ts'] = time.ctime(res['ts'])
            res['msg'] = markup.Markup(res['msg'], self.people, self.streams)
            results.append(res)
        return results, query.count()

    def filter_streams(self, user_info, filter_name):
        cur_person = self.people[user_info['user']]
        public = [self.streams[chan]
                  for chan in cur_person.get('channels', [])]
        private = [self.streams[group]
                   for group in cur_person.get('groups', [])]
        direct = [self.streams[im] for im in cur_person.get('ims', [])]
        if filter_name == 'all':
            public = [v for v in self.streams.values()
                      if v['type'] == SlackArchive.PUBLIC]
        elif filter_name == 'archive':
            public = [v for v in self.streams.values()
                      if v['type'] == SlackArchive.PUBLIC and not v['active']]
            private = [v for v in private if not v['active']]
            direct = [v for v in direct if not v['active']]
        else:  # 'my', 'active' or unknown
            if filter_name == 'my' and user_info['full_access']:
                public = [v for v in public if v['active']]
            else:
                filter_name = 'active'  # reset default
                public = [v for v in self.streams.values()
                          if v['type'] == SlackArchive.PUBLIC and v['active']]
            private = [v for v in private if v['active']]
            direct = [v for v in direct if v['active']]
        # hide conversations without fetched history, make directs mutable
        public = [stream for stream in public
                  if not stream.get('empty', True)]
        private = [stream for stream in private
                   if not stream.get('empty', True)]
        direct = [dict(d) for d in direct
                  if not d.get('empty', True)]
        # skip current person login from conversation name
        for conversation in direct:
            logins = conversation['name'].split('+')
            logins.remove('@'+user_info['login'])
            conversation['name'] = '+'.join(logins)

        public.sort(key=lambda ch: ch['name'])
        private.sort(key=lambda ch: ch['name'])
        direct.sort(key=lambda ch: ch['name'])
        return public, private, direct, filter_name

    @staticmethod
    def _message_uid(stream, timestamp):
        return stream + '_' + timestamp

    def _ts_from_message_uid(self, msg_uid):
        try:
            return float(msg_uid.split('_')[-1])
        except ValueError:  # failed on parsing float
            self.log.exception('Failed on parsing timestamp')
            return 0

    def _import_people(self, archive):
        with archive.open('users.json') as users_list:
            people = json.loads(users_list.read())
            bulk = self.mongo.db.users.initialize_ordered_bulk_op()
            for person in people:
                bulk.find({'_id': person['id']}).upsert().update(
                    {'$set': {'name': person['profile']['real_name'],
                              'login': person['name'],
                              'avatar': person['profile']['image_72']}})
            # manual insert for slackbot user
            bulk.find({'_id': 'USLACKBOT'}).upsert().update(
                {'$set': {'name': 'slackbot',
                          'login': 'slackbot',
                          'avatar': 'https://a.slack-edge.com/'
                                    '0180/img/slackbot_72.png'}})
            bulk.execute()

    def _import_channels(self, channel_list):
        channels = json.loads(channel_list.read())
        bulk = self.mongo.db.streams.initialize_ordered_bulk_op()
        for channel in channels:
            pins = SlackArchive._pins_from_stream(channel)
            bulk.find({'_id': channel['id']}).upsert().update(
                {'$set': {'name': channel['name'],
                          'type': SlackArchive.PUBLIC,
                          'active': not channel['is_archived'],
                          'topic': channel['topic']['value'],
                          'purpose': channel['purpose']['value'],
                          'pins': pins}})
        bulk.execute()
        return channels

    @staticmethod
    def _pins_from_stream(stream):
        pins = []
        if 'pins' in stream:
            for pin in stream['pins']:
                msg_uid = SlackArchive._message_uid(stream['id'],
                                                    pin['id'])
                pins.append(msg_uid)
        return pins

    def _import_messages(self, channels, archive):
        types_import, types_ignore = SlackArchive._message_type_sets()
        files = [n for n in archive.namelist()
                 if not n.endswith(os.path.sep)]
        bulk = self.mongo.db.messages.initialize_ordered_bulk_op()
        for channel in channels:
            last_msg_ts = '0'
            for fname in [n for n in files
                          if n.startswith(channel['name'] + os.path.sep)]:
                with archive.open(fname) as day_export:
                    msgs = json.loads(day_export.read())
                    _, last_import_ts = SlackArchive._import_messages_bulk(
                        bulk, channel, msgs, types_import, types_ignore)
                if float(last_import_ts) > float(last_msg_ts):
                    last_msg_ts = last_import_ts
            # FIXME TODO Bad transaction: last_msg is set before applying bulk
            self.streams.set_field(channel['id'], 'last_msg', last_msg_ts)
        return bulk.execute(), types_ignore

    @staticmethod
    def _message_type_sets():
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
        types_ignore = {'pinned_item', 'file_comment',
                        'bot_message', 'is_ephemeral'}
        return types_import, types_ignore

    @staticmethod
    def _import_messages_bulk(bulk, channel, msgs,
                              types_import, types_ignore):
        # reverse order for exported messages, no sort for API response
        msgs = sorted(msgs, key=lambda m: float(m['ts']), reverse=True)
        msg_counter = 0
        known_fields = {'type', 'subtype', 'ts', 'text', 'user',
                        'bot_id', 'edited', 'username', 'pinned_to', 'upload',
                        'is_starred', 'display_as_bot', 'item_type', 'inviter',
                        'members', 'purpose', 'topic', 'comment', 'item',
                        'attachments', 'file', 'reactions', 'name', 'old_name',
                        'icons', 'is_intro', 'no_notifications',
                        'room', 'channel', 'is_ephemeral',
                        'parent_user_id', 'thread_ts', 'reply_count',
                        'subscribed', 'replies',
                        'channel_type', 'channel_id', 'is_multiteam',
                        'timestamp', 'unread_count', 'last_read',
                        'slog_is_self_dm', 'slog_is_mpdm', 'slog_is_shared',
                        'slog_is_slackbot_dm', 'upload_reply_to', 'root',
                        'is_thread_broadcast', 'new_broadcast', 'plain_text',
                        'hidden', 'bot_link', }
        for msg in msgs:
            unknown_fields = set(msg.keys()) - known_fields
            print(unknown_fields)
            # assert len(unknown_fields) == 0, ', '.join(unknown_fields)
            subtype = msg.get('subtype', '')
            if subtype not in types_import:
                if subtype not in types_ignore:
                    types_ignore.add(subtype)
                continue
            msg_counter += 1
            msg_id = SlackArchive._message_uid(channel['id'], msg['ts'])
            if 'file' in msg and False:
                logging.error(' '.join(sorted(msg['file'].keys())) + '\n' +
                              msg['file']['pretty_type'] + ' ' +
                              msg['file']['mimetype'].split('/')[0] + ' ' +
                              msg['file']['name'] + ' ' +
                              msg['file']['title'] + '\n' +
                              msg['file']['url_private'])
            bulk.find({'_id': msg_id}).upsert().update(
                {'$set': {'ts': float(msg['ts']),
                          'type': hash(subtype),
                          'msg': msg['text'],
                          'from': msg['user'],
                          'to': channel['id']}})
        return msg_counter, msgs[0]['ts']

    @scheduler.task_logging
    def tokens_validation(self):
        self.log.info('Validating tokens')
        for token, enc_key in self.tokens.decrypt_keys_map().items():
            self.log.info('Check token %s', token)
            try:
                user_info = Slacker(token).auth.test().body
                SlackArchive.api_call_delay()
            except Error as err:
                self.mongo.db.z_errors.insert_one({'_id': time.time(),
                                                   'ctx': 'tokens_validation',
                                                   'msg': str(err)})
                self.log.exception('Error %s for token %s', str(err), token)
                del self.tokens[enc_key]
                continue
            self.log.info('Valid token')
            self.tokens.upsert(token, user_info)

    @scheduler.task_logging
    def people_fetch_all(self):
        self.log.info('Fetching people list')
        try:
            people = self.api_handle.users.list().body
            SlackArchive.api_call_delay()
        except Error as err:
            self.log.exception('Fetching people list exception %s', str(err))
            return
        # TODO add bulk_op wrapper for mongo_store
        for person in people['members']:
            item_id = person['id']
            person_dict = dict(self.people[item_id]) \
                if item_id in self.people.keys() else {}
            person_dict['name'] = person['profile']['real_name']
            person_dict['login'] = person['name']
            person_dict['avatar'] = person['profile']['image_72']
            person_dict['active'] = (not person.get('deleted', True) and
                                     not person.get('is_bot', True))
            self.people[item_id] = person_dict

    def streams_fetch(self, token):
        enc_key = self.tokens.get_key_by_known_token(token)
        user_info = self.tokens[enc_key]
        if user_info['full_access']:
            try:
                self.log.info('Fetch channels for %s', user_info['login'])
                all_ch = Slacker(token).channels.list().body
                SlackArchive.api_call_delay()
                self.people.set_field(user_info['user'], 'channels',
                                      SlackArchive._filter_channel_ids(all_ch))
                self.update_streams(all_ch)  # not a duplicate op: fight races
                self.log.info('Fetch %s\'s private groups', user_info['login'])
                groups = Slacker(token).groups.list().body
                SlackArchive.api_call_delay()
                self.people.set_field(user_info['user'], 'groups',
                                      SlackArchive._filter_group_ids(groups))
                self.update_streams(groups, user_info['user'])
                self.log.info('Fetch direct msgs for %s', user_info['login'])
                ims = Slacker(token).im.list().body
                SlackArchive.api_call_delay()
                self.people.set_field(user_info['user'], 'ims',
                                      SlackArchive._filter_im_ids(groups, ims))
                self.update_streams(ims, user_info['user'])
            except Error as err:
                self.mongo.db.z_errors.insert_one({'_id': time.time(),
                                                   'ctx': 'channels_fetch',
                                                   'msg': str(err)})
                self.log.exception('Fetch streams error %s', str(err))
                # full access was revoked
                if str(err) == 'missing_scope':
                    self.tokens.set_field(enc_key, 'full_access', False)

    @scheduler.task_logging
    def fetch_private_messages(self):
        self.log.info('Fetching private groups & ims messages')
        # shuffle users array
        tokens_to_keys = self.tokens.decrypt_keys_map().items()
        random.shuffle(tokens_to_keys)
        for token, enc_key in tokens_to_keys:
            user_info = self.tokens[enc_key]
            if not user_info['full_access']:
                continue
            self.streams_fetch(token)
            api_handle = Slacker(token)
            self.log.info('Fetching private groups for %s', user_info['login'])
            self._fetch_person_groups_history(user_info, api_handle)
            self.log.info('Fetching private ims for %s', user_info['login'])
            self._fetch_person_ims_history(user_info, api_handle)

    @scheduler.task_logging
    def update_streams_properties(self):
        self.log.info('Updating streams properties')
        empty_count = 0
        for stream_id in self.streams.keys():
            if not self.streams[stream_id].get('empty'):
                continue
            stream_row = self.mongo.db.messages.find_one({'to': stream_id})
            self.streams.set_field(stream_id, 'empty', stream_row is None)
            if stream_row is None:
                empty_count += 1
        self.log.info('Updating streams: %d/%d streams are empty',
                      empty_count, len(self.streams))
        # TODO Make a list of abandoned streams to fetch them not so often

    def _fetch_person_groups_history(self, user_info, api_handle):
        try:
            groups = api_handle.groups.list().body
            SlackArchive.api_call_delay()
        except Error as err:
            self.mongo.db.z_errors.insert_one({'_id': time.time(),
                                               'ctx': ('fetch_person_groups ' +
                                                       user_info['login']),
                                               'msg': str(err)})
            self.log.exception('Fetch person groups error %s', str(err))
            return
        api_loader = functools.partial(api_handle.groups.history,
                                       inclusive=0, count=1000)
        self._fetch_stream_messages(api_loader, groups['groups'])

    def _fetch_person_ims_history(self, user_info, api_handle):
        try:
            ims = api_handle.im.list().body
            SlackArchive.api_call_delay()
        except Error as err:
            self.mongo.db.z_errors.insert_one({'_id': time.time(),
                                               'ctx': ('fetch_person_ims ' +
                                                       user_info['login']),
                                               'msg': str(err)})
            self.log.exception('Fetch person groups error %s', str(err))
            return
        api_loader = functools.partial(api_handle.im.history,
                                       inclusive=0, count=1000)
        self._fetch_stream_messages(api_loader, ims['ims'])

    @scheduler.task_logging
    def fetch_public_messages(self):
        self.log.info('Fetching public channels messages')
        self.create_messages_indices()
        try:
            chans_list = self.api_handle.channels.list().body
            random.shuffle(chans_list['channels'])
            SlackArchive.api_call_delay()
        except Error as err:
            self.mongo.db.z_errors.insert_one({'_id': time.time(),
                                               'ctx': 'fetch_public_messages',
                                               'msg': str(err)})
            self.log.exception('Fetch public messages error %s', str(err))
            return

        self.update_streams(chans_list)
        api_loader = functools.partial(self.api_handle.channels.history,
                                       inclusive=0, count=1000)
        self._fetch_stream_messages(api_loader, chans_list['channels'])

    def _fetch_stream_messages(self, api_loader, streams_list):
        pos = 0
        for stream in streams_list:
            pos += 1
            self.log.info('[%d/%d] Fetching messages from %s',
                          pos, len(streams_list),
                          self.streams[stream['id']]['name'])
            self._fetch_single_stream_messages(api_loader, stream)

    def _fetch_single_stream_messages(self, api_loader, stream):
        last_msg_ts = self.streams[stream['id']].get('last_msg', '0')
        # TODO Skip 'just fetched' streams (when fetching for multiple users)
        bulk = self.mongo.db.messages.initialize_ordered_bulk_op()
        bulk_total_size = 0
        while True:
            has_more, last_msg_ts, bulk_count = self._iterate_messages_history(
                api_loader, stream, last_msg_ts, bulk)
            bulk_total_size += bulk_count
            if not has_more:
                break
        if bulk_total_size:
            bulk.execute()
            if last_msg_ts != '0':  # import non-contiguous history
                self.streams.set_field(stream['id'], 'last_msg', last_msg_ts)
            self.streams.set_field(stream['id'], 'empty', False)
            self.log.info('Fetched %s new message(s) from %s',
                          bulk_total_size, self.streams[stream['id']]['name'])

    def _iterate_messages_history(self, api_loader, stream, last_msg_ts, bulk):
        msgs = api_loader(stream['id'], oldest=last_msg_ts).body
        SlackArchive.api_call_delay()
        types_import, types_ignore = SlackArchive._message_type_sets()
        if msgs['messages']:
            bulk_op_count, last_import_ts = SlackArchive._import_messages_bulk(
                bulk, stream, msgs['messages'], types_import, types_ignore)
        else:
            bulk_op_count, last_import_ts = 0, last_msg_ts
        if msgs.get('is_limited'):
            self.log.warning('Limited stream history for %s',
                             self.streams[stream['id']]['name'])
            return False, '0', bulk_op_count
        return msgs['has_more'], last_import_ts, bulk_op_count

    def _update_stream(self, api_stream, src_user=None):
        sid = api_stream['id']
        stream_dict = dict(self.streams[sid]) if sid in self.streams.keys() \
            else {}
        item_type = SlackArchive._stream_type(api_stream)

        stream_dict['name'] = api_stream.get('name')
        if item_type == SlackArchive.DIRECT:
            members = api_stream.get('members', [])
            if not members:
                assert src_user is not None
                members = [src_user, api_stream['user']]
            logins = ['@'+(self.people[m]['login']
                           if m in self.people.keys() else m)
                      for m in members]
            stream_dict['name'] = '+'.join(sorted(logins))
        is_archived = (api_stream.get('is_archived', False) or
                       api_stream.get('is_user_deleted', False))
        stream_dict['active'] = not is_archived
        stream_dict['topic'] = ('' if 'topic' not in api_stream
                                else api_stream['topic']['value'])
        pins = SlackArchive._pins_from_stream(api_stream)
        if pins:
            stream_dict['pins'] = pins
        stream_dict['type'] = item_type
        stream_dict['purpose'] = ('' if 'purpose' not in api_stream
                                  else api_stream['purpose']['value'])
        # TODO Add cheap method for mongo_store for this
        self.streams[sid] = stream_dict

    @staticmethod
    def _stream_type(api_stream):
        if (api_stream.get('is_mpim', False) or
                api_stream.get('is_im', False)):
            item_type = SlackArchive.DIRECT
        elif api_stream.get('is_group', False):
            item_type = SlackArchive.PRIVATE
        else:
            assert api_stream['is_channel']
            item_type = SlackArchive.PUBLIC
        return item_type

    def update_streams(self, api_body, src_user=None):
        for channel in api_body.get('channels', []):
            self._update_stream(channel, src_user)
        for channel in api_body.get('groups', []):
            self._update_stream(channel, src_user)
        for channel in api_body.get('ims', []):
            self._update_stream(channel, src_user)

    @staticmethod
    def _filter_channel_ids(channels):
        return [channel['id']
                for channel in channels['channels']
                if channel['is_member']]

    @staticmethod
    def _filter_group_ids(groups):
        return [group['id']
                for group in groups['groups']
                if not group['is_mpim']]

    @staticmethod
    def _filter_im_ids(groups, ims):
        return ([im['id']
                 for im in ims['ims']] +
                [group['id']
                 for group in groups['groups']
                 if group['is_mpim']])

    def import_archive(self):
        # TODO convert this to background task
        # TODO add logging around
        with zipfile.ZipFile(LOCAL_ARCHIVE_FILE) as archive:
            self._import_people(archive)
            self.people.reload()
            # import channels
            with archive.open('channels.json') as channel_list:
                channels = self._import_channels(channel_list)
                self.streams.reload()
                # import messages
                result, types_new = self._import_messages(channels, archive)
                self.create_messages_indices()
        skip_fields = ['upserted', 'modified', 'matched']
        for field in skip_fields:
            result.pop(field, None)
        return result, types_new

    def create_messages_indices(self):
        self.mongo.db.messages.create_index('ts')
        self.mongo.db.messages.create_index('to')
        self.mongo.db.messages.create_index('type')
        self.mongo.db.messages.create_index('from')
        self.mongo.db.messages.create_index([('msg', 'text')],
                                            default_language='ru')

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
        query = self.mongo.db.messages.find(
            {'to': stream},
            sort=[('ts', -1)],
            skip=page * MESSAGES_NUMBER_PER_STREAM_REQUEST,
            limit=MESSAGES_NUMBER_PER_STREAM_REQUEST)
        return self._prepare_messages(query)

    def find_messages(self, query, streams, page):
        condition = {'$text': {'$search': query}, 'to': {'$in': streams}}
        return self._search_messages(condition, page)

    def find_messages_around(self, context, stream, page):
        timestamp = self._ts_from_message_uid(context)
        condition = {'ts': {'$lt': timestamp + 60 * 60,
                            '$gt': timestamp - 60 * 60},
                     'to': stream}
        return self._search_messages(condition, page)

    def find_messages_in_stream(self, query, stream, page):
        condition = {'$text': {'$search': query}, 'to': stream}
        return self._search_messages(condition, page)

    def _search_messages(self, condition, page):
        query = self.mongo.db.messages.find(
            condition,
            sort=[('ts', -1)],
            skip=page * MESSAGES_NUMBER_PER_SEARCH_REQUEST,
            limit=MESSAGES_NUMBER_PER_SEARCH_REQUEST)
        return self._prepare_messages(query)

    def has_stream_access(self, user_info, stream_id):
        if stream_id not in self.streams:
            return False
        if self.streams[stream_id]['type'] == SlackArchive.PUBLIC:
            return True
        cur_person = self.people[user_info['user']]
        if stream_id in cur_person.get('groups', []):
            return True
        if stream_id in cur_person.get('ims', []):
            return True
        return False

    def stat(self):
        people_count = sum(person.get('active', False)
                           for person in self.people.values())
        tokens_count = len(self.tokens)
        advanced_auth_count = sum(person['full_access']
                                  for person in self.tokens.values())
        public = sum(stream['type'] == SlackArchive.PUBLIC
                     for stream in self.streams.values())
        private = sum(stream['type'] == SlackArchive.PRIVATE
                      for stream in self.streams.values())
        direct = sum(stream['type'] == SlackArchive.DIRECT
                     for stream in self.streams.values())
        msgs_stat = self.mongo.db.command('collstats', 'messages')
        return [
            {'Full access logins': advanced_auth_count},
            {'Limited access logins': tokens_count-advanced_auth_count},
            {'People in team': people_count},
            {'': ''},
            {'Public channels': public},
            {'Private groups': private},
            {'Direct message streams': direct},
            {'': ''},
            {'Total messages imported': msgs_stat['count']},
        ]
