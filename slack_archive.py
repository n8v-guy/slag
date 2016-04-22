# pylint: disable=fixme,missing-docstring
import atexit
import functools
import json
import logging
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

    def __init__(self, server_callback):
        # scheduler in background
        atexit.register(self.background_stop)
        server_callback(schedule)
        self.background_task()

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
    PUBLIC = 0
    PRIVATE = 1  # no MPIMs here
    DIRECT = 2  # MPIMs are here

    def __init__(self, db, ctx, tokens, api_key):
        self.database = db
        self.log = SlackArchive.get_logger()
        self.people = mongo_store.MongoStore(self.database.users, ctx)
        self.streams = mongo_store.MongoStore(self.database.streams, ctx)
        self.tokens = tokens
        self.api_handle = Slacker(api_key)
        self.timers = Scheduler(self._setup_scheduler)

    def _setup_scheduler(self, scheduler):
        scheduler.every(10).minutes.do(self.tokens_validation)
        scheduler.every(10).minutes.do(self.people_fetch_all)
        scheduler.every(30).minutes.do(self.fetch_public_messages)
        scheduler.every(30).minutes.do(self.fetch_private_messages)

    @staticmethod
    def get_logger():
        log = logging.getLogger(__name__)
        log.setLevel(logging.INFO)
        log_handler = logging.StreamHandler()
        log_handler.setFormatter(
            logging.Formatter('%(levelname)-7s | %(message)-80s | '
                              '%(filename)s:%(lineno)d | '
                              '%(asctime)s | %(funcName)s | '
                              '%(threadName)s'))
        log.addHandler(log_handler)
        return log

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
        return results

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
        # skip current person login from conversation name
        direct = [dict(d) for d in direct]
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
            bulk = self.database.users.initialize_ordered_bulk_op()
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
        bulk = self.database.streams.initialize_ordered_bulk_op()
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
        bulk = self.database.messages.initialize_ordered_bulk_op()
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
        types_ignore = {'pinned_item', 'file_comment', 'bot_message'}
        return types_import, types_ignore

    @staticmethod
    def _import_messages_bulk(bulk, channel, msgs,
                              types_import, types_ignore):
        # no sort for API results (default sorting method), reverse for exports
        msgs = sorted(msgs, key=lambda m: float(m['ts']), reverse=True)
        msg_counter = 0
        for msg in msgs:
            subtype = msg.get('subtype', '')
            if subtype not in types_import:
                if subtype not in types_ignore:
                    types_ignore.add(subtype)
                continue
            msg_counter += 1
            msg_id = SlackArchive._message_uid(channel['id'], msg['ts'])
            bulk.find({'_id': msg_id}).upsert().update(
                {'$set': {'ts': float(msg['ts']),
                          'type': hash(subtype),
                          # TODO check other useful fields
                          'msg': msg['text'],
                          'from': msg['user'],
                          'to': channel['id']}})
        return msg_counter, msgs[0]['ts']

    def tokens_validation(self):
        self.log.info('Validating tokens')
        for token, enc_key in self.tokens.decrypt_keys_map().items():
            time.sleep(1)
            self.log.info('Check token %s', token)
            try:
                user_info = Slacker(token).auth.test().body
            except Error as err:
                self.database.z_errors.insert_one({'_id': time.time(),
                                                   'ctx': 'tokens_validation',
                                                   'msg': str(err)})
                self.log.exception('Error %s for token %s', str(err), token)
                del self.tokens[enc_key]
                continue
            self.log.info('Valid token')
            self.tokens.upsert(token, user_info)

    def people_fetch_all(self):
        self.log.info('Fetching people list here')
        try:
            people = self.api_handle.users.list().body
        except Error as err:
            self.log.exception('Fetching people list exception %s', str(err))
            return
        # TODO add bulk_op wrapper for mongo_store
        for person in people['members']:
            item_id = person['id']
            item = dict(self.people.get(item_id, {}))
            item['name'] = person['profile']['real_name']
            item['login'] = person['name']
            item['avatar'] = person['profile']['image_72']
            item['active'] = (not person.get('deleted', True) and
                              not person.get('is_bot', True))
            self.people[item_id] = item

    def streams_fetch(self, token):
        enc_key = self.tokens.get_key_by_known_token(token)
        user_info = self.tokens[enc_key]
        if user_info['full_access']:
            try:
                self.log.info('Fetch channels for %s', user_info['login'])
                all_ch = Slacker(token).channels.list().body
                self.people.set_field(user_info['user'], 'channels',
                                      SlackArchive._filter_channel_ids(all_ch))
                self.update_streams(all_ch)  # not a duplicate op: fight races
                self.log.info('Fetch %s\'s private groups', user_info['login'])
                groups = Slacker(token).groups.list().body
                self.people.set_field(user_info['user'], 'groups',
                                      SlackArchive._filter_group_ids(groups))
                self.update_streams(groups, user_info['user'])
                self.log.info('Fetch direct msgs for %s', user_info['login'])
                ims = Slacker(token).im.list().body
                self.people.set_field(user_info['user'], 'ims',
                                      SlackArchive._filter_im_ids(groups, ims))
                self.update_streams(ims, user_info['user'])
            except Error as err:
                self.database.z_errors.insert_one({'_id': time.time(),
                                                   'ctx': 'channels_fetch',
                                                   'msg': str(err)})
                self.log.exception('Fetch streams error %s', str(err))
                # full access was revoked
                if str(err) == 'missing_scope':
                    self.tokens.set_field(enc_key, 'full_access', False)

    def fetch_private_messages(self):
        self.log.info('Fetching private groups & ims messages')
        for token, enc_key in self.tokens.decrypt_keys_map().items():
            user_info = self.tokens[enc_key]
            if not user_info['full_access']:
                continue
            self.streams_fetch(token)
            api_handle = Slacker(token)
            self.log.info('Fetching private groups for %s', user_info['login'])
            self._fetch_person_groups_history(user_info, api_handle)
            self.log.info('Fetching private ims for %s', user_info['login'])
            self._fetch_person_ims_history(user_info, api_handle)

    def _fetch_person_groups_history(self, user_info, api_handle):
        try:
            groups = api_handle.groups.list().body
        except Error as err:
            self.database.z_errors.insert_one({'_id': time.time(),
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
        except Error as err:
            self.database.z_errors.insert_one({'_id': time.time(),
                                               'ctx': ('fetch_person_ims ' +
                                                       user_info['login']),
                                               'msg': str(err)})
            self.log.exception('Fetch person groups error %s', str(err))
            return
        api_loader = functools.partial(api_handle.im.history,
                                       inclusive=0, count=1000)
        self._fetch_stream_messages(api_loader, ims['ims'])

    def fetch_public_messages(self):
        self.log.info('Fetching public channels messages')
        try:
            chans_list = self.api_handle.channels.list().body
        except Error as err:
            self.database.z_errors.insert_one({'_id': time.time(),
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
        bulk = self.database.messages.initialize_ordered_bulk_op()
        bulk_total_size = 0
        while True:
            time.sleep(1)
            has_more, last_msg_ts, bulk_count = self._iterate_messages_history(
                api_loader, stream, last_msg_ts, bulk)
            bulk_total_size += bulk_count
            if not has_more:
                break
        if bulk_total_size:
            bulk.execute()
            if last_msg_ts != '0':  # import non-contiguous history
                self.streams.set_field(stream['id'], 'last_msg', last_msg_ts)
            self.log.info('Fetched %s new message(s) from %s',
                          bulk_total_size, self.streams[stream['id']]['name'])

    def _iterate_messages_history(self, api_loader, stream, last_msg_ts, bulk):
        msgs = api_loader(stream['id'], oldest=last_msg_ts).body
        types_import, types_ignore = SlackArchive._message_type_sets()
        if msgs['messages']:
            bulk_op_count, last_import_ts = SlackArchive._import_messages_bulk(
                bulk, stream, msgs['messages'], types_import, types_ignore)
        else:
            bulk_op_count, last_import_ts = 0, last_msg_ts
        if msgs['is_limited']:
            self.log.warning('Limited stream history for %s',
                             self.streams[stream['id']]['name'])
            return False, '0', bulk_op_count
        return msgs['has_more'], last_import_ts, bulk_op_count

    def _update_stream(self, item, src_user=None):
        sid = item['id']
        stream = dict(self.streams.get(sid, {}))
        item_type = SlackArchive._stream_type(item)

        stream['name'] = item.get('name')
        if item_type == SlackArchive.DIRECT:
            members = item.get('members', [])
            if not members:
                assert src_user is not None
                members = [src_user, item['user']]
            logins = ['@'+self.people[m]['login'] for m in members]
            stream['name'] = '+'.join(sorted(logins))
        is_archived = (item.get('is_archived', False) or
                       item.get('is_user_deleted', False))
        stream['active'] = not is_archived
        stream['topic'] = ('' if 'topic' not in item
                           else item['topic']['value'])
        pins = SlackArchive._pins_from_stream(item)
        if pins:
            stream['pins'] = pins
        stream['type'] = item_type
        stream['purpose'] = ('' if 'purpose' not in item
                             else item['purpose']['value'])
        # TODO Add cheap method for mongo_store for this
        self.streams[sid] = stream

    @staticmethod
    def _stream_type(item):
        if item.get('is_mpim', False) or item.get('is_im', False):
            item_type = SlackArchive.DIRECT
        elif item.get('is_group', False):
            item_type = SlackArchive.PRIVATE
        else:
            assert item['is_channel']
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
        query = self.database.messages.find(
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

    def people_stat(self):
        total = sum([person.get('active', False)
                     for person in self.people.values()])
        tokens = len(self.tokens)
        advanced = sum([person['full_access']
                        for person in self.tokens.values()])
        return '{} / {} / {}'.format(total, tokens, advanced)
