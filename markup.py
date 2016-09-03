"""Util to work with Slack users message formatting"""
# pylint: disable=fixme,missing-docstring,unused-variable,invalid-name
import re


def wrap_html(text):
    return '||[' + text + ']||'


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
QUOT_RE = re.compile(r'^>\s*(.+?)$[\n]?', re.MULTILINE)
LNGQ_RE = re.compile(r'>>>\s*(.+)[\n]*', re.MULTILINE | re.DOTALL)
MULQ_RE = re.compile(re.escape(wrap_html('</blockquote>')) +
                     re.escape(wrap_html('<blockquote>')), re.MULTILINE)


class Markup(object):
    """Converting markup to HTML"""

    def user_name(self, user):
        uid = user[1:]
        if uid in self.people:
            return '@'+self.people[uid]['login']
        return user

    def stream_name(self, stream):
        return '#'+self.streams[stream[1:]]['name']

    @staticmethod
    def link_page(url, title):
        if not title:
            title = url
        return wrap_html('<a href="'+url+'">'+title+'</a>')

    def link_user(self, user):
        return Markup.link_page('javascript:void(0)', self.user_name(user))

    def link_stream(self, stream):
        return Markup.link_page('javascript:void(0)', self.stream_name(stream))

    def parse_link(self, m):
        target = m.group(1)
        label = m.group(2)
        if target.startswith('@'):
            return self.link_user(target)
        if target.startswith('#'):
            return self.link_stream(target)
        if target.startswith('!'):
            return Markup.link_page('javascript:void(0)', '@'+target[1:])
        if target.startswith('http://') or \
           target.startswith('https://') or \
           target.startswith('mailto:'):
            return Markup.link_page(target, label)
        return m.group(0)

    @staticmethod
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

    @staticmethod
    def markup(regexp, tag, s, code=False):
        def wrap_all(m):
            return wrap_html('<'+tag+'>'+raw_text(m.group(1))+'</'+tag+'>')

        def wrap_tags(m):
            return wrap_html('<'+tag+'>')+m.group(1)+wrap_html('</'+tag+'>')

        return Markup.re_iter(regexp, wrap_all if code else wrap_tags, s)

    def __init__(self, msg, people, streams):
        self.people = people
        self.streams = streams
        # TODO Add tests cases around
        msg = msg.replace('&gt;', '>')  # when not from user ('&amp;gt;' then)
        # markup processing
        msg = self.markup(PREF_RE, 'pre', msg, True)
        msg = self.markup(LNGQ_RE, 'blockquote', msg)
        msg = self.markup(QUOT_RE, 'blockquote', msg)
        msg = re.sub(MULQ_RE, wrap_html('<br/>'), msg)
        msg = self.markup(CODE_RE, 'code', msg, True)
        msg = self.markup(STRK_RE, 'strike', msg)
        msg = self.markup(BOLD_RE, 'b', msg)
        msg = self.markup(ITAL_RE, 'i', msg)
        msg = self.re_iter(LINK_RE, self.parse_link, msg)
        # apply entities for sources
        msg = use_entities(msg)
        # restore markup
        msg = re.sub(HTML_RE, restore_html, msg)
        msg = msg.replace('\n', '<br/>')
        self.str = msg

    def __str__(self):
        return self.str
