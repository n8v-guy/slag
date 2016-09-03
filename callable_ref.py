# -*- coding: utf-8 -*-
"""Helpers for serializing callable objects"""
import base64
import functools
import itertools
import sys

import six


def equals(func_left, func_right):
    """Compare functions and partials"""
    # plain functions
    if func_left == func_right:
        return True
    # functools.partial implementation
    return (isinstance(func_left, functools.partial) and
            isinstance(func_right, functools.partial) and
            func_left.func == func_right.func and
            func_left.args == func_right.args and
            func_left.keywords == func_right.keywords)


def unwrap(func):
    """Unwrap partial if no parameters there"""
    if isinstance(func, functools.partial):
        if len(func.args) != 0 or len(func.keywords.keys()) != 0:
            return func
        func = func.func
    return func


def equals_soft(func_left, func_right):
    """Compare functions and partials with ability to have a wrapper"""
    if equals(func_left, func_right):
        return True
    return unwrap(func_left) == unwrap(func_right)


def pure_base64_dumps(elem):
    """return pure base64 value, without CR & equals signs"""
    return base64.encodestring(elem).replace('=', '').replace('\n', '')


def pure_base64_loads(elem):
    """return source value from base64, adding mandatory equals signs"""
    while len(elem) % 8 != 0:
        elem += '='
    return base64.decodestring(elem)


class Callable(object):
    """This class allows to serialize functions and partials with parameters"""
    def __init__(self, *args):
        self.instance_map = {}
        for arg in args:
            self.instance_map[type(arg).__name__] = arg

    def _extract_callable_name(self, func):
        """
        :returns the best available display name for the given callable
        :rtype: str
        """
        # the easy case (on Python 3.3+)
        if hasattr(func, '__qualname__'):
            return func.__qualname__

        # class methods, bound and unbound methods
        f_self = getattr(func, '__self__', None) or \
            getattr(func, 'im_self', None)
        if f_self and hasattr(func, '__name__'):
            f_class = f_self if isinstance(f_self, type) else f_self.__class__
        else:
            f_class = getattr(func, 'im_class', None)

        if f_class and hasattr(func, '__name__'):
            self.instance_map[f_class.__name__] = f_self
            return '%s.%s,%s' % (f_class.__name__, func.__name__,
                                 f_class.__name__)

        # class or class instance
        if hasattr(func, '__call__'):
            # class
            if hasattr(func, '__name__'):
                return func.__name__

            # instance of a class with a __call__ method
            return func.__class__.__name__

        assert False, "Function, method or callable class should be passed"

    def _dumps(self, elem):
        """:returns parameter to serialize"""
        if callable(elem):  # callable wrapped in string
            return 'call@%s' % pure_base64_dumps(self.dumps(elem))
        if isinstance(elem, six.integer_types):
            return 'int@%i' % elem
        if isinstance(elem, six.string_types):
            return 'str@%s' % pure_base64_dumps(elem)
        if isinstance(elem, list):  # avoid passing namedtuple here
            return 'list@%s' % pure_base64_dumps(
                '|'.join([self._dumps(el) for el in elem]))
        el_typename = type(elem).__name__
        assert el_typename in self.instance_map.keys(), \
            'Cannot serialize [%s] object' % el_typename
        assert elem == self.instance_map[el_typename], \
            'Value isn\'t supported: [%s] is not a singleton' % el_typename
        return el_typename

    def _loads(self, el_str):
        """:returns deserialized parameter"""
        if el_str.startswith('call@'):
            return self.loads(pure_base64_loads(el_str[len('call@'):]))
        if el_str.startswith('int@'):
            return int(el_str[len('int@'):])
        if el_str.startswith('str@'):
            return pure_base64_loads(el_str[len('str@'):])
        if el_str.startswith('list@'):
            list_el = pure_base64_loads(el_str[len('list@'):]).split('|')
            return [self._loads(el) for el in list_el]
        assert el_str in self.instance_map.keys(), \
            'Cannot deserialize [%s] object' % el_str
        return self.instance_map[el_str]

    def _dumps_params(self, *args, **kwargs):
        """:returns string having serialized parameters list"""
        str_args = [self._dumps(arg) for arg in args]
        str_kwargs = ['%s=%s' % (name, self._dumps(arg))
                      for name, arg in six.iteritems(kwargs)]
        return ','.join(itertools.chain(str_args, str_kwargs))

    @staticmethod
    def printable_params(*args, **kwargs):
        """:returns string having serialized parameters list"""
        args_str = [repr(arg) for arg in list(args) + kwargs.items()]
        return ', '.join(args_str)

    def loads_params(self, str_params):
        """:returns tuple (args, kwargs) deserialized"""
        params = str_params.split(',')
        args = tuple([self._loads(arg) for arg in params
                      if '=' not in arg])
        kwargs = {name: self._loads(arg)
                  for name, arg in [kwarg.split('=') for kwarg in params
                                    if '=' in kwarg]}
        return args, kwargs

    def dumps(self, functor, *args, **kwargs):
        """:returns the path to the given functor"""
        if isinstance(functor, functools.partial):
            assert len(args) == 0 and len(kwargs.keys()) == 0, \
                'Nested partials are not yet supported'
            return self.dumps(functor.func,
                              *(functor.args or []),
                              **(functor.keywords or {}))

        ref = '%s:%s#%s' % (functor.__module__,
                            self._extract_callable_name(functor),
                            self._dumps_params(*args, **kwargs))
        return ref

    def loads(self, ref):
        """:returns the functor pointed to by ref"""
        assert isinstance(ref, six.string_types), 'References must be strings'
        assert ':' in ref, 'Invalid reference'
        self_link = None
        ref, params = ref.split('#')
        if ',' in ref:
            ref, self_link = ref.split(',')

        module_name, rest = ref.split(':', 1)

        assert module_name in sys.modules, \
            'Error resolving module ' + module_name

        functor_iter = __import__(module_name)
        for name in module_name.split('.')[1:] + rest.split('.'):
            functor_iter = getattr(functor_iter, name)
        if self_link:
            self_obj = self.instance_map[self_link]
            functor_iter = functor_iter.__get__(self_obj, type(self_obj))
        if params:
            args, kwargs = self.loads_params(params)
            functor_iter = functools.partial(functor_iter, *args, **kwargs)
        return functor_iter
