# -*- coding: utf-8 -*-
'''
Taint Mode for Python via a Library

Copyright 2009 Juan José Conti
Copyright 2010 Juan José Conti - Alejandro Russo

This file is part of taintmode.py

taitmode is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

taintmode.py is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with taintmode.py.  If not, see <http://www.gnu.org/licenses/>.

'''
import inspect
import sys
from itertools import chain


__version__ = 'trunk-svn-2'

__all__ = ['tainted', 'taint', 'untrusted', 'untrusted_args', 'ssink',
           'validator', 'cleaner', 'STR', 'INT', 'FLOAT', 'UNICODE', 'chr',
           'ord', 'len', 'ends_execution', 'XSS', 'SQLI', 'OSI', 'II']


ENDS = False
RAISES = False
KEYS  = [XSS, SQLI, OSI, II] = range(1, 5)
TAGS = set(KEYS)


class TaintException(Exception):
    pass


def ends_execution(b=True):
    global ENDS
    ENDS = b


# ------------------------- Taint-aware functions -----------------------------
def propagate_func(original):
    def inner (*args, **kwargs):
        t = set()
        for a in args:
            collect_tags(a, t)
        for v in kwargs.values():
            collect_tags(v, t)
        r  = original(*args, **kwargs)
        if t == set([]):
            return r
        r = taint_aware(r, t)
        return r
    return inner

len = propagate_func(len)
ord = propagate_func(ord)
chr = propagate_func(chr)

# ------------------------- Auxiliaries functions -----------------------------

def mapt(o, f, check=lambda o: type(o) in tclasses.keys()):
    if check(o):
        return f(o)
    elif isinstance(o, list):
        return [mapt(x, f, check) for x in o]
    elif isinstance(o, tuple):
        return tuple([mapt(x, f, check) for x in o])
    elif isinstance(o, set):
        return  set([mapt(x, f, check) for x in o])
    elif isinstance(o, dict):
        klass = type(o) # It's quite common for frameworks to extend dict
                        # with useful new methdos - i.e. web.py
        return klass([(k, mapt(v, f, check)) for k, v in o.items()])
    else:
        return o


def remove_taint(v):
    def _remove(o):
        if hasattr(o, 'taints'):
            o.taints.discard(v)
    return _remove


def remove_tags(r, v):
    mapt(r, remove_taint(v), lambda o: True)


def collect_tags(s, t):
    '''Collect tags from a source s into a target t.'''
    mapt(s, lambda o: t.update(o.taints), lambda o: hasattr(o, 'taints'))


def update_tags(r, t):
    mapt(r, lambda o: o.taints.update(t), lambda o: hasattr(o, 'taints'))


def taint_aware(r, ts=set()):
    r = mapt(r, tclass)
    update_tags(r, ts)
    return r


# ------------------------- Decorators ----------------------------------------

def untrusted_args(nargs=[], nkwargs=[]):
    '''
    Mark a function or method that would recive untrusted values.

    nargs is a list of positions. Positional arguments in that position will be
    tainted for all the types of taint.
    nkwargs is a list of strings. Keyword arguments for those keys will be
    tainted for all the types of taint.

    >>> @untrusted_args([0])
    ... def noconfialbe(algo):
    ...     return algo
    >>> type(noconfialbe("string"))
    <class '__main__.tklass'>

    adsasd
    asd
    adsasdad
    a
    >>> a = noconfialbe("alg")
    >>> a.taints
    set([1, 2, 3, 4])

    '''
    def _untrusted_args(f):
        def inner(*args, **kwargs):
            args = list(args)   # args is a tuple
            for n in nargs:
                args[n] = mapt(args[n], taint)
            for n in nkwargs:
                kwargs[n] = mapt(kwargs[n], taint)
            r = f(*args, **kwargs)
            return r
        return inner
    return _untrusted_args

def untrusted(f):
    '''
    Mark a function or method as untrusted.

    The returned value will be tainted for all the types of taint.
    '''
    def inner(*args, **kwargs):
        r = f(*args, **kwargs)
        return taint_aware(r, TAGS)
    return inner

def validator(v, cond=True, nargs=[], nkwargs=[]):
    '''
    Mark a function or method as capable to validate its input.

    nargs is a list of positions. Positional arguments in that positions are
    the ones validated.
    nkwargs is a list of strings. Keyword arguments for those keys are the ones
    validated.
    If the function returns cond, v will be removed from the the validated
    inpunt.

    Example:

    for a function called invalid_mail, cond is liked to be False. If
    invalid_mail returns False, then the mail IS valid and have no craft data
    on it.

    for a function called valid_mail, cond is liked to be True.
    '''
    def _validator(f):
        def inner(*args, **kwargs):
            r = f(*args, **kwargs)
            if r == cond:
                tovalid = set([args[n] for n in nargs])
                tovalid.update([kwargs[n] for n in nkwargs])
                for a in tovalid:
                    remove_tags(a, v)
            return r
        return inner
    return _validator


def cleaner(v):
    '''
    Mark a function or methos as capable to clean its input.

    v is removed from the returned value.
    '''
    def _cleaner(f):
        def inner(*args, **kwargs):
            r = f(*args, **kwargs)
            remove_tags(r, v)
            return r
        return inner
    return _cleaner

def reached(t, v=None):
    '''
    Execute if a tainted value reaches a sensitive sink
    for the vulnerability v.
    '''
    frame = sys._getframe(3)
    filename = inspect.getfile(frame)
    lno = frame.f_lineno
    print "=" * 79
    print "Violation in line %d from file %s" % (lno, filename)
    # Localize this message
    print "Tainted value: %s" % t
    print '-' * 79
    lineas = inspect.findsource(frame)[0]
    lineas = ['    %s' % l for l in lineas]
    lno = lno - 1
    lineas[lno] = '--> ' + lineas[lno][4:]
    lineas = lineas[lno - 3: lno + 3]
    print "".join(lineas)
    print "=" * 79

def ssink(v=None, reached=reached):
    '''
    Mark a function or method as sensitive to tainted data.

    If it is called with a value with the v tag
    (or any tag if v is None),
    it's not executed and reached is executed instead.
    '''
    def _solve(a, f, args, kwargs):
        if ENDS:
            if RAISES:
                reached(a)
                raise TaintException
            else:
                return reached(a)
        else:
            reached(a)
            return f(*args, **kwargs)

    def _ssink(f):
        def inner(*args, **kwargs):
            allargs = chain(args, kwargs.values())
            if v is None:   # sensitive to ALL
                for a in allargs:
                    t = set()
                    collect_tags(a, t)
                    if t:
                        return _solve(a, f, args, kwargs)
            else:
                for a in allargs:
                    t = set()
                    collect_tags(a, t)
                    if v in t:
                        return _solve(a, f, args, kwargs)
            return f(*args, **kwargs)
        return inner
    return _ssink

def tainted(o, v=None):
    '''
    Tells if a value o, ant tclass instance, is tainted for the given vul.

    If v is None, test if o.taints is not empty.
    '''
    if not hasattr(o, 'taints'):
        return False
    if v is not None:   #OJO CON EL 0
        return v in o.taints
    if o.taints:
        return True
    return False

def taint(o, v=None):
    '''
    Helper function for taint variables.
    '''
    ts = set()
    if v is not None:
        ts.add(v)
    else:
        ts.update(TAGS)

    return taint_aware(o, ts)

# ------------------------- Taint-aware classes -------------------------------

def propagate_method(method):
    def inner(self, *args, **kwargs):
        r = method(self, *args, **kwargs)
        t = set()
        for a in args:
            collect_tags(a, t)
        for v in kwargs.values():
            collect_tags(v, t)
        t.update(self.taints)
        return taint_aware(r, t)
    return inner


def taint_class(klass, methods=None):
    if not methods:
        methods = attributes(klass)
    class tklass(klass):
        def __new__(cls, *args, **kwargs):
            self = super(tklass, cls).__new__(cls, *args, **kwargs) #justificar analizar pq no init
            self.taints = set()

            # if any of the arguments is tainted, taint the object aswell

            for a in args:      # this CHUNK of code appears at least 3 times, refactor later
                collect_tags(a, self.taints)
            for v in kwargs.values():
                collect_tags(v, self.taints)

            return self

        # support for assigment and taint change in classobj

        def __setattr__(self, name, value):
            if self.__dict__ and name in self.__dict__ and tainted(self.__dict__[name]):
                for t in self.__dict__[name].taints:
                    # if other field had it, keep it
                    taintsets = [v.taints for k,v in self.__dict__.items() if not callable(v) and tainted(v) and k != name]
                    if not any([t in x for x in taintsets]):
                        self.taints.remove(t)

            if self.__dict__ is not None:
                self.__dict__[name] = value
                if tainted(value):
                    self.taints.update(value.taints)

    d = klass.__dict__
    for name, attr in [(m, d[m]) for m in methods]:
        if inspect.ismethod(attr) or inspect.ismethoddescriptor(attr):
            setattr(tklass, name, propagate_method(attr))
    # str has no __radd__ method
    if '__add__' in methods and '__radd__' not in methods:
        setattr(tklass, '__radd__', lambda self, other:
                                    tklass.__add__(tklass(other), self))
    # unicode __rmod__ returns NotImplemented
    if klass == unicode:
        setattr(tklass, '__rmod__', lambda self, other:
                                    tklass.__mod__(tklass(other), self))
    return tklass


dont_override = set(['__repr__', '__cmp__', '__getattribute__', '__new__',
                     '__init__','__nonzero__', '__reduce__', '__reduce_ex__',
                     '__str__', '__int__', '__float__', '__unicode__'])


# ------- Taint-aware classes for strings, integers, floats, and unicode ------

def attributes(klass):
    a = set(klass.__dict__.keys())
    return a - dont_override

str_methods = attributes(str)
unicode_methods = attributes(unicode)
int_methods = attributes(int)
float_methods = attributes(float)

STR = taint_class(str, str_methods)
UNICODE = taint_class(unicode, unicode_methods)
INT = taint_class(int, int_methods)
FLOAT = taint_class(float, float_methods)

tclasses = {str: STR, int: INT, float: FLOAT, unicode: UNICODE}

def tclass(o):
    '''Tainted instance factory.'''
    klass = type(o)
    if klass in tclasses.keys():
        return tclasses[klass](o)
    else:
        raise KeyError

if __name__ == "__main__":
        import doctest
        doctest.testmod()
