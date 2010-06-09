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
from taintmode import *
import unittest

ends_execution()

def reached(f):
    return False

@untrusted
def some_input(value="some input from the outside"):
    '''Some random input from the 'outside'.'''
    return value

@cleaner(SQLI)
def cleanSQLI(s):
    '''Dummy SQL injection cleaner.'''
    return s.replace("--", "")

@cleaner(XSS)
def cleanXSS(s):
    '''Dummy XSS cleaner.'''
    return s.replace("<", "&lt;")

@cleaner(II)
def cleanII(s):
    '''Dummy II cleaner.'''
    return s.replace("os", "")

@cleaner(OSI)
def cleanOSI(s):
    '''Dummy OSI cleaner.'''
    return s.replace(";", "")

@ssink(reached=reached)
def saveDB1(valor):
    '''Dummy save in database function. Sensitive to all vulnerabilities.'''
    return True

@ssink(v=SQLI, reached=reached)
def saveDB2(valor):
    '''Dummy save in database function. Only sensitive to SQL injection.'''
    return True

@ssink(v=XSS, reached=reached)
def saveDB3(valor):
    '''Dummy save in database function. Only sensitive to SQL injection.'''
    return True

# Para some_input() se debe usar siempre un valor nuevo para evitar
# que el orden en que se ejecutan los tests y el hecho de que TAINTED sea
# global afecte el resultado.

class TestTaintFlow(unittest.TestCase):

    def test_tainted(self):
        '''a tainted value reaches a sensitive sink.'''

        i = some_input('a r v r a s s')
        self.assertFalse(saveDB1(i))

    def test_tainted_not_clean_anough(self):
        '''a partial tainted value reaches a full sensitive sink.'''

        i = some_input('a p t v r a f s s')
        self.assertFalse(saveDB1(cleanSQLI(i)))

    def test_not_tainted(self):
        '''an SQLI-cleaned value reaches a SQLI-sensitive sink.
        It's all right.'''

        i = some_input('a s c v r a s s s i a r')
        self.assertTrue(saveDB2(cleanSQLI(i)))


class TestSTR(unittest.TestCase):

    def test_right_concatenation_not_cleaned(self):
        '''a tainted value is right concatenated with a non tainted value.
        The result is tainted. If not cleaned, the taint reaches the sink.'''

        i = some_input('right concatenation')
        self.assertFalse(saveDB2(i + "hohoho"))

    def test_left_concatenation_not_cleaned(self):
        '''a tainted value is left concatenated with a non tainted value.
        The result is tainted. If not cleaned, the taint reaches the sink.'''

        i = some_input('left concatenation')
        self.assertFalse(saveDB2("hohoho" + i))

    def test_right_concatenation(self):
        '''a tainted value is right concatenated with a non tainted value.
        The result is tainted.'''

        i = some_input('clean right concatenation')
        self.assertTrue(saveDB2(cleanSQLI(i + "hohoho")))

    def test_left_concatenation(self):
        '''a tainted value is left concatenated with a non tainted value.
        The result is tainted.'''

        i = some_input('clean left concatenation')
        self.assertTrue(saveDB2(cleanSQLI("hohoho" + i)))

    def test_indexing_not_cleaned(self):
        '''if you get an item from a tainted value, te item is also tainted.'''

        i = some_input('indexing')
        self.assertFalse(saveDB2(i[4]))

    def test_indexing(self):
        '''if you get an item from a tainted value, te item is also tainted.'''

        i = some_input('clean indexing')
        self.assertTrue(saveDB2(cleanSQLI(i[4])))

    def test_mul_not_cleaned(self):
        '''if s is tainted, s * n is also tainted.'''

        i = some_input('multi')
        self.assertFalse(saveDB2(i * 8))

    def test_mul(self):
        '''if s is tainted, s * n is also tainted.'''

        i = some_input('clean multi')
        self.assertTrue(saveDB2(cleanSQLI(i * 8)))

    def test_left_mul_not_cleaned(self):
        '''if s is tainted, n * s is also tainted.'''

        i = some_input('left multi')
        self.assertFalse(saveDB2(8 * i))

    def test_left_mul(self):
        '''if s is tainted, n * s is also tainted.'''

        i = some_input('clean left multi')
        self.assertTrue(saveDB2(cleanSQLI(8 * i)))

    def test_slice_not_cleaned(self):
        '''if  you slice a tainted value, the slice also tainted.'''

        i = some_input('take a slice')
        self.assertFalse(saveDB2(i[2:5]))

    def test_slice(self):
        '''if  you slice a tainted value, the slice also tainted.'''

        i = some_input('clean teke a slice')
        self.assertTrue(saveDB2(cleanSQLI(i[2:5] )))

    def test_mod_not_cleaned(self):
        '''if s is tainted, s % a is also tainted.'''

        i = some_input("fomat %s this 1")
        self.assertFalse(saveDB2(i % 'a'))

    def test_mod(self):
        '''if s is tainted, s % a is also tainted.'''

        i = some_input("fomat %s this 2")
        self.assertTrue(saveDB2(cleanSQLI(i % 'b')))

    def test_rmod_not_cleaned(self):
        '''if s is tainted, a % s is also tainted.'''

        i = some_input("ar1")
        self.assertFalse(saveDB2("%s" % i))

    def test_rmod(self):
        '''if s is tainted, a % s is also tainted.'''

        i = some_input("ar2")
        self.assertTrue(saveDB2(cleanSQLI("%s" % i)))

    # tests for public str methdos

    def test_join_not_cleaned(self):
        '''if s is tainted, s.join(aLista) is also tainted.'''

        i = some_input('join')
        self.assertFalse(saveDB2(i.join(['_', '_', '_'])))

    def test_join(self):
        '''if s is tainted, s.join(aLista) is also tainted.'''

        i = some_input('clean join')
        self.assertTrue(saveDB2(cleanSQLI(i.join(['_', '_', '_']))))

    # join with tainted value as argument, not suported.

    def test_capitalize_not_cleaned(self):
        '''if s is tainted. s.capitalize() is also tainted.'''

        i = some_input('capitalize')
        self.assertFalse(saveDB2(i.capitalize()))

    def test_capitalize(self):
        '''if s is tainted. s.capitalize() is also tainted.'''

        i = some_input('clean capitalize')
        self.assertTrue(saveDB2(cleanSQLI(i.capitalize())))

    def test_center_not_cleaned(self):
        '''if s is tainted. s.center(n) is also tainted.'''

        i = some_input('center')
        self.assertFalse(saveDB2(i.center(6)))

    def test_center(self):
        '''if s is tainted. s.center(n) is also tainted.'''

        i = some_input('clean center')
        self.assertTrue(saveDB2(cleanSQLI(i.center(6))))

    def test_expandtabs_not_cleaned(self):
        '''if s is tainted. s.expandtabs(n) is also tainted.'''

        i = some_input('\t')
        self.assertFalse(saveDB2(i.expandtabs(4)))

    def test_expandtabs(self):
        '''if s is tainted. s.expandtabs(n) is also tainted.'''

        i = some_input('\tclean\t')
        self.assertTrue(saveDB2(cleanSQLI(i.expandtabs(4))))

    def test_ljust_not_cleaned(self):
        '''if s is tainted. s.ljust(n) is also tainted.'''

        i = some_input('left just')
        self.assertFalse(saveDB2(i.ljust(42)))

    def test_ljust(self):
        '''if s is tainted. s.ljust(n) is also tainted.'''

        i = some_input('clean left just')
        self.assertTrue(saveDB2(cleanSQLI(i.ljust(42))))

    def test_lower_not_cleaned(self):
        '''if s is tainted. s.lower() is also tainted.'''

        i = some_input("NOT LOWER")
        self.assertFalse(saveDB2(i.lower()))

    def test_lower(self):
        '''if s is tainted. s.lower() is also tainted.'''

        i = some_input("CLEAN NOT LOWER")
        self.assertTrue(saveDB2(cleanSQLI(i.lower())))

    def test_lstrip_not_cleaned(self):
        '''if s is tainted. s.lstrip([chars]) is also tainted.'''

        i = some_input("       left spaces")
        self.assertFalse(saveDB2(i.lstrip()))

    def test_lstrip(self):
        '''if s is tainted. s.lstrip([chars]) is also tainted.'''

        i = some_input("       left spaces and clean")
        self.assertTrue(saveDB2(cleanSQLI(i.lstrip())))

    def test_partition_not_cleaned(self):
        '''s.partition(sep) -> head, sep, tail. If s is tainted,
        head, sep and tail are also tainted.'''

        i = some_input("sepa/rated")
        h, s, t = i.partition('/')
        self.assertFalse(saveDB2(h))
        self.assertFalse(saveDB2(s))
        self.assertFalse(saveDB2(t))

    def test_partition(self):
        '''s.partition(sep) -> head, sep, tail. If s is tainted,
        head, sep and tail are also tainted.'''

        i = some_input("clean sepa/rated")
        h, s, t = i.partition('/')
        self.assertTrue(saveDB2(cleanSQLI(h)))
        self.assertTrue(saveDB2(cleanSQLI(s)))
        self.assertTrue(saveDB2(cleanSQLI(t)))

    def test_replace_not_cleaned(self):
        '''if s is tainted. s.replace(old, new[, count]) is also tainted.'''

        i = some_input("a_a_a_a_a")
        self.assertFalse(saveDB2(i.replace('_', ' ')))

    def test_replace(self):
        '''if s is tainted. s.replace(old, new[, count]) is also tainted.'''

        i = some_input("clean_a_a_a_a_a")
        self.assertTrue(saveDB2(cleanSQLI(i.replace('_', ' '))))

    def test_replace_with_count_not_cleaned(self):
        '''if s is tainted. s.replace(old, new[, count]) is also tainted.'''

        i = some_input("a_a_a_a_a_count")
        self.assertFalse(saveDB2(i.replace('_', ' ', 2)))

    def test_replace_with_count(self):
        '''if s is tainted. s.replace(old, new[, count]) is also tainted.'''

        i = some_input("clean_a_a_a_a_a_count")
        self.assertTrue(saveDB2(cleanSQLI(i.replace('_', ' ', 2))))

    # replace with tainted value as argument, not suported.

    def test_rjust_not_cleaned(self):
        '''if s is tainted. s.rjust(n) is also tainted.'''

        i = some_input('right just')
        self.assertFalse(saveDB2(i.rjust(42)))

    def test_rjust(self):
        '''if s is tainted. s.rjust(n) is also tainted.'''

        i = some_input('clean right just')
        self.assertTrue(saveDB2(cleanSQLI(i.rjust(42))))

    def test_rpartition_not_cleaned(self):
        '''s.rpartition(sep) -> head, sep, tail. If s is tainted,
        head, sep and tail are also tainted.'''

        i = some_input("rsepa/rated")
        h, s, t = i.rpartition('/')
        self.assertFalse(saveDB2(h))
        self.assertFalse(saveDB2(s))
        self.assertFalse(saveDB2(t))

    def test_rpartition(self):
        '''s.rpartition(sep) -> head, sep, tail. If s is tainted,
        head, sep and tail are also tainted.'''

        i = some_input("clean rsepa/rated")
        h, s, t = i.rpartition('/')
        self.assertTrue(saveDB2(cleanSQLI(h)))
        self.assertTrue(saveDB2(cleanSQLI(s)))
        self.assertTrue(saveDB2(cleanSQLI(t)))

    def test_rsplit_not_cleaned(self):
        '''s.rsplit(sep) -> list of strings. If s is tainted,
        strings in the list are also tainted.'''

        i = some_input("right/sepa/rated")
        aList = i.rsplit('/')
        for l in aList:
            self.assertFalse(saveDB2(l))

    def test_rsplit(self):
        '''s.rsplit(sep) -> list of strings. If s is tainted,
        strings in the list are also tainted.'''

        i = some_input("clean/right/sepa/rated")
        aList = i.rsplit('/')
        self.assertTrue(len(aList) == 4)
        for l in aList:
            self.assertTrue(saveDB2(cleanSQLI(l)))

    def test_rsplit_max(self):
        '''s.rsplit(sep [, maxsplit]) -> list of strings. If s is tainted,
        strings in the list are also tainted.'''

        i = some_input("max/clean/right/sepa/rated")
        aList = i.rsplit('/', 1)
        self.assertTrue(len(aList) == 2)
        for l in aList:
            self.assertTrue(saveDB2(cleanSQLI(l)))

    def test_rstrip_not_cleaned(self):
        '''If s is tainted, s.rstrip([chars]) is also tainted.'''

        i = some_input("right strip it     ")
        self.assertFalse(saveDB2(i.rstrip()))

    def test_rstrip(self):
        '''If s is tainted, s.rstrip([chars]) is also tainted.'''

        i = some_input("clean right strip it     ")
        self.assertTrue(saveDB2(cleanSQLI(i.rstrip())))

    def test_split_not_cleaned(self):
        '''s.split(sep) -> list of strings. If s is tainted,
        strings in the list are also tainted.'''

        i = some_input("split/sepa/rated")
        aList = i.split('/')
        for l in aList:
            self.assertFalse(saveDB2(l))

    def test_split(self):
        '''s.split(sep) -> list of strings. If s is tainted,
        strings in the list are also tainted.'''

        i = some_input("clean/split/sepa/rated")
        aList = i.split('/')
        self.assertTrue(len(aList) == 4)
        for l in aList:
            self.assertTrue(saveDB2(cleanSQLI(l)))

    def test_split_max(self):
        '''s.split(sep [, maxsplit]) -> list of strings. If s is tainted,
        strings in the list are also tainted.'''

        i = some_input("max/clean/split/sepa/rated")
        aList = i.split('/', 1)
        self.assertTrue(len(aList) == 2)
        for l in aList:
            self.assertTrue(saveDB2(cleanSQLI(l)))

    def test_splitlines_not_cleaned(self):
        '''s.splitlines([keepends]) -> list of strings. If s is tainted,
        strings in the list are also tainted.'''

        i = some_input("line\nline\nline")
        aList = i.splitlines()
        for l in aList:
            self.assertFalse(saveDB2(l))

    def test_splitlines(self):
        '''s.splitlines([keepends]) -> list of strings. If s is tainted,
        strings in the list are also tainted.'''

        i = some_input("clean\nline\nline\nline")
        aList = i.splitlines()
        for l in aList:
            self.assertTrue(saveDB2(cleanSQLI(l)))

    def test_strip_not_cleaned(self):
        '''if s is tainted. s.strip([chars]) is also tainted.'''

        i = some_input("       leftright spaces       ")
        self.assertFalse(saveDB2(i.strip()))

    def test_strip(self):
        '''if s is tainted. s.strip([chars]) is also tainted.'''

        i = some_input("       leftright spaces and clean       ")
        self.assertTrue(saveDB2(cleanSQLI(i.strip())))

    def test_swapcase_not_cleaned(self):
        '''if s is tainted. s.swapcase() is also tainted.'''

        i = some_input('SwApCaSe')
        self.assertFalse(saveDB2(i.swapcase()))

    def test_swapcase(self):
        '''if s is tainted. s.swapcase() is also tainted.'''

        i = some_input('cLeAn SwApCaSe')
        self.assertTrue(saveDB2(cleanSQLI(i.swapcase())))

    def test_title_not_cleaned(self):
        '''if s is tainted. s.title() is also tainted.'''

        i = some_input('title this')
        self.assertFalse(saveDB2(i.title()))

    def test_title(self):
        '''if s is tainted. s.title() is also tainted.'''

        i = some_input('clean title this')
        self.assertTrue(saveDB2(cleanSQLI(i.title())))

    def test_translate_not_cleaned(self):
        '''if s is tainted. s.translate(table [, deletechars])
        is also tainted.'''

        i = some_input('translate it')
        self.assertFalse(saveDB2(i.translate('o'*256)))

    def test_translate(self):
        '''if s is tainted. s.translate(table [, deletechars])
           is also tainted.'''

        i = some_input('clean title this')
        self.assertTrue(saveDB2(cleanSQLI(i.translate('o'*256))))

    def test_upper_not_cleaned(self):
        '''if s is tainted. s.upper() is also tainted.'''

        i = some_input("not upper")
        self.assertFalse(saveDB2(i.upper()))

    def test_upper(self):
        '''if s is tainted. s.upper() is also tainted.'''

        i = some_input("clean not upper")
        self.assertTrue(saveDB2(cleanSQLI(i.upper())))

    def test_zfill_not_cleaned(self):
        '''if s is tainted. s.zfill(width) is also tainted.'''

        i = some_input("9")
        self.assertFalse(saveDB2(i.zfill(3)))

    def test_zfill(self):
        '''if s is tainted. s.zfill(width) is also tainted.'''

        i = some_input("8")
        self.assertTrue(saveDB2(cleanSQLI(i.zfill(3))))

    # Previous tests are for methods returning str or containers

    def test_len(self):
        '''if s is tainted. len(s) is also tainted.'''

        i = some_input("cinco")
        self.assertFalse(saveDB2(len(i)))

class TestINT(unittest.TestCase):

    def test_abs(self):
        i = some_input(1)
        self.assertTrue(tainted(abs(i)))

    def test_add(self):
        i = some_input(1)
        self.assertTrue(tainted(i + 2))

    def test_and(self):
        i = some_input(1)
        self.assertTrue(tainted(i & 2))

    def test_div(self):
        i = some_input(1)
        self.assertTrue(tainted(i / 2))

    def test_divmod(self):
        i = some_input(1)
        a,b = divmod(i, 2)
        self.assertTrue(tainted(a))
        self.assertTrue(tainted(b))

    #def test_float(self):
    #    '''If i is a tainted int, float(i) is tainted too.'''
    #    i = some_input(1)
    #    f = float(i)
    #    self.assertTrue(tainted(f))

    def test_floordiv(self):
        i = some_input(1)
        d = i // 2
        self.assertTrue(tainted(d))

    def test_radd(self):
        i = some_input(1)
        self.assertTrue(tainted(2 + i))

class TestFLOAT(unittest.TestCase):

    def test_abs(self):
        f = some_input(1.0)
        self.assertTrue(tainted(abs(f)))

    def test_add(self):
        f = some_input(1.0)
        self.assertTrue(tainted(f + 2))

    def test_div(self):
        f = some_input(1.0)
        self.assertTrue(tainted(f / 2))

    def test_divmod(self):
        f = some_input(1.0)
        a,b = divmod(f, 2)
        self.assertTrue(tainted(a))
        self.assertTrue(tainted(b))

    #def test_int(self):
    #    '''If f is a tainted float, int(f) is tainted too.'''
    #    f = some_input(1.0)
    #    i = float(f)
    #    self.assertTrue(tainted(i))

    def test_floordiv(self):
        f = some_input(1.0)
        d = f // 2
        self.assertTrue(tainted(d))

    def test_radd(self):
        f = some_input(1.0)
        self.assertTrue(tainted(2 + f))

class TestUNICODE(unittest.TestCase):

    def test_add(self):
        u = some_input(u'Asimov')
        #self.assertEqual(UNICODE, type(u))
        self.assertTrue(tainted(u + ' books'))

    def test_contains(self):
        u = some_input(u'Asimov')
        #self.assertEqual(UNICODE, type(u))
        self.assertTrue(tainted(u + ' books'))

    def test_rmod_not_cleaned(self):
        '''if s is tainted, a % s is also tainted.'''

        i = some_input(u"ar1")
        self.assertFalse(saveDB2("%s" % i))

    def test_rmod_not_cleaned_u(self):
        '''if s is tainted, a % s is also tainted.'''

        i = some_input(u"ar1")
        self.assertFalse(saveDB2(u"%s" % i))

    def test_rmod(self):
        '''if s is tainted, a % s is also tainted.'''

        i = some_input(u"ar2")
        self.assertTrue(saveDB2(cleanSQLI(u"%s" % i)))

class TestDict(unittest.TestCase):

    def test_dict(self):
        @untrusted
        def retorna_dict():
            return dict(a=1)

        d = retorna_dict()
        self.assertTrue(tainted(d['a']))

    def test_dictkind(self):
        class myDict(dict):
            pass

        @untrusted
        def retorna_dict():
            return myDict(a=1)

        d = retorna_dict()
        self.assertTrue(tainted(d['a']))

class TestCHR(unittest.TestCase):
    '''Test the chr built-it function. If the int-like argument is tainted,
     the returned string must be tainted too.'''

    def test_no_tainted_ord(self):
        c = chr(42)
        self.assertFalse(tainted(c))

    def test_tainted_ord(self):
        c = chr(INT(42))
        self.assertEqual(str, type(c))

    def test_same_taints(self):
        o = INT(42)
        o.taints.add(XSS)
        c = chr(o)
        self.assertTrue(XSS in c.taints)
        self.assertEqual(1, len(c.taints))

class TestORD(unittest.TestCase):
    '''Test the ord built-it function. If the str-like argument is tainted,
     the returned integer must be tainted too.'''

    def test_no_tainted_char(self):
        c = ord('*')
        self.assertFalse(tainted(c))

    def test_tainted_char(self):
        c = ord(STR('*'))
        self.assertEqual(int, type(c))

    def test_same_taints(self):
        c = STR('*')
        c.taints.add(XSS)
        o = ord(c)
        self.assertTrue(XSS in o.taints)
        self.assertEqual(1, len(o.taints))

class TestTaints(unittest.TestCase):

    def test_all_set(self):
        n = some_input('test all set')
        self.assertTrue(SQLI in n.taints)
        self.assertTrue(XSS in n.taints)

    def test_in_one_set(self):
        n = some_input('test in one set')
        n = cleanSQLI(n)
        self.assertFalse(SQLI in n.taints)
        self.assertTrue(XSS in n.taints)

    def test_in_no_set(self):
        n = some_input('test in no set')
        n = cleanSQLI(n)
        n = cleanXSS(n)
        self.assertFalse(SQLI in n.taints)
        self.assertFalse(XSS in n.taints)


class TestTainted(unittest.TestCase):

    def test_taint(self):
        x = 'taint'
        self.assertFalse(tainted(x))
        i = some_input(x)
        self.assertTrue(tainted(i))

    def test_taint_vul(self):
        x = 'taint_vul'
        self.assertFalse(tainted(x))
        i = some_input(x)
        self.assertTrue(tainted(i, v=XSS))
        self.assertTrue(tainted(i, v=SQLI))
        i = cleanSQLI(i)
        self.assertTrue(tainted(i, v=XSS))
        self.assertFalse(tainted(i, v=SQLI))

    def test_taint_vul2(self):
        '''If the givven vul argument is not a valid KEY,
        return False.'''
        x = 'taint_vul2'
        self.assertFalse(tainted(x))
        i = some_input(x)
        self.assertFalse(tainted(i, v=100))

class TestSink(unittest.TestCase):

    def test_false_all(self):
        n = some_input('test false all')
        self.assertFalse(saveDB1(n))
        self.assertFalse(saveDB2(n))
        self.assertFalse(saveDB3(n))

    def test_one(self):
        n = some_input('test one')
        n = cleanSQLI(n)
        self.assertFalse(saveDB1(n))
        self.assertTrue(saveDB2(n))
        self.assertFalse(saveDB3(n))

    def test_true_all(self):
        n = some_input('test true all')
        n = cleanSQLI(n)
        n = cleanXSS(n)
        n = cleanOSI(n)
        n = cleanII(n)
        self.assertTrue(saveDB1(n))
        self.assertTrue(saveDB2(n))
        self.assertTrue(saveDB3(n))

class TaintFunction(unittest.TestCase):

    def test_taint_values(self):
        a = "will be xss tainted"
        b = "will be sqli tainted"
        taint(a, XSS)
        taint(b, SQLI)
        self.assertTrue(tainted(a, v=XSS))
        self.assertTrue(tainted(a, v=XSS))

    def test_taint_values(self):
        a = "will be xss tainted"
        b = "will be sqli tainted"
        a = taint(a, XSS)
        b = taint(b, SQLI)
        self.assertTrue(tainted(a, v=XSS))
        self.assertTrue(tainted(a, v=XSS))

class TaintOperations(unittest.TestCase):

    def test_add_2taints(self):
        a = "will be xss tainted"
        b = "will be sqli tainted"
        a = taint(a, XSS)
        b = taint(b, SQLI)
        r = a + b
        self.assertTrue(tainted(r, v=XSS))
        self.assertTrue(tainted(r, v=SQLI))

    def test_radd_2taints(self):
        a = "will be xss tainted"
        b = "will be sqli tainted"
        a = taint(a, XSS)
        b = taint(b, SQLI)
        r = b + a
        self.assertTrue(tainted(r, v=XSS))
        self.assertTrue(tainted(r, v=SQLI))

    def test_mod_2taints(self):
        a = "will be xss tainted"
        b = "will be sqli tainted"
        a = taint(a, XSS)
        b = taint(b, SQLI)
        r = b + a
        self.assertTrue(tainted(r, v=XSS))
        self.assertTrue(tainted(r, v=SQLI))

    #MOD y falta MOD en testSTR
    #JOIN

class UnstrustedDecorator(unittest.TestCase):

    def test_untrusted_string(self):
        @untrusted
        def uf():
            return "untrusted"
        u = uf()
        self.assertTrue(tainted(u))

    def test_untrusted_dict(self):
        @untrusted
        def uf():
            return {0: "untrusted1", 1: "untrusted2"}
        u = uf()
        self.assertTrue(tainted(u[0]))
        self.assertTrue(isinstance(u[0], STR))
        self.assertTrue(tainted(u[1]))
        self.assertTrue(isinstance(u[1], STR))

    def test_untrusted_list(self):
        @untrusted
        def uf():
            return ["untrustedA", "untrustedB"]
        u = uf()
        self.assertTrue(tainted(u[0]))
        self.assertTrue(isinstance(u[0], STR))
        self.assertTrue(tainted(u[1]))
        self.assertTrue(isinstance(u[1], STR))

    def test_untrusted_dict_with_list(self):
        @untrusted
        def uf():
            return {0: "untrustedC", 1: ["untrustedD"]}
        u = uf()
        self.assertTrue(tainted(u[0]))
        self.assertTrue(isinstance(u[0], STR))
        self.assertTrue(tainted(u[1][0]))
        self.assertTrue(isinstance(u[1][0], STR))

    def test_untrusted_list_with_dict(self):
        @untrusted
        def uf():
            return ["unstrustedE", {0: "untrustedF"}]
        u = uf()
        self.assertTrue(tainted(u[0]))
        self.assertTrue(isinstance(u[0], STR))
        self.assertTrue(tainted(u[1][0]))
        self.assertTrue(isinstance(u[1][0], STR))

    def test_untrusted_twisted_structure(self):
        @untrusted
        def uf():
            return ["unstrustedG", {0: "untrustedH",
                                    1: ["untrustedI", "untrustedJ"]}]
        u = uf()
        self.assertTrue(tainted(u[0]))
        self.assertTrue(isinstance(u[0], STR))
        self.assertTrue(tainted(u[1][0]))
        self.assertTrue(isinstance(u[1][0], STR))
        self.assertTrue(tainted(u[1][1][0]))
        self.assertTrue(isinstance(u[1][0][0], STR))
        self.assertTrue(tainted(u[1][1][1]))
        self.assertTrue(isinstance(u[1][0][1], STR))

class CleanerDecorator(unittest.TestCase):

    def test_clener1(self):
        i = some_input('1')
        i = cleanOSI(i)
        #cleanOSI('1')
        self.assertFalse(OSI in i.taints)

@validator(XSS, nargs=[0])
def is_good(a):
    return True

class ValidatorDecorator(unittest.TestCase):

    def test_validator(self):
        i = some_input(1)
        is_good(i)
        self.assertFalse(XSS in i.taints)
        self.assertTrue(SQLI in i.taints)

if __name__ == '__main__':
    unittest.main()

