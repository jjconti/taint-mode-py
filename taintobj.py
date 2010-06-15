# Taint mode for objects EXPERIMENTO
from taintmode import taint, tainted, taint_class, attributes




if __name__ == '__main__':
    # if executed directly, run some tests
    import unittest

    a = taint('value1', 0)
    b = taint('value2', 1)
    c = taint('value3', 2)

    @taint_class
    class Dummy(object):

        def __init__(self, a, b, c):
            self.a = a
            self.other = b
            self.ccc = 3 * c

        def get(self):
            return self.a + self.ccc

        def get_with_arg(self, a):
            return self.a + self.ccc + a

        def set(self, x):
            self.a = x


    class TestTaintObjects(unittest.TestCase):

        def test_simple(self):
            '''
            A tainted object must have a taint field and must be tainted.
            '''

            d = Dummy(a, b, c)
            self.assertTrue(hasattr(d, 'taints'))
            self.assertTrue(tainted(d))

        def test_simple2(self):
            '''
            The taints in a tainted object are those of its initialization
            arguments. At least at the begginig.
            '''
            d = Dummy(a, a, a)
            self.assertEqual(d.taints, set([0]))

        def test_method(self):
            '''
            If a method recive a tainted argument, the result should
            have the object taints + the argument taints.
            '''
            d = Dummy(a, a, a)
            r = d.get_with_arg(b)
            self.assertTrue(tainted(r))
            self.assertEqual(r.taints, set([0, 1]))

        def test_setter(self):
            '''
            If a field is set, the new value taint should be consider.
            If it wasn't in the original object, it must be added and if the
            replaced value have a taint no more present, that taint should
            be removed from the object.
            '''
            d = Dummy(a, c, c)
            d.set(b)
            self.assertEqual(d.taints, set([1, 2]))

        def test_setter2(self):
            '''
            If a a field is set, the new value taint should be consider.
            If it wasn't in the original object, it must be and if the
            replaced value have a taint no more present, that taint should
            be removed from the object.

            But if the taint was present in another field, it shoudl be conseve.
            '''
            d = Dummy(a ,a, a)
            d.set(b)
            self.assertEqual(d.taints, set([0, 1]))

        def test_setter3(self):
            '''
            If the replaced field is not tainted, don't crash.
            '''
            d = Dummy(a, c, c)
            d.set("look ma, no taints")
            d.set("look ma, no taints")
            self.assertEqual(d.taints, set([2]))

    unittest.main()