import ast
import unittest


try:
    next = next
except NameError:
    def next(x):
        return x.next()


class TestAST(unittest.TestCase):

    def test_parse(self):
        a = ast.parse('foo(1 + 1)')
        b = compile('foo(1 + 1)', '<unknown>', 'exec', ast.PyCF_ONLY_AST)
        self.assertEqual(ast.dump(a), ast.dump(b))

    def test_dump(self):
        node = ast.parse('spam(eggs, "and cheese")')
        self.assertEqual(ast.dump(node),
            "Module(body=[Expr(value=Call(func=Name(id='spam', ctx=Load()), "
            "args=[Name(id='eggs', ctx=Load()), Str(s='and cheese')], "
            "keywords=[], starargs=None, kwargs=None))])"
        )
        self.assertEqual(ast.dump(node, annotate_fields=False),
            "Module([Expr(Call(Name('spam', Load()), [Name('eggs', Load()), "
            "Str('and cheese')], [], None, None))])"
        )
        self.assertEqual(ast.dump(node, include_attributes=True),
            "Module(body=[Expr(value=Call(func=Name(id='spam', ctx=Load(), "
            "lineno=1, col_offset=0), args=[Name(id='eggs', ctx=Load(), "
            "lineno=1, col_offset=5), Str(s='and cheese', lineno=1, "
            "col_offset=11)], keywords=[], starargs=None, kwargs=None, "
            "lineno=1, col_offset=0), lineno=1, col_offset=0)])"
        )

    def test_copy_location(self):
        src = ast.parse('1 + 1', mode='eval')
        src.body.right = ast.copy_location(ast.Num(2), src.body.right)
        self.assertEqual(ast.dump(src, include_attributes=True),
            'Expression(body=BinOp(left=Num(n=1, lineno=1, col_offset=0), '
            'op=Add(), right=Num(n=2, lineno=1, col_offset=4), lineno=1, '
            'col_offset=0))'
        )

    def test_fix_missing_locations(self):
        src = ast.parse('write("spam")')
        src.body.append(ast.Expr(ast.Call(ast.Name('spam', ast.Load()),
                                          [ast.Str('eggs')], [], None, None)))
        self.assertEqual(src, ast.fix_missing_locations(src))
        self.assertEqual(ast.dump(src, include_attributes=True),
            "Module(body=[Expr(value=Call(func=Name(id='write', ctx=Load(), "
            "lineno=1, col_offset=0), args=[Str(s='spam', lineno=1, "
            "col_offset=6)], keywords=[], starargs=None, kwargs=None, "
            "lineno=1, col_offset=0), lineno=1, col_offset=0), "
            "Expr(value=Call(func=Name(id='spam', ctx=Load(), lineno=1, "
            "col_offset=0), args=[Str(s='eggs', lineno=1, col_offset=0)], "
            "keywords=[], starargs=None, kwargs=None, lineno=1, "
            "col_offset=0), lineno=1, col_offset=0)])"
        )

    def test_increment_lineno(self):
        src = ast.parse('1 + 1', mode='eval')
        self.assertEqual(ast.increment_lineno(src, n=3), src)
        self.assertEqual(ast.dump(src, include_attributes=True),
            'Expression(body=BinOp(left=Num(n=1, lineno=4, col_offset=0), '
            'op=Add(), right=Num(n=1, lineno=4, col_offset=4), lineno=4, '
            'col_offset=0))'
        )

    def test_get_fields(self):
        node = ast.parse('foo()', mode='eval')
        for d in ast.get_fields(node.body), dict(ast.iter_fields(node.body)):
            self.assertEqual(d.pop('func').id, 'foo')
            self.assertEqual(d, {'keywords': [], 'kwargs': None,
                                 'args': [], 'starargs': None})

    def test_get_child_nodes(self):
        node = ast.parse("spam(23, 42, eggs='leek')", mode='eval')
        self.assertEqual(len(ast.get_child_nodes(node.body)), 4)
        iterator = ast.iter_child_nodes(node.body)
        self.assertEqual(next(iterator).id, 'spam')
        self.assertEqual(next(iterator).n, 23)
        self.assertEqual(next(iterator).n, 42)
        self.assertEqual(ast.dump(next(iterator)),
            "keyword(arg='eggs', value=Str(s='leek'))"
        )

    def test_get_docstring(self):
        node = ast.parse('def foo():\n  """line one\n  line two"""')
        self.assertEqual(ast.get_docstring(node.body[0]),
                         'line one\nline two')

    def test_literal_eval(self):
        self.assertEqual(ast.literal_eval('[1, 2, 3]'), [1, 2, 3])
        self.assertEqual(ast.literal_eval('{"foo": 42}'), {"foo": 42})
        self.assertEqual(ast.literal_eval('(True, False, None)'), (True, False, None))
        self.assertRaises(ValueError, ast.literal_eval, 'foo()')


if __name__ == '__main__':
    unittest.main()
