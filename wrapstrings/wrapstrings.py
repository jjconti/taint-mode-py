import ast

def myfunc(a):
    return a


class RewriteMod(ast.NodeTransformer):

    def visit_BinOp(self, node):
        '''
        Mod es un operador binario.
        Una instancia de BinOp tiene atributos left, op y right.
        Si node.op es instancia de Mod y node.left es instancia de Str,
        tomar node.left y cambiarlo por una llamada a funcion.
        '''
        if isinstance(node.op, ast.Mod) and isinstance(node.left, ast.Str):
                node.left = ast.Call(func=ast.Name(id="myFunc"), args=[node.left])
                return node
        return node

a = ast.parse(open('ejemplo.py').read())

RewriteMod().visit(a)

import codegen
print codegen.to_source(a)

