'''
Author: Juan Jose Conti <jjconti@gmail.com>

This module can parse Python files looking for uses of the % operator.
The % operator is mainly used for string formatting operations.

Use:

    python wrapstrings.py file.py funcName
    
'''
import ast

class RewriteMod(ast.NodeTransformer):

    def visit_BinOp(self, node):
        '''
        Mod es un operador binario.
        Una instancia de BinOp tiene atributos left, op y right.
        Si node.op es instancia de Mod y node.left es instancia de Str,
        tomar node.left y cambiarlo por una llamada a funcion.
        '''
        if isinstance(node.op, ast.Mod) and (changeall or isinstance(node.left, ast.Str)):
                node.left = ast.Call(func=ast.Name(id=funcname), args=[node.left])
                return node
        return node


if __name__ == '__main__':
    import sys
    filename = sys.argv[1]
    funcname = sys.argv[2]
    if len(sys.argv) > 3:
        changeall = True
    else:
        changeall = False
        
    a = ast.parse(open(filename).read())
    
    RewriteMod().visit(a)

    import codegen
    print codegen.to_source(a)

