from dyntaint import *

# Mark unstrusted sources

@untrusted
def obtener_numero(mensaje="Ingrese un numero: "):
    n = raw_input(mensaje)
    return n

@cleaner(SQLI)
def limpiarSQLi(s):
    '''lo limpie, creeme.'''
    return s

@ssinc(SQLI)
def guardarDB(valor):
    print "Guardando en la BD:", valor

@ssinc(XSS)
def mostrarPagina(valor):
    print '<html>%s</html>' % (valor,)

@ssink()
def sensible(valor):
    print valor

if __name__ == '__main__':
    import re
    n = obtener_numero()
    # n esta manchada
    guardarDB(n)
    a, b, c = re.findall( '(.*?),(.*?),(.*?)', n )[0]
    # a, b y c estan manchadas
    sensible(a)
    sensible(b)
    sensible(c)
