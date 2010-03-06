from dyntaint import *

# Mark unstrusted sources
# raw_input = untrusted(raw_input)

@untrusted
def obtener_numero(mensaje="Ingrese un numero: "):
    n = raw_input(mensaje)
    return n

@cleaner(SQLI)
def limpiarSQLi(s):
    '''lo limpie, creeme.'''
    return s

@ssink(SQLI)
def guardarDB(valor):
    print "Guardando en la BD:", valor

if __name__ == '__main__':
    n = obtener_numero()
    guardarDB(limpiarSQLi(n + "jeje"))
    guardarDB(limpiarSQLi("jeje" + n))
