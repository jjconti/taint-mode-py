from dyntaint import *

class Do(object):
    
    def __init__(self, a, b):
        self.a = a
        self.b = b
        
d1 = Do('no manchado', 1)
m = taint('manchado')
d2 = Do(m, 2)
Do = ssink()(Do)
d3 = Do('no manchado', 1)
d4 = Do(m, 2)

