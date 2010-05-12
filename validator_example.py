'''
The idea of this tests is to show that the 3rd limitation pointed at
http://andrewpetukhov.blogspot.com/2010/04/limitations-of-taint-propagation.html
can be overcame using taintmode.py validator decorator.
'''

from taintmode import *

@untrusted
def data_from_outside(msg="Insert data: "):
    return raw_input(msg)
    
@ssink(XSS)
def my_sink(data):
    print "Reached a ssink", data
    
@validator(XSS, True, [0])
def is_digit(n):
    if len(n) != 1:
        return False
    return n in "0123456789"

@validator(XSS, False, [0])
def is_not_digit(n):
    if len(n) != 1:
        return True
    return n not in "0123456789"

if __name__ == '__main__':
    
    data = data_from_outside()
    
    if is_digit(data):
        my_sink(data)
    else:
        print "Cant use provided data"
        
    if is_not_digit(data):
        print "Cant use provided data"
    else:
        my_sink(data)