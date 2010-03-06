from dyntaint import *

@ssink(OSI)
def execute(cmd):
     print "Executing:", cmd 
     # Here, it will go an eval cmd or something like that

def f(character): 
  for a in range(65,123): # range from A to z
    if ord(character) == a: return chr(a)  # chr no mantiene la mancha.

def conv(s):
  r = ''
  for a in range(0, len(s)):    
    r+=(f(s[a]))
  return r

def inject(s): 
    no_tainted = 'null_command ;' # null command can be anything like echo ''
    no_tainted+= s#conv(s)
    execute(no_tainted) 

    

inject(taint('attack_command')) # where attack command can be rm -r * or things
                                # things like that.
