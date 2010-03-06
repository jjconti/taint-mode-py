from dyntaint import *


@ssink()
def execute(cmd):
     print "Executing:", cmd 
     # Here, it will go an eval cmd or something like that


def conv(s):
  r = ''
  for a in range(0, len(s)):
     r+= chr(ord(s[a]))
  return r

def inject(s): 
    no_tainted = 'null_command ;' # null command can be anything like echo ''
    no_tainted+= conv(s)
    execute(no_tainted) 
    
inject(taint('attack_command')) # where attack command can be rm -r * or things
                                # things like that.

