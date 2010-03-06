from twisted.protocols.basic import LineOnlyReceiver
from twisted.internet.protocol import Factory
from twisted.internet import reactor

import os

from dyntaint import *

@cleaner(OSI)   # this function cleans from Operative System Injection
def clean_command(cmd):
    if ';' in cmd:
        return ''
    if 'kill' in cmd:
        return ''        
    if cmd.startswith('ls'):
        return cmd
    return ''
            
class Command(LineOnlyReceiver):

    @untrusted_params([1])
    def lineReceived(self, line):
        print "from client:", line
        l = clean_command(line)
        self.ejecutar(l)
        
    @ssink(OSI)
    def ejecutar(self, line):
        os.system(line)
        
class CommandFactory(Factory):
    protocol = Command             
        

factory = CommandFactory()
reactor.listenTCP(3333, factory)

reactor.run()
