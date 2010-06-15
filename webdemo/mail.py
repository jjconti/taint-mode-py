import smtplib
import sys


fromaddr = 'system@system.ar'
subject = sys.argv[2]
toaddr = sys.argv[3]
msg = ''

while 1:
    try:
        line = raw_input()
    except EOFError:
        break
    if not line:
        break
    msg = msg + line

server = smtplib.SMTP('localhost')
#server.set_debuglevel(1)
server.sendmail(fromaddr, toaddr, msg)
server.quit()

