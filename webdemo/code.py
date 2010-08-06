import web
import view
from view import render
import os
from datetime import datetime

from taintmode import *
web.input = untrusted(web.input)
os.system = ssink(OSI)(os.system)
import taintmode
taintmode.ends_execution()

from cleaners import clean_osi
clean_osi = cleaner(OSI)(clean_osi)

urls = (
    '/', 'index',
    '/add', 'add',
    '/clean', 'clean'
)

class index:
    def GET(self):
        return render.base(view.listing())

class clean:
    def POST(self):
        dayfile = datetime.today().strftime('%Y-%m-%d') + '.txt'
        os.system("rm " + dayfile)
        raise web.seeother('/')
        
class add:
    def POST(self):
        user = web.input().user
        meal = clean_osi(web.input().meal)
        # save it to the file of the day
        dayfile = datetime.today().strftime('%Y-%m-%d') + '.txt'
        os.system("echo " + meal + " >> " + dayfile)
        raise web.seeother('/')

if __name__ == "__main__":
    app = web.application(urls, globals())
    app.internalerror = web.debugerror
    app.run()
