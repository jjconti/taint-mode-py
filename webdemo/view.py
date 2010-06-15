import web
from datetime import datetime

t_globals = dict(
  datestr=web.datestr,
)
render = web.template.render('templates/', globals=t_globals)
render._keywords['globals']['render'] = render

def listing():
    dayfile = datetime.today().strftime('%Y-%m-%d') + '.txt'
    try:
        f = open(dayfile)
        l = f.readlines()
        f.close()
    except:
        l = []  # no file yet
    return render.listing(l)
