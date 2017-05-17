import flask
from flask_login import LoginManager, UserMixin, login_required, login_user, logout_user
from flask_session import Session
import time
import random
import gnupg
import os

login_manager = LoginManager()
session_manager = Session()
app = flask.Flask(__name__, template_folder='templates')
homegpgdir = os.environ['HOME'] + '/.gnupg'
try:
    gpg = gnupg.GPG(gnupghome=homegpgdir)
except TypeError:
    gpg = gnupg.GPG(homedir=homegpgdir)

def MakeData(dataName, serviceName, dataList):
    data = '''
      var %(DATA)s = new google.visualization.DataTable();
      %(DATA)s.addColumn('timeofday', 'time');
      %(DATA)s.addColumn('number', '%(SERVICE)s');
      %(DATA)s.addRows([''' % {'DATA':dataName, 'SERVICE':serviceName}

    for item in dataList[:-1]:
        data += '[%s, %s], ' % (item[0], item[1])
    data += '[%s, %s] ]);\n' % (dataList[-1][0], dataList[-1][1])

    return data

def MakeJoinData(result, target1, target2, num):
    return "var %s = google.visualization.data.join(%s, %s, 'full', [[0, 0]], [%s], [1]);\n" %(result, target1, target2, ''.join(str(i + 1) + ',' for i in range(num-1)) + str(num))

def MakeGraphData(services):
    data = ''
    if len(services) == 1:
        data += makeData('data', services[0], services[services[0]])
    else:
        for idx, item in enumerate(services):
            data += MakeData('data' + str(idx), item, services[item])
        prev = 'data0'
        for idx in range(len(services) - 1):
            if idx == len(services) - 2:
                data += MakeJoinData('data', prev, 'data' + str(idx+1), idx+1)
            else:
                data += MakeJoinData('JD' + str(idx), prev, 'data' + str(idx+1), idx+1)
                prev = 'JD' + str(idx)

    return data

# index page
# login O - redirect to log upload page
# login X - redirect to login page
@app.route('/')
def index():
    login = flask.session.get('login', False)
    if login:
        return flask.redirect('/upload')
    else:
        return flask.redirect('/login')

# login page
# GET  - display login page(input ID box)
# POST - user submitted github ID
@app.route('/login', methods=['GET', 'POST'])
def login():
    if flask.request.method == 'POST':
        githubID = flask.request.form['id']
        keypath = './pub/' + githubID + '.pub'

        # check github ID by finding public key
        if not os.path.exists(keypath):
            return flask.Response('No public key')
        pubkey = gpg.import_keys(open(keypath).read())
        challenge = str(random.getrandbits(256))
        flask.session['id'] = githubID
        flask.session['challenge'] = challenge
        flask.session['encChallenge'] = str(gpg.encrypt(challenge, pubkey.fingerprints[0]))
        return flask.redirect('/auth')

    return flask.render_template('login.html')

@app.route('/auth', methods=['GET', 'POST'])
def auth():
    githubID = flask.session.get('id', False)
    challenge = flask.session.get('challenge', False)
    encChallenge = flask.session.get('encChallenge', False)

    if githubID == False or challenge == False or encChallenge == False:
        return flask.redirect('/login')

    # verify challenge
    if flask.request.method == 'POST':
        userChallenge = flask.request.form['challenge']
        # TODO: input correct passpghrase
        decrypt_data = gpg.decrypt(userChallenge, passphrase='server-pub-key-passphrase')
        if str(decrypt_data) == challenge:
            user = User(githubID, challenge)
            login_user(user)
            flask.session['login'] = True
            return flask.redirect('/upload')
        else:
            return 'auth fail'

    return flask.render_template('auth.html', challenge=encChallenge)

@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload_file():
    if flask.request.method == 'POST':
        # check if the post request has the file part
        if 'file' not in flask.request.files:
            flash('No file part')
            return flask.redirect(request.url)

        services = {}

        file = flask.request.files['file']
        for data in file.read().split('\n'):
            if data == '': continue
            items = data.split(',')
            HMS = time.strftime("[%H, %M, %S]", time.localtime(int(items[0])))
            service = items[1].strip() + ':' + items[2].strip()
            status = 1 if items[3].find('up') != -1 else 0
            if not services.has_key(service):
                services[service] = []
            services[service].append((HMS, status))
        data = MakeGraphData(services)
        return flask.render_template('chart.html', data=data)

    return flask.render_template('upload.html')

@app.route("/logout")
@login_required
def logout():
    # logout and delete session informations
    logout_user()
    del flask.session['id']
    del flask.session['challenge']
    del flask.session['login']
    return flask.redirect('/login')

@login_manager.user_loader
def load_user(userid):
    login = flask.session.get('login', False)
    if login:
        return User(userid, flask.session.get('challenge', False))
    else:
        return None

class User(UserMixin):
    def __init__(self, githubID, challenge):
        self.name = githubID
        self.password = challenge

    def get_id(self):
        return self.name

    def __repr__(self):
        return "%s/%s" % (self.name, self.password)

if __name__ == '__main__':
    app.secret_key = ''.join(chr(random.randrange(0, 256)) for i in range(32))
    app.config['SESSION_TYPE'] = 'filesystem'
    login_manager.init_app(app)
    session_manager.init_app(app)
    app.run(host='0.0.0.0', port=80)
