import flask
from flask_login import LoginManager, UserMixin, login_required, login_user, logout_user
from flask_session import Session
import datetime
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
        file = flask.request.files['file']
        # TODO: parse data and draw
        return file.read()

    return flask.render_template('upload.html')

@app.route('/chart')
@login_required
def chart():
    labels = ["January","February","March","April","May","June","July","August"]
    values = [10,9,8,7,6,4,7,8]
    return flask.render_template('chart.html', values=values, labels=labels)

@app.route("/logout")
@login_required
def logout():
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
