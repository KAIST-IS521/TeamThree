import flask
from flask_login import LoginManager, UserMixin, login_required, login_user, logout_user
from flask_session import Session
import datetime
import random

login_manager = LoginManager()
session_manager = Session()
app = flask.Flask(__name__, template_folder='templates')

@app.route('/')
def index():
    login = flask.session.get('login', False)
    if login:
        return flask.redirect('/upload')
    else:
        return flask.redirect('/login')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if flask.request.method == 'POST':
        githubID = flask.request.form['id']
        # TODO: check valid id(finding correspond pub-key)
        flask.session['id'] = githubID
        challenge = 1
        for i in range(128):
            challenge *= random.randrange(1, 10)
        flask.session['challenge'] = challenge
        # TODO: encrypt with pub-key
        flask.session['encChallenge'] = 'something base64'#encChallenge
        return flask.redirect('/auth')

    return flask.Response('''
    <form action="" method="post">
        ID : <input type=text name=id>
        <p><input type=submit value="Get Challenge">
    </form>
    ''')

@app.route('/auth', methods=['GET', 'POST'])
def auth():
    githubID = flask.session.get('id', False)
    challenge = flask.session.get('challenge', False)
    encChallenge = flask.session.get('encChallenge', False)

    if githubID == False or challenge == False or encChallenge == False:
        return flask.redirect('/login')

    if flask.request.method == 'POST':
        userChallenge = flask.request.form['challenge']
        # TODO: decrypt challenge with server privkey and check
        user = User(githubID, challenge)
        login_user(user)
        flask.session['login'] = True
        return flask.redirect('/upload')

    return flask.Response('''
    ID : ''' + githubID + '''
    <p>Challenge : ''' + encChallenge + '''
    <p>decrypt your <b>pri-key</b> and encrypt it with server <b>pub-key</b>
    <form action="" method="post">
        <p><input type=text name=challenge>
        <p><input type=submit value="Auth">
    </form>
    ''')

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
    print userid
    # TODO: need to login check. not userid, challenge
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
