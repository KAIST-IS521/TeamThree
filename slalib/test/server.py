import time
import random
import gnupg
import socket
import os
import sys

homegpgdir = os.environ['HOME'] + '/.gnupg'
try:
    gpg = gnupg.GPG(gnupghome=homegpgdir)
except TypeError:
    gpg = gnupg.GPG(homedir=homegpgdir)

####################################################
# Add information of server PGP key in config file #
####################################################
KEYID='' # first line of config file
PASSPHRASE='' # second line of config file

'''
@app.route('/login', methods=['GET', 'POST'])
def login():
    if flask.request.method == 'POST':
        global KEYID
        global PASSPHRASE
        githubID = flask.request.form['id']
        keypath = './pub/' + githubID + '.pub'

        # check github ID by finding public key
        if not os.path.exists(keypath):
            return flask.Response('No public key')
        pubkey = gpg.import_keys(open(keypath).read())
        challenge = str(random.getrandbits(256))
        flask.session['id'] = githubID
        flask.session['challenge'] = challenge
        try:
            challenge = str(gpg.sign(challenge, keyid=KEYID, passphrase=PASSPHRASE))
        except:
            challenge = str(gpg.sign(challenge, default_key=KEYID, passphrase=PASSPHRASE))
        challenge = str(gpg.encrypt(challenge, pubkey.fingerprints[0]))
        flask.session['encChallenge'] = challenge
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
        global PASSPHRASE
        userChallenge = flask.request.form['challenge']
        decrypt_data = gpg.decrypt(userChallenge, passphrase=PASSPHRASE)
        if str(decrypt_data).strip() == challenge:
            user = User(githubID, challenge)
            login_user(user)
            flask.session['login'] = True
            return flask.redirect('/upload')
        else:
            return 'auth fail'

    return flask.render_template('auth.html', challenge=encChallenge)
'''

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print 'Usage: python web.py [PORT]'
        exit(1)
    lines=open('config').read().split('\n')
    KEYID = lines[0].strip()
    PASSPHRASE = lines[1].strip()
    PORT = int(sys.argv[1])

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    print 'Socket created'

    #Bind socket to local host and port
    try:
        s.bind(("127.0.0.1", PORT))
    except socket.error as msg:
        print 'Bind failed. Error Code : ' + str(msg[0]) + ' Message ' + msg[1]
        sys.exit()

    print 'Socket bind complete'

    #Start listening on socket
    s.listen(10)
    print 'Socket now listening'

    #now keep talking with the client
    while 1:
        #wait to accept a connection - blocking call
        conn, addr = s.accept()
        print 'Connected with ' + addr[0] + ':' + str(addr[1])
        githubID = conn.recv(1024)
        keypath = './pub/' + githubID + '.pub'

        if not os.path.exists(keypath):
            print 'No public key'
            sys.exit()

        pubkey = gpg.import_keys(open(keypath).read())
        random_number = str(random.getrandbits(256))
        print "random_number"
        print random_number

        try:
            challenge = str(gpg.sign(random_number, keyid=KEYID, passphrase=PASSPHRASE))
        except:
            challenge = str(gpg.sign(random_number, default_key=KEYID, passphrase=PASSPHRASE))
        challenge = str(gpg.encrypt(challenge, pubkey.fingerprints[0]))

        print "make challenge!"
        print challenge

        conn.send(challenge)
        time.sleep(0.1)
        userChallenge = conn.recv(1024)
        print "userChallenge"
        print userChallenge
        decrypt_data = str(gpg.decrypt(userChallenge, passphrase=PASSPHRASE))
        print "decrypt_data"
        print decrypt_data
        if decrypt_data == random_number:
            print "Success!"
            conn.send("Success")
        else:
            print "Fail!"
            conn.send("Fail")

        conn.close()

    s.close()
