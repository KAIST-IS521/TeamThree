import urllib
import urllib2
import gnupg
import os
import socket
import sys

# server keyid
KEYID='XXXXXXXXXXXXXXXX'
# client key information for authentication
GITHUB_ID='your-github-id'
PASSPHRASE='client-passphrase'

URL=''
SESSION=''

homegpgdir = os.environ['HOME'] + '/.gnupg'
try:
    gpg = gnupg.GPG(gnupghome=homegpgdir)
except TypeError:
    gpg = gnupg.GPG(homedir=homegpgdir)

def HTTP_send(url, headers=[], data=None):
    global SESSION
    req = urllib2.Request(URL + url, data=data)
    for header in headers:
        req.add_header(header[0], header[1])
    req.add_header('Cookie', SESSION)

    try:
        return urllib2.urlopen(req, timeout=3)
    except urllib2.URLError, e:
        # For Python 2.6
        if isinstance(e.reason, socket.timeout):
            exit(1)
        else:
            # reraise the original error
            exit(1)
    except socket.timeout, e:
        # For Python 2.7
        exit(1)
 
def session_test():
    global URL
    global SESSION
    SESSION = open('session').read().strip()
    req = urllib2.Request(URL + '/upload')
    req.add_header('Cookie', SESSION)
    try:
        resp = urllib2.urlopen(req, timeout=3)
    except urllib2.HTTPError, e:
        if isinstance(e.reason, socket.timeout):
            exit(1)
        else:
            resp = e
    except socket.timeout, e:
        exit(1)

    if resp.getcode() == 200:
        return True
    else:
        return False

def get_session():
    session = None
    resp = HTTP_send('/login')
    for header in resp.info().headers:
        if header.startswith("Set-Cookie: "):
            session = header[header.find(" ") + 1:].strip()

    return session

def solve_challenge(challenge):
    global KEYID
    global gpg
    dec = str(gpg.decrypt(challenge, passphrase=PASSPHRASE))
    random = dec.split('\n')[3]
    pubkeyAscii = gpg.export_keys(KEYID)
    pubkey = gpg.import_keys(pubkeyAscii)
    enc = str(gpg.encrypt(random, pubkey.fingerprints[0]))
    return enc

def fake_authentication():
    content = HTTP_send('/login', [], 'id=somethingwrongid').read()
    return content == 'No public key'

def authentication():
    global GITHUB_ID
    content = HTTP_send('/login', [], 'id=' + GITHUB_ID).read()
    #TODO: check no public key
    challenge = content[content.find('-----BEGIN PGP MESSAGE-----'):content.find('-----END PGP MESSAGE-----') + 25]
    solution = solve_challenge(challenge)
    data = urllib.urlencode({'challenge' : solution})
    content = HTTP_send('/auth', [], data).read()

def upload_log():
    headers = []
    headers.append(['Content-Type', 'multipart/form-data; boundary=----900435611877411605980745415'])

    file_data = '''430, 127.0.0.1,15,down
1430, 127.0.0.1,15,up
2450, 127.0.0.1,15,up
3330, 127.0.0.1,15,down'''

    data = '''------900435611877411605980745415
Content-Disposition: form-data; name="file"; filename="log"
Content-Type: application/octet-stream

''' + file_data + '''
------900435611877411605980745415--
'''
    return HTTP_send('/upload', headers, data).read()

def check(content, service, values):
    result = True
    idx = 0
    for value in values:
        idx = content.find('<desc class="value">', idx + 1)
        tmp = content[content.find('>', idx) + 1: content.find('</desc', idx)]
        if int(tmp) != value:
            result = False
            break
        idx += 1

    # TODO:need to check labels

    idx = content.find('<text x')
    tmp = content[content.find('>', idx) + 1:content.find('</text>', idx)].strip()
    if tmp != service:
        result = False

    return result

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print "Usage: python checker.py [IP] [PORT]"
        exit(0)
    URL = 'http://' + sys.argv[1] + ':' + sys.argv[2]

    if fake_authentication() == False:
        exit(1)

    #TODO: various SLA
    SESSION = get_session()
    if SESSION:
        authentication()
    else:
        exit(1)

    content = upload_log()
    result = check(content, "127.0.0.1:15", [0,1,1,0])
    if result == False:
        exit(1)
    #TODO: various SLA (ex NULL data)

    exit(0)
