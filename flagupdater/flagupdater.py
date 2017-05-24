import gnupg
import base64
import json
import os
import daemon
from tempfile import NamedTemporaryFile
from SocketServer import ThreadingTCPServer, StreamRequestHandler

if __debug__:
    FLAG_PATH = './sla.flag'
    TT_KEY_PATH = './TTprivate.key'
    TT_PAP_PATH = './TTprivate.pass'
    TA_DIR_PATH = './TAkey'
    ADDR, PORT = '', 4242
else:
    #TODO: Specify values after server configure done
    FLAG_PATH = '/var/www/sla.flag'
    TT_KEY_PATH = None
    TT_PAP_PATH = None
    TA_DIR_PATH = None
    ADDR, PORT = '', 42

class FlagUpdater:
    def __init__(self, selfKey, passphrase, peerKeys = dict()):
        self.gpg = gnupg.GPG()
        self.passphrase = passphrase
        self.sigMap = dict()

        with open(selfKey, 'rb') as f:
            self.gpg.import_keys(f.read())

        for peer, keyfile in peerKeys.items():
            with open(keyfile, 'rb') as f:
                key = self.gpg.import_keys(f.read())
                self.sigMap[peer] = key.fingerprints

    def _verify(self, signer, newflag, sign):
        if not signer in self.sigMap:
            return False

        data = '{}:{}'.format(signer, newflag)

        f_sign = NamedTemporaryFile(delete = False)
        tmpFileName = f_sign.name
        f_sign.write(sign)
        f_sign.close()

        result = self.gpg.verify_data(tmpFileName, data)

        f_data.close()
        os.remove(tmpFileName)

        if result is None:
            return False

        return result.fingerprint in self.sigMap[signer]

    def handle_update_request(self, req):
        req = self.gpg.decrypt(req, always_trust = True,
                               passphrase = self.passphrase)
        dic = json.loads(req)

        signer = dic['signer']
        newflag = dic['newflag']
        sign = base64.b64decode(dic['signature'])

        if self._verify(signer, newflag, sign):
            with open(FLAG_PATH, 'wb') as f:
                f.write(newflag)

class myFlagUpdateHandler(StreamRequestHandler):
    def handle(self):
        req = self.rfile.readline()
        UPDATER.handle_update_request(req)

if __name__ == '__main__':
    TA_list = ['DaramG', 'jchoi2022', 'soomin-kim']
    peerKeys = dict()
    for name in TA_list:
        peerKeys[name] = '{}/{}.pub'.format(TA_DIR_PATH, name)

    with open(TT_PAP_PATH, 'rb') as f:
        passphrase = f.read()

    UPDATER = FlagUpdater(TT_KEY_PATH, passphrase, peerKeys)
    ThreadingTCPServer.allow_reuse_address = True

    with daemon.DaemonContext():
        server = ThreadingTCPServer((ADDR, PORT), myFlagUpdateHandler)
        server.serve_forever()
