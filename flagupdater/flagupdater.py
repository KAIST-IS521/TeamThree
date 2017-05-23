import gnupg
import base64
import json
import os
from tempfile import NamedTemporaryFile

mkStream = gnupg._util._make_binary_stream
if __debug__:
    FLAG_PATH = './sla.flag'
    TT_KEY_PATH = './TTprivate.key'
    TA_DIR_PATH = './TAKey'
else:
    FLAG_PATH = '/var/www/sla.flag'
    TEAM_PATH = None
    TA_PATH   = None
    #TODO: Specify key_paths

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
        f_data = mkStream('{}:{}'.format(signer, newflag))

        f_sign = NamedTemporaryFile(delete = False)
        tmpFileName = f_sign.name
        f_sign.write(sign)
        f_sign.close()

        result = self.gpg.verify_file(f_data, tmpFileName,
                                      key_id = self.sigMap[signer])

        f_data.close()
        os.remove(tmpFileName)

        return result

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
