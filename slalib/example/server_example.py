import gnupg
import os
import sys
import time
from SocketServer import ThreadingTCPServer, BaseRequestHandler
from config import signerFpr, passphrase

def DEBUG(data):
    if __debug__:
        print data
    else:
        pass

class myTCPHandler(BaseRequestHandler):
    def readSome(self):
        data = self.request.recv(4096)
        while len(data) == 0:
            data = self.request.recv(4096)
            time.sleep(0.5)
        return data

    def handle(self):
        gpg = gnupg.GPG()

        githubID = self.readSome()
        DEBUG(githubID)

        keyPath = './pub/{}.pub'.format(githubID)

        if not os.path.exists(keyPath):
            DEBUG('Invalid id: %s' % keyPath)
            exit()

        with open(keyPath, 'rb') as f:
            key = gpg.import_keys(f.read())

        rndm = os.urandom(128)
        chal = gpg.encrypt(rndm, key.fingerprints[0],
                           sign = signerFpr, passphrase = passphrase,
                           always_trust = True)

        self.request.sendall(chal.data)

        data = self.readSome()
        data = gpg.decrypt(data, passphrase = passphrase, always_trust = True).data
        if data == rndm:
            self.request.sendall('success')
        else:
            self.request.sendall('failure')

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print 'Usage: {} [port]'.format(sys.argv[0])
        exit()
    else:
        ADDR, PORT = '0', int(sys.argv[1])

    ThreadingTCPServer.allow_reuse_address = True
    server = ThreadingTCPServer((ADDR, PORT), myTCPHandler)
    server.serve_forever()
