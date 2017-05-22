import gnupg
import base64
import json
import os
import socket

def init():
    global gpg
    gpg = gnupg.GPG()
    with open("./Teamkey/IS521_TT.pub", "r") as f:
        gpg.import_keys(f.read())
        print("Import Team key") 
    with open("./TAkey/DaramG.pub", "r") as f:
        gpg.import_keys(f.read())
        print("Import TA key") 

def Dec(data):
    pt = gpg.decrypt(data, passphrase = " ",  always_trust=True)
    print("decrypted")
    return str(pt)

def Verify(data):
    #Todo
    gpg.verify(data)

def Flag(data):
    #flagdata = Dec(data)
    flagdata = data
    json_data = json.loads(flagdata)
    newdata = json_data['signer']+":"+json_data['newflag']
    verified = Verify(data)
    if verified:
	print("Verified\n")
    else:
	print("Error: Not Verified\n")
	return False
# save flag
    

if __name__ == "__main__":
    init()
    #sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    #sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    #sock.bind(('0.0.0.0', 42))
    #sock.listen(5)
    #sock, client = sock.accept()
    #data = sock.recv(1)
    with open("./flag/message.txt", "r") as f:
        data = f.read()
        print("Read flag message") 
    Flag(data)
    #sock.close()

