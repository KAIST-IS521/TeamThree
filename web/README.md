# Web Visulizer
Web Visualizer that visualizing log file.

## Authentication Protocol
1. Insert github ID to get the challenge.
2. Web gives you the challenge, it encrypted and signed with users' public key and servers' private key.
3. Decrypt and Encrypt random number to authenticate.
 - Encrypt: gpg -da ./challenge | gpg -ear [server-pub-key]
4. Upload log file.

## config
Need to setup config file

Do not add comment on config file... :(
```bash
KEYID # pgp public key id of server
PASSPHRASE # pgp public key passphrase of server
```

## Usage
```
python web.py [PORT]
```
