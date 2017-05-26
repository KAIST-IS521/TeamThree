# Web Visulizer
Web Visualizer that visualizing log file.

## Authentication Protocol
1. Insert github ID to get the challenge.
2. Web gives you the challenge, it encrypted with users' public key.
 - Decrypt: gpg -da ./challenge
3. Decrypt challenge, and verify sign.
 - Verify: gpg -da ./challenge | gpg --verify
4. Encrypt random number and authenticate.
 - Encrypt: echo [random_number] | gpg -ear [server-pub-key]
5. Upload log file.

## config
Need to setup config file

Do not add comment on config file... :(
```bash
KEYID # pgp key id of server
PASSPHRASE # pgp key passphrase of server
```

## Usage
```
python web.py [PORT]
```
