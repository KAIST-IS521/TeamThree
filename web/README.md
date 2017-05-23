# Web Visulizer
Web Visualizer that visualizing log file.

## Authentication Protocol
1. Insert github ID to get challenge
2. If you can get the challenge, then decrypt it using gpg command
 - Verify: gpg -da ./challenge | gpg --verify
 - Decrypt: gpg -da ./challenge
 - Encrypt: gpg -da ./challenge | gpg -ear [server-pub-key]
3. upload log file

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
