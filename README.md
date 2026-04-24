This is ChatGPT based port of https://github.com/dkolasinski/aruba-instant-on-1930-backup-script. 
I made the port as the Perl version in its current form does not work with modern OpenSSL builds when the configuration is encrypted.

Credits to dkolasinski!

# Usage
```$ git clone https://github.com/cddmp/aruba-instant-on-1930-backup
$ cd aruba-instant-on-1930-backup
$ python3 -m venv .venv
$ source .venv/bin/activate
$ pip install -r requirements.txt
$ python3 ./ofi-1930-get-backup.py```
