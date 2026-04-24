#!/usr/bin/env python3
# This script is a ChatGPT based port of https://github.com/dkolasinski/aruba-instant-on-1930-backup-script.
# The Perl version did not work with a recent OpenSSL version as OpenSSL no longer supports PKCS#1 v1.5 RSA padding due to the
# Marvin attack. This port requires pycryptodome which does not rely on OpenSSL.
# Credits to @dkolasinski!

import sys
import re
import requests
import urllib.parse
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5

# Disable TLS warnings 
requests.packages.urllib3.disable_warnings()

# --- INPUT ---
if len(sys.argv) != 5:
    print(f"Usage: {sys.argv[0]} <ip/hostname> <user> <pass> <output filename>")
    sys.exit(1)

host = sys.argv[1]
username = sys.argv[2]
password = sys.argv[3]
filename = sys.argv[4]

if not re.match(r'^[0-9a-zA-Z\.\-]+$', host):
    print("IP/Hostname - input does not match pattern!")
    sys.exit(1)

session = requests.Session()
session.verify = False  # disable TLS validation

# Set cookies
session.cookies.set('activeLangId', 'english')
session.cookies.set('sessionID', '')
session.cookies.set('userName', '')
session.cookies.set('firstWelcomeBanner', 'true')
session.cookies.set('LogOff_Reason', 'Manual')

# ----------- 1 - REQ - get document root
resp = session.get(f"https://{host}", allow_redirects=False)

if resp.is_redirect:
    initial_location = resp.headers.get("Location", "")
    match = re.match(r'^/([^/]+)', initial_location)
    if match:
        document_root = match.group(1)
        print("req 1. LOCATION REQ OK")
    else:
        print("req 1. Cannot parse Location:", initial_location)
        sys.exit(1)
else:
    print("req 1. Expected redirect, got:", resp.status_code)
    sys.exit(1)

# ----------- 2 - REQ - get login page
resp = session.get(f"https://{host}{initial_location}")

if resp.ok:
    content = resp.text
    if "inputUsername" in content:
        print("req 2. INITIAL REQ OK: ARUBA INSTANT ON DETECTED")
    elif "UserCntrl" in content:
        print("req 2. INITIAL REQ OK: CISCO CBS DETECTED")
    else:
        print("req 2. LOGIN FIELD NOT FOUND")
        sys.exit(1)
else:
    print("req 2. ERROR:", resp.status_code)
    sys.exit(1)

# ----------- 3 - REQ - encryption settings
resp = session.get(
    f"https://{host}/device/wcd?{{EncryptionSetting}}",
    headers={"Accept": "application/xml, text/xml"}
)

if not resp.ok:
    print("req 3. ERROR:", resp.status_code)
    sys.exit(1)

content = resp.text

def extract(tag):
    m = re.search(f"<{tag}>(.+?)</{tag}>", content, re.S)
    return m.group(1) if m else None

rsa_public_key = extract("rsaPublicKey")
login_token = extract("loginToken")
passw_encrypt_enable = extract("passwEncryptEnable")

if not rsa_public_key:
    print("req 3. No RSA key found")
    sys.exit(1)
print("req 3. RSA KEY OK")

if not login_token:
    print("req 3. No login token found")
    sys.exit(1)
print("req 3. LOGIN TOKEN OK")

if not passw_encrypt_enable:
    print("req 3. No passwEncryptEnable found")
    sys.exit(1)
print("req 3. ENCRYPT FLAG OK")

# ----------- 4 - REQ - login
login_string = (
    "user=" + urllib.parse.quote(username) +
    "&password=" + urllib.parse.quote(password) +
    "&ssd=true" +
    "&token=" + login_token +
    "&"
)

if passw_encrypt_enable == "1":
    rsa_key = RSA.import_key(rsa_public_key)
    cipher = PKCS1_v1_5.new(rsa_key)
    encrypted = cipher.encrypt(login_string.encode())
    hex_encrypted = encrypted.hex()
else:
    hex_encrypted = login_string

resp = session.get(
    f"https://{host}/{document_root}/hpe/config/system.xml",
    params={
        "action": "login",
        "cred": hex_encrypted
    }
)

if not resp.ok:
    print("req 4. LOGIN REQUEST ERROR:", resp.status_code)
    sys.exit(1)

m = re.search(r"<statusString>(.+?)</statusString>", resp.text, re.S)
status = m.group(1) if m else ""

if status != "OK":
    print("req 4. LOGIN FAILED:", status)
    sys.exit(1)

print("req 4. LOGIN OK")

# ----------- 5 - REQ - download config
resp = session.get(
    f"https://{host}/{document_root}/hpe/http_download",
    params={
        "action": "3",
        "ssd": "4"
    }
)

if not resp.ok:
    print("req 5. DOWNLOAD ERROR:", resp.status_code)
    sys.exit(1)

with open(filename, "wb") as f:
    f.write(resp.content)

print("req 5. DOWNLOAD OK")
print("END OF SCRIPT")
