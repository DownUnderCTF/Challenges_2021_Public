from Crypto.PublicKey import ECC
from Crypto.Hash import SHA3_512
from Crypto.Signature import DSS
from Crypto.Util import asn1
import base64
import random

with open("app/secp256r1.key") as f:
    key = ECC.import_key(f.read())
    signer = DSS.new(key, 'fips-186-3', 'der')

prefix = "https://GOODCODE/update/"
urls = [prefix + random.randbytes(32).hex() for i in range(16)]

duplicate_indices = [random.randint(0, 15), random.randint(0, 15)]
while duplicate_indices[0] == duplicate_indices[1]:
    duplicate_indices = [random.randint(0, 15), random.randint(0, 15)]

urls = [
    (url, signer.sign(SHA3_512.new(url.encode())))
    if i not in duplicate_indices else
    (url,)
    for i, url in enumerate(urls)]

k = random.randbytes(256)
def fixed_rng(l):
    print(k[:l])
    return k[:l]

vulnerable_signer = DSS.new(key, 'fips-186-3', 'der', fixed_rng)

for i in duplicate_indices:
    url, = urls[i]
    urls[i] = (url, vulnerable_signer.sign(SHA3_512.new(url.encode())))

print(k)
print(duplicate_indices)
with open("app/update.log", "w") as f:
    for url, sig in urls:
        f.write(f"{url} {base64.b64encode(sig).decode()}\n")
