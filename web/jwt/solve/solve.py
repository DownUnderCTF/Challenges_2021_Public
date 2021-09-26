# solve script written by joseph

import requests
from hashlib import sha256
from base64 import urlsafe_b64decode
from Crypto.PublicKey import RSA
from Crypto.Util.number import bytes_to_long, long_to_bytes
import gmpy2

def pkcs1_v1_5_encode(msg: bytes, n_len: int):
    SHA256_Digest_Info = b'\x30\x31\x30\x0D\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01\x05\x00\x04\x20'
    T = SHA256_Digest_Info + sha256(msg).digest()
    PS = b'\xFF' * (n_len - len(T) - 3)
    return b'\x00\x01' + PS + b'\x00' + T

# from https://ctftime.org/writeup/26173
def get_magic(jwt):
    header, payload, signature = jwt.split(".")

    raw_signature = urlsafe_b64decode(f"{signature}==")
    raw_signature_int = gmpy2.mpz(bytes_to_long(raw_signature))

    padded_msg = pkcs1_v1_5_encode(f"{header}.{payload}".encode(), len(raw_signature))
    padded_int = gmpy2.mpz(bytes_to_long(padded_msg))

    e = gmpy2.mpz(65537)
    return gmpy2.mpz(pow(raw_signature_int, e) - padded_int)

jwt0 = requests.get('http://0.0.0.0:1337/get_token').text
jwt1 = requests.get('http://0.0.0.0:1337/get_token').text
# jwt0 = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJhZG1pbiI6ZmFsc2UsIm5vdyI6MTYzMDk4MTgwOS4xNjQzMDF9.BV5n_9LpciesgBgO8wy7owjMIQoFj5OPP1vsN-S_V47rZFnSrDYDooxeIT6f9369tC2-NOpusU_6Xfyh_TLTdiIZU9LeS-KNZlENsj2F5St6A6jXgdfq0aS27ltMHRSwVA'
# jwt1 = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJhZG1pbiI6ZmFsc2UsIm5vdyI6MTYzMDk4MTgxOC45OTIzNzl9.CwYmWPSd4T8NHzi8YcfuCUTMHU4jwkFvzqPSzJnp3ItBmeu_bXDSB5_qng9lO80bQp-l7JFHgHwo9VYKac4xy9m9PGFq3NPJfpjLO59mkyMsNW5-uhVkRyh-rkQWma-sHA'
magic0 = get_magic(jwt0)
magic1 = get_magic(jwt1)

N = int(gmpy2.gcd(magic0, magic1))
print(hex(N))

assert N % 29 == 0
p = 29
q = N//p
e = 0x10001
d = pow(e, -1, (p-1)*(q-1))

# generate private key
key = RSA.construct((N, e, d))
PRIV_KEY = key.exportKey().decode()
print(PRIV_KEY)

import jwt
token = jwt.encode({'admin': True}, PRIV_KEY, algorithm='RS256')
print(token)

flag = requests.post('http://0.0.0.0:1337/get_flag', data={ 'jwt': token })
print(flag.text)
