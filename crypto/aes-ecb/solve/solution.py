#!/usr/bin/python3

from Crypto.Cipher import AES
from pwn import *
from base64 import b64decode

if len(sys.argv) != 3:
    print("usage: ./solution.py IP PORT")
    exit()

def get_block(s,n):
    start = 16 * (n-1)
    end = start + 16
    r = b.decode("utf-8")
    return b64decode(r)[start:end]

# this will grow as each byte of the key is revealed
key = b""


s = remote(sys.argv[1], sys.argv[2])
s.recvline()

# each byte position in the block (16)
for i in range(16, 0, -1):
    partial = b"A"*(i-1)
    s.recvline()
    s.sendline(partial)
    b = s.recvline()
    target = get_block(b, 3)

    # each possible ascii byte value for that position
    for j in range(33, 127):
        k = bytes([j])
        s.recvline()
        s.sendline(partial + key + k)
        b = s.recvline()
        res = get_block(b, 3)

        # compare with padded output
        if res == target:
            key += k
            break

print("found key:", key)
cipher = AES.new(key, AES.MODE_ECB)
s.sendline()
s.recvline()
b = s.recvline()
ct = get_block(b,1) + get_block(b,2)
flag = cipher.decrypt(ct)
print(flag.decode("utf-8"))
s.close()
