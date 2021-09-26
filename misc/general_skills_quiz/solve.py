# /usr/bin/python3
import re, urllib.parse, base64, codecs
from pwn import *

HOST = "127.0.0.1"
PORT = 1337

def extract_q():
    print(r.recvuntil(":").decode('utf-8'))
    q = str(r.recvline().strip())
    q_extracted = "".join(re.findall("'([^']*)'", q))
    return q_extracted

def answer_send(ans, n):
    answer = ans
    print("[+] Answer " + str(n) +": " + answer)
    r.sendline(answer)

# Question 1 - Basic Maths
r = remote(HOST, PORT)
print(r.recvline().decode('utf-8'))
# Sending \n to progress
r.sendline()
print(r.recvline().decode('utf-8'))
print(r.recvline().decode('utf-8'))
answer_send("2", 1)

# Question 2 - Hex -> Base 10
answer_send(str(int(extract_q(), 0)), 2)

# Question 3 - Hex -> ASCII
answer_send(bytes.fromhex(extract_q()).decode('utf-8'), 3)

# Question 4 - URL Encoded -> ASCII Symbols
answer_send(urllib.parse.unquote(extract_q()), 4)

# Question 5 - Base64 -> ASCII
answer_send(base64.b64decode(extract_q()).decode('utf-8'), 5)

# Question 6 - ASCII -> Base64
answer_send(base64.b64encode(str.encode(extract_q())).decode('utf-8'), 6)

# Question 7 - ROT13 -> ASCII
answer_send(codecs.encode(extract_q(), 'rot_13'), 7)

# Question 8 - ASCII -> ROT13
answer_send(codecs.decode(extract_q(), 'rot_13'), 8)

# Question 9 - Binary -> Base 10
answer_send(str(int(extract_q(),2)), 9)

# Question 10 - Base10 -> Binary
answer_send(bin(int(extract_q())), 10)

# Question 11 - CTF Q
print(r.recvuntil("?"))
answer11 = "DUCTF"
print("[+] Answer 11: " + answer11)
r.sendline(answer11)
print(r.recvall().decode('utf-8'))