from pwn import remote, context
from sys import argv
import time

known = b""

context.timeout = None

threshold = 0.5

def guess():
    global known
    io = None
    attempts = 0
    guesses = []
    for i in range(256):
        c = bytes([i])
        print(known+c)
        if io is None:
            io = remote(argv[1], int(argv[2]))
        print(io.readuntil("(hex): "))
        attempts += 1
        start = time.time()
        io.sendline((known + c).hex())
        if b"Incorrect handshake" not in (line := io.recvline()):
            print(line)
            print(io.recvall())
            exit()
        end = time.time()
        if attempts >= 3:
            io.close()
            io = None
            attempts = 0
        if len(guesses) > 0:
            if end - start > guesses[-1][0] + threshold:
                return c
            elif end - start < guesses[-1][0] - threshold:
                return guesses[-1][1]
        else:
            guesses.append((end - start, c))


while len(known) < 5:
    known += guess()
    print(known)
