from pwn import *
from parse import parse

conn = remote('0.0.0.0', 1337)

# check 1
X = b'DUCTF'
S = b'\x02\x01\x01\x01\x89'
z1 = sum(s*(i+1) for i, s in enumerate(S)) % 256

assert sum([x^s for x, s in zip(X ,S)]) % 256 == 0
assert z1 % 2**3 == 0

conn.sendlineafter(': ', S)

# check 2
r1 = parse('Solve this: x + y = {:d}\n', conn.recvline().decode())[0]
for v in range(16):
    if r1 % 2**(v+1) != 0:
        break
k = 15 - v
x = r1 + 2**k
y = 2**32 - 2**k
z2 = (x*y) & 0xffff
assert z2 == 2**15

conn.sendline(f'{x} {y}')

# check 3
r2 = parse('Now solve this: x1 + x2 + x3 + x4 + x5 = {:d}\n', conn.recvline().decode())[0]
x1 = 2 - (r2 & 1)
x2 = 3
x3 = 2**7 + x2
x4 = (r2 - x1 - 2*x2 - 2**7 - 2**8)//2
x5 = 2**8 + x4
z3 = (x3 - x2)*(x5 - x4) % 2**16

assert x1 + x2 + x3 + x4 + x5 == r2
assert z3 % 2**14 == 0

conn.sendline(f'{x1} {x2} {x3} {x4} {x5}')

assert z1*z2*z3 % 2**32 == 0

print(conn.recvline().decode())
print(conn.recvline().decode())
print(conn.recvline().decode())
