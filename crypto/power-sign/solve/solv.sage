import os
os.environ['PWNLIB_NOTERM'] = 'True'
from pwn import *
from parse import parse

proof.arithmetic(False)

def H(params, msg, u):
    K, m = params
    r, z = K.characteristic(), K.gens()[0]
    h = 0
    while msg > 0:
        h *= z
        h += msg % r
        msg //= r
    h += z*u
    for _ in range(m):
        h ^= r
    return int(h.polynomial()[0])

def sign(params, privkey, msg):
    p, q = privkey
    u = 1
    while True:
        c = H(params, msg, u) % (p*q)
        if c != 0 and legendre_symbol(c, p) == legendre_symbol(c, q) == 1:
            break
        u += 1
    xp = pow(c, (p+1)//4, p)
    xq = pow(c, (q+1)//4, q)
    x = crt([int(xp), int(xq)], [p, q])
    return x, u

# context.log_level = 'debug'
# conn = process('../challenge/power-sign.sage')
conn = remote('0.0.0.0', 1337)
conn.recvline()
N = list(parse('N: {:d}\n', conn.recvline().decode()))[0]

n, m = 15, 3
r = next_prime(N)
F = GF(r)
K.<zK> = F.extension(n)
E = K.subfield(m, 'zE')
zE = E.gens()[0]

e0 = int(K(zE).polynomial()[0])
s = randint(1, N)
s2 = s^2 % N
k = K(inverse_mod(e0, r) * s2 * zE) - zK
y = sum(int(a)*r^i for i, a in enumerate(k.polynomial().coefficients(sparse=False)[::-1]))

conn.sendlineafter('message (in hex): ', hex(y))
x = list(parse('x: {:d}\n', conn.recvline().decode()))[0]
u = list(parse('u: {:d}\n', conn.recvline().decode()))[0]

if x == s or x == -s % N:
    print('attack failed... try again')
    exit()

p = gcd(s - x, N)
q = N//p

auth_msg = list(parse('Now sign {:d}\n', conn.recvline().decode()))[0]
x, u = sign((K, m), (p, q), auth_msg)
conn.sendlineafter('x: ', str(x))
conn.sendlineafter('u: ', str(u))

print(conn.recvline().decode())
