from Crypto.Util.number import long_to_bytes

exec(open('../challenge/output.txt').read()) # hint1, hint2, c

nbits = 1337
l = 1+337
dd = 2^-l
D = hint1

t1, t2 = [int(b^2 * D - y)//int(2*a*b) for y, a, b in hint2]
s1, s2 = [int(dd*D)//a for _, a, b in hint2]

M = Matrix([
    [s1, 1, 0],
    [s2, 0, 1],
    [t1 - t2, 0, 0]
])
B = M.LLL()
d = abs(B[0][1])
y, a, b = hint2[0]
my_p = int(y - (b^2 + 2*dd*b*d)*D)//int(2*a*b)

for p in range(my_p - 2^8, my_p + 2^8):
    if ZZ(D - p^2).is_square():
        q = ZZ(D - p^2).sqrt()
        print('[+] primes recovered!', p, q)
        break

n = p*q
Zn.<I> = (ZZ.quo(n*ZZ))[]
ZnI.<I> = Zn.quo(I^2 + 1)
c = ZnI(c)

d = pow(0x1337, -1, (p-1)*(q-1))
m = pow(c, int(d))

flag = long_to_bytes(list(m)[1])
print('[*] flag:', flag.decode())
