P.<x> = PolynomialRing(ZZ)
f = 13*x^2 + 3*x + 7

enc = open('../challenge/output.txt', 'r').read().strip()
flag = ''
for c in enc:
    p = (f - ord(c)).roots()[0][0]
    flag += chr(p)
print(flag)
