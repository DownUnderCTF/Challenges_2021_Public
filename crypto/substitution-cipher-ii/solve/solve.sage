from string import ascii_lowercase, digits

CHARSET = 'DUCTF{}_!?\'' + ascii_lowercase + digits
n = len(CHARSET)

def to_num(c):
    return CHARSET.index(c)

def to_chr(x):
    return CHARSET[x]

enc = open('../challenge/output.txt', 'r').read().strip()

P.<x> = PolynomialRing(GF(n))

known_pt = 'DUCTF{}'
known_ct = enc[:6] + enc[-1]
pairs = [(to_num(p), to_num(c)) for p,c in zip(known_pt, known_ct)]
f = P.lagrange_polynomial(pairs)

# get the possible plaintext character for each ciphertext character
possible_chars = []
for c in enc:
    possible = (f - to_num(c)).roots()
    possible = [to_chr(p[0]) for p in possible]
    possible_chars.append(possible)

# get all combinations of possible plaintext characters
possible_flags = []
for p in cartesian_product(possible_chars):
    possible_flags.append(''.join(p))

print('Possible Flags:')
print('\n'.join(possible_flags))
