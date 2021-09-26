R.<alpha> = PolynomialRing(GF(2))
F = GF(2^8, alpha, modulus=alpha^8 + alpha^4 + alpha^3 + alpha + 1)
Fi = F.fetch_int

# K.<b0,b1,b2,b3,b4,b5> = PolynomialRing(F)
# S.<Y> = PolynomialRing(K)
# m = Y^6 + Y^2 + Fi(1)
# f = b0 + b1*Y + b2*Y^2 + b3*Y^3 + b4*Y^4 + b5*Y^5
# c = Fi(2)*Y^6 + Fi(3)*Y^4 + Fi(1)

M = [
    [3, 0, 3, 0, 2, 0],
    [0, 3, 0, 3, 0, 2],
    [2, 0, 0, 0, 1, 0],
    [0, 2, 0, 0, 0, 1],
    [3, 0, 2, 0, 0, 0],
    [0, 3, 0, 2, 0, 0],
]
M = [[Fi(x) for x in r] for r in M]
M = Matrix(F, M)

NUM_ROUNDS = 16
PBOX = [23, 16, 19, 12, 31, 24, 17, 22, 13, 18, 25, 30, 9, 2, 11, 4, 33, 26, 3, 8, 5, 10, 27, 32, 21, 14, 35, 28, 7, 0, 15, 20, 29, 34, 1, 6]
C0 = [0, 1, 2, 6, 12, 18]
C1 = [3, 4, 5, 11, 17, 23]
C2 = [7, 8, 9, 13, 14, 15]
C3 = [10, 16, 22, 28, 29, 35]
C4 = [19, 20, 24, 25, 26, 30]
C5 = [21, 27, 31, 32, 33, 34]
Cs = [C0, C1, C2, C3, C4, C5]

def permute(M):
    M_ = copy(M)
    for i,p in enumerate(PBOX):
        M_[i] = M[p]
    return M_

def inv_permute(M):
    M_ = copy(M)
    for i,p in enumerate(PBOX):
        M_[p] = M[i]
    return M_

def mix_column(col):
    v = vector(F, [Fi(x) for x in col])
    w = [x.integer_representation() for x in list(M * v)]
    return w

def inv_mix_column(col):
    v = vector(F, [Fi(x) for x in col])
    w = [x.integer_representation() for x in list(~M * v)]
    return w

def mix(M):
    V = [mix_column([M[i] for i in C]) for C in Cs]
    out = [None]*sum(len(r) for r in V)
    for i in range(len(V)):
        for idx, v in zip(Cs[i], V[i]):
            out[idx] = v
    return out

def inv_mix(M):
    V = [inv_mix_column([M[i] for i in C]) for C in Cs]
    out = [None]*sum(len(r) for r in V)
    for i in range(len(V)):
        for idx, v in zip(Cs[i], V[i]):
            out[idx] = v
    return out

output = [0x0f, 0x4f, 0x73, 0x3c, 0x41, 0xc6, 0xa4, 0xaf, 0xb4, 0x41, 0xd6, 0x65, 0xc8, 0x99, 0xaa, 0xb3, 0x6c, 0x99, 0x61, 0x3c, 0x4e, 0xdd, 0x70, 0x46, 0x15, 0x66, 0x3c, 0x1b, 0x7f, 0x16, 0xa6, 0x6f, 0x23, 0x13, 0x12, 0x6e]
for _ in range(NUM_ROUNDS):
    output = inv_permute(output)
    output = inv_mix(output)

print(''.join(map(chr, output)))
