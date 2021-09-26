from data import M

xs = [182, 710, 103, 47, 14, 212, 85, 196, 136, 52, 260, 20, 627, 474, 86, 3, 59, 199, 76, 141, 244, 73, 243, 124, 71, 67, 126, 162, 103, 78, 59, 41, 3, 415, 68, 41, 81, 6, 293, 24, 198, 134, 137, 406, 148, 57, 53, 150, 176, 96, 82, 371, 102]

p = 3766999387
F = GF(p)
n = 50
MS = MatrixSpace(F, n)
M = MS(M)
D, P = M.diagonalization()

def fast_exp(P, D, k):
    return P * MS.diagonal_matrix([x^k for x in D.diagonal()]) * ~P

def sum_entries(M, p=127):
    return sum(map(int, M.list())) % p

y = 2
FLAG = ''
M_ = M
for x in xs:
    M_ *= fast_exp(P, D, y + x)
    c = chr(sum_entries(M_))
    y = (y*y) % (p-1)
    FLAG += c
print(FLAG)
