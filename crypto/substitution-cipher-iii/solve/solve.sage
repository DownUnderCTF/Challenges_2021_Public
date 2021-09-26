from Crypto.Util.number import long_to_bytes
from string import printable
from tqdm import tqdm

E, C1, C2 = open('../challenge/output.txt', 'r').read().splitlines()

def encrypt(pubkey, msg):
    # assume msg \in {0,1}^n
    return tuple([p(*msg) for p in pubkey])

# not entirely necessary, but speeds up polynomial evaluation
def gen_sparse_vector(i, n):
    p = 0
    while i > 0:
        p |= 1 << (i % n)
        i //= n
    return tuple(map(int, f'{p:0b}'.zfill(n)))

def get_ptct_pairs(pubkey, N):
    n = len(pubkey[0].parent().gens())
    seen = set()
    pairs = []
    i = 0
    pbar = tqdm(total=int(N))
    while len(pairs) < N:
        pt = gen_sparse_vector(i, n)
        if pt not in seen:
            ct = encrypt(pubkey, pt)
            pairs.append((pt, ct))
            seen.add(pt)
            pbar.update(int(1))
        i += 1
    pbar.close()
    return pairs

def gen_matrix_row(pair):
    X, Y = pair
    r = []
    for i in range(n):
        for j in range(n):
            r.append(F(X[i]*Y[j]))
    r += [F(x) for x in X]
    r += [F(y) for y in Y]
    r.append(1)
    return r

q = 2
n = 80
F = GF(q)
G = PolynomialRing(F, [f'x{i}' for i in range(n)])
Kb = BooleanPolynomialRing(n, 'x') # faster than GF(2)[x0, ..., xn]
Kb.inject_variables()

pubkey = eval(E)
print('generating random pt/ct pairs...')
pairs = get_ptct_pairs(pubkey, (n+1)^2)

print('generating coefficient matrix...')
M = list(gen_matrix_row(pair) for pair in tqdm(pairs))
M = Matrix(F, M)

print(f'nullity: {M.right_nullity()}')
print('computing kernel...')
K = M.right_kernel()

def recover_X(K, C):
    X = Kb.gens()
    Y = [int(c) for c in C]
    T = []
    for coeffs in K.basis():
        eq = 0
        for i in range(n):
            for j in range(n):
                eq += coeffs[n*i + j]*X[i]*Y[j]
        eq += sum(coeffs[n^2 + i]*X[i] for i in range(n))
        eq += sum(coeffs[n^2 + n + i]*Y[i] for i in range(n))
        eq += coeffs[n^2 + 2*n]
        T.append(G(eq))
    T = Sequence(T)
    for v in T.coefficient_matrix()[0].right_kernel():
        m = ''.join(map(str, v[:-1]))
        pt = long_to_bytes(int(m, 2))
        if all(chr(c) in printable for c in pt):
            return pt.decode()

flag1 = recover_X(K, C1)
flag2 = recover_X(K, C2)
flag = 'DUCTF{' + flag1 + flag2 + '}'
print(flag)
