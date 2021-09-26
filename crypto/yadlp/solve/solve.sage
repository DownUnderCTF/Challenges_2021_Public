from tqdm import tqdm

exec(open('../challenge/output.txt').read())

proof.arithmetic(False)
F.<x> = GF(p)[]
R.<W> = GF(p^2, modulus=x^2 - (D+1))
q = p+1
g = R.zeta(q)

def phi(g):
    x, y = g
    return (x+y) + y*W

print('[!] calculating logs...')
L = [discrete_log(phi(gi), g) for gi in tqdm(G)]
log_ct = discrete_log(phi(c), g)
print('[+] calculating logs done...')

m = len(G)
C = L + [log_ct, q]
M = Matrix.column(ZZ, vector(C))
M = M.augment(Matrix.identity(m+1).stack(vector([0]*(m+1))))
M = M.dense_matrix()

B = M.LLL()
for r in B:
    if r[0] == 0:
        break

print('[+] solved SVP:', r)

flag = ''.join(int(abs(m)).to_bytes(8, 'big').decode() for m in r[1:-1])
print('[+] flag:', flag)
