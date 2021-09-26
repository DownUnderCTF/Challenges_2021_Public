This challenge is a sequel to "Substitution Cipher I". We have a similar situation as with the first challenge, except instead of a function over the integers, we work over a finite field `GF(n)`, which for the purposes of this challenge, we can think of as basically a subset of the integers where addition and multiplication are done modulo `n`. Another difference is that the polynomial `f` is not given, and it is of degree 6. Each coefficient of `f` can be any integer in the range `0, 1, ..., n`, and since there are 7 coefficients, there can be up to `n^7` different possibilities for `f`. In the challenge, `n = 47`, so searching `n^7` possibilities would be unreasonable.

Instead, we can use the fact that a polynomial of degree `d` is uniquely determined by `d+1` points that lie on it. We know that the flag is of the form `DUCTF{...}` so we have exactly 7 known points on the curve! We can use a technique known as [Lagrange interpolation](https://en.wikipedia.org/wiki/Lagrange_polynomial) to recover the polynomial (SageMath has a method for this too!). We find that the polynomial is

```
f(x) = 41x^6 + 15x^5 + 40x^4 + 9x^3 + 28x^2 + 27x + 1
```

Now we can use a similar idea to the previous challenge and find possible plaintext characters for each ciphertext character `c` by finding the roots of `f(x) - c`. However, in this case, there may be many solutions in the range `0, 1, ..., n`. It turns out that the total number of possible flags is not that high, so we can look through all of them and choose the one that seems most fitting (or just try submitting all of them). The possible flags that we find (excluding the ones that don't fit flag format) are:

```
DUCTF{go0d_0l'_l4gr4pg8}
DUCTF{go0d_0l'_l4gr4pg3}
DUCTF{go0d_0l'_l4gr4ng8}
DUCTF{go0d_0l'_l4gr4ng3}
DUCTF{go0d_0l'_l4gr4fg8}
DUCTF{go0d_0l'_l4gr4fg3}
```

The correct flag is `DUCTF{go0d_0l'_l4gr4ng3}`.

```py
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
```
