The encryption used in the challenge is indeed a simple substitution cipher in disguise. If the text was longer and closer to English, it could be cracked with frequency analysis since each character is encrypted individually and independently of each other.

A plaintext character `m` is encrypted by evaluating it at a public polynomial `f(x) = 13x^2 + 3x + 7`. For example, to encrypt the character "a" (whose ASCII value is 97) we would compute 
```
f(97) = 13*(97^2) + 3*97 +7 = 122615
```

The entire message is encrypted by encrypting each character in this way.

Now suppose we are given a ciphertext value `c`. The goal is to find its corresponding plaintext character `x`. We can represent this mathematically as `f(x) = c`, so plugging in the values, we get

```
13x^2 + 3x + 7 = 122615
```

so

```
13x^2 + 3x + 7 - 122615 = 0
```

Which is just a quadratic equation that can be solved using the quadratic formula. In particular, we get

```
x = (-3 ± sqrt(9 - 4*13*(-122608)))/(2*13)
  = -97.23077 or 97
```

Since we are only interested in positive, integer solutions, we conclude that `x = 97`. Doing this for each character in the ciphertext, we can recover the flag.

SageMath provides a nice [method](https://doc.sagemath.org/html/en/reference/polynomial_rings/sage/rings/polynomial/polynomial_element.html#sage.rings.polynomial.polynomial_element.Polynomial.roots) for solving for the roots of polynomials which is used in the solve script:

```py
P.<x> = PolynomialRing(ZZ)
f = 13*x^2 + 3*x + 7

enc = open('../challenge/output.txt', 'r').read().strip()
flag = ''
for c in enc:
    p = (f - ord(c)).roots()[0][0]
    flag += chr(p)
print(flag)
```
