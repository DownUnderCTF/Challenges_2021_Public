# Challenge Overview

This challenge is a sequel to "Substitution Cipher II", though in terms of difficulty, it is a large step up. The basis of the challenge is Patarin's famous attack (though other attacks may work) on the Matsumoto-Imai cryptosystem which was hinted towards by the bold **MI** in the challenge's description (one could easily find useful resources online by searching "MI cryptosystem"). The large public key size is also a trait of multivariate public key cryptosystems which some people may have recognised.

Like with the other two substitution cipher challenges, we are given the code which has been used to encrypt the flag, as well as the ciphertext. In this challenge, we are also given a public key.

## Matsumoto-Imai Cryptosystem

In this section we give a rough description of the Matsumoto-Imai-like cryptosystem as presented in the challenge. There are some differences from the original cryptosystem, so to hopefully make it easier to follow, we also draw comparisons between the mathematical notation and the handout code.

The general idea is that a composition of certain transformations is difficult to invert without knowledge of the individual transformations that make it up; so a private key is made up of some invertible transformations, and the corresponding public key is their composition. Additionally, solving a set of multivariate (even quadratic) polynomial equations over a finite field in general is proven to be NP-complete, so one _shouldn't_ be able to easily recover the plaintext from a given ciphertext and the public key alone.

### Parameters

To set the scene, we choose parameters $q$ and $n$ (in the challenge $q = 2$ and $n = 80$) and define some algebraic objects to work with:

$$
\begin{aligned}
    K &= \mathbb{F}_q[x_1, \ldots, x_n] \\
    E &= K[t]/(i(t)) \\
    L &= E[x] \\
    A &= \mathrm{Aff}(n, K)
\end{aligned}
$$

where $i(t)$ is an arbitrary degree $n$ irreducible polynomial. 

In Sage, we need to write a bit more boilerplate to achieve this:

```py
    q = 2
    F = GF(q)
    K = BooleanPolynomialRing(n, 'x')
    R.<t> = PolynomialRing(K)
    i = GF(q)[t].irreducible_element(n)
    I = Ideal(R(i))
    I.reduce = lambda f: f % i # dirty sage hack
    E.<tbar> = PolynomialRing(K, t).quo(I)
    L.<x> = PolynomialRing(E)
    A = AffineGroup(n, K)
```

- [`BooleanPolynomialRing`](https://doc.sagemath.org/html/en/reference/polynomial_rings/sage/rings/polynomial/pbori/pbori.html) is a more efficient implementation of boolean polynomials; in most cases it can be used as a clean replacement for `GF(2)[x1, ..., xn]`.
- As for the `I.reduce = ...` line, this should probably not need to be done but I was having difficulties getting Sage to properly reduce elements of $E$ modulo $i(t)$ and this seemed like the only way to fix it.
- The purpose of $L$ is to define polynomials whose variables are in $E$ (which we'll do next).
- $A$ is defined so that we can easily work with affine transformations.

### Private Key

Next, we'll generate the private key. We choose random $S, T \in A$ and $P = r x^{q + 1} \in L$ where $r \in E$ is randomly chosen. (Note that the construction of $P$ here is not in its most general form, and that this particular choice of $P$ is potentially weaker than other choices).

In Sage, we write:

```py
    S = A(GL(n, F).random_element(), random_vector(F, n), check=False)
    r = sum(randint(0, 1) * tbar^i for i in range(n))
    P = r * x^(q + 1)
    T = A(GL(n, F).random_element(), random_vector(F, n), check=False)
```

`A.random_element()` wasn't working for some reason, so we simply generate a random invertible matrix and a random vector with elements in $\mathbb{F}_q$ which is enough to represent an affine transformation.

### Public Key

To derive the public key $R$ from the private key, we simply take the composition $R = T \circ P \circ S$.

Actually, that's not entirely correct but it captures the general idea. To be more explicit, $S$ and $T$ are affine transformations that map elements of $K^n$ to elements of $K^n$, whereas $P$ is a function that takes an element in $E$ and outputs an element in $E$. The way we glue together these components of different "types" is by introducing an extra function that converts between the two types; there is a natural bijection between $K^n$ and $E$, so we define:

$$
\begin{aligned}
    \varphi : K^n &\rightarrow E \\
            (v_0, v_1, \ldots, v_{n-1}) &\mapsto v_0 + v_1 t + \cdots + v_{n-1} t^{n-1}
\end{aligned}
$$

So more accurately, we take the public key to be $R = T \circ \varphi^{-1} \circ P \circ \varphi \circ S$.

$R$ itself can be represented by $n$ multivariate polynomials $r_1, r_2, \ldots, r_n$; these are what will be used for encryption.

In Sage, we can write this concisely as:

```py
    B = S(K.gens()) * vector([tbar^i for i in range(n)])
    Q = P(B)
    R = T(Q.lift().coefficients())
```

Since $S$ and $T$ are elements of $A$, we can perform the transformation they represent with `S(x)` and `T(x)` respectively, where `x` is an element of $K^n$. Multiplication by the vector $(1, t, \ldots, t^{n-1})$ is equivalent to the conversion map $\varphi$, and taking the coefficients of an element in $E$ is equivalent to $\varphi^{-1}$. The reason for the `.lift()` is to consider `Q` as an element of $K[t]$ (as opposed to an element of $E$) since `.coefficients()` seems to be not implemented for this quotient ring.

### Encryption

Encryption is easy but there is a slight caveat that might be confusing. The public polynomials $r_i : K^n \rightarrow K$ map elements of $K^n$ to an element of $K$. We defined $K$ to be a boolean polynomial ring, but it should be noted that $\mathbb{F}_q$ is a subset of $K$, and that $\mathbb{F}_q^n$ is a subset of $K^n$. When we encrypt messages, we are really only concerned with the subset $\mathbb{F}_q$ and not with other elements of $K$. (This is just for the reason that working with bits is easier; there shouldn't be any issues with encoding messages using other elements in $K$)

To encrypt a message, we first encode the message as an element $m$ of $\mathbb{F}_q^n$ and compute $(r_1(m), r_2(m), \ldots, r_n(m))$. where $r_i$ are the public polynomials. Since each of the $r_i$ sends elements of $\mathbb{F}_q^n$ to an element in $\mathbb{F}_q$, the resulting ciphertext is an element of $\mathbb{F}_q^n \subset K^n$.

# Solution

We are given nothing but the public key and the ciphertexts. We could attempt to recover the private key, but it isn't necessary. We will follow Patarin's attack from Crypto'95 which allows us to recover the plaintext for any given ciphertext.

The attack relies on the fact that maps $f : E \rightarrow E$ of the form $x \mapsto x^{q^k}$ are linear for any integer $k$. By this, we mean that if $z = z_0 + z_1 t + \cdots + z_{n-1} t^{n-1} \in E$, then $f(z) = z_0' + z_1' t + \cdots + z_{n-1}' t^{n-1}$ is such that $z_i' = f_i(z_0, \ldots, z_{n-1})$ with $\deg f_i = 1$. In words; this says that the coefficients of $f(z)$ can be written as a linear combination of the coefficients of $z$.

I couldn't find a proof for this, (maybe because it's supposed to be obvious, but it certainly wasn't obvious to me), so here is my (possibly wrong) attempt at a justification (which I think might actually only work for $q = 2$):

Define $f : E \rightarrow E$ as $f(x) = x^{q^k}$ for any integer $k$. Let $z = z_0 + z_1 t + \cdots + z_{n-1} t^{n-1} \in E$. Then

$$
\begin{aligned}
    f(z) &= (z_0 + z_1 t + \cdots + z_{n-1} t^{n-1})^{q^k} \\
         &= z_0^{q^k} + (z_1 t)^{q^k} + \cdots + (z_{n-1} t^{n-1})^{q^k} \quad \text{since } \mathrm{char}(E) = q \\
         &= z_0 + z_1 t^{q^k} + \cdots + z_{n-1} t^{(n-1)q^k} \quad \text{since } x = x^q \text{ for all } x \in K
\end{aligned}
$$

It should now follow that, after being reduced modulo the irreducible polynomial $i(t)$, the coefficients of $f(z)$ are linear combinations of the $z_i$.

Combined with some other clever insights, this eventually leads to a linear expression relating all plaintext and ciphertext pairs as we will soon see.

## Finding the Relation

This is the core of the attack. To begin, recall that a plaintext message $x \in K^n$ is encrypted by computing its ciphertext $y = (T \circ \varphi^{-1} \circ P \circ \varphi \circ S)(x) \in K^n$.

Let $a = \varphi(S(x))$ and $b = \varphi(T^{-1}(y))$. Note that $a, b \in E$ and furthermore that $b = P(a)$. So we have

$$
b = ra^{q + 1}
$$

Now, applying $g : E \rightarrow E, x \mapsto x^{q-1}$ to both sides of the equation, we get

$$
\begin{aligned}
    g(b) &= g(ra^{q+1}) \\
    b^{q-1} &= r^{q-1} a^{q^2 - 1}
\end{aligned}
$$

Multiplying both sides by $ab$, we get

$$
ab^q = r^{q-1} a^{q^2} b \tag{1}
$$

By the definition of $a$ and $b$, we have

$$
a = c_1x + c_2 \qquad b = c_3 y + c_4
$$

where the $c_i$ are elements of $E$ which we do not particularly care about. This follows because $a$ and $b$ are simply affine transformations of $x$ and $y$ respectively.

Combining this with the fact that the maps $b \mapsto b^q$ and $a \mapsto a^{q^2}$ are linear maps, equation $(1)$ effectively gives us an equation relating $x$ and $y$ where $x$, $y$ and $xy$ appear to a power of no greater than $1$.

So, if we let $x = (x_0, x_1, \ldots, x_{n-1})$ and $y = (y_0, y_1, \ldots, y_{n-1})$, then the information given by equation $(1)$ can be rewritten as:

$$
\sum_{i=0}^{n-1} \sum_{j=0}^{n-1} \gamma_{i, j} x_i y_j + \sum_{i=0}^{n-1} \alpha_i x_i + \sum_{j=0}^{n-1} \beta_j y_j + \delta = 0 \tag{2}
$$

And the amazing thing about this relation is that it holds for _all_ plaintext/ciphertext pairs $(x, y)$ since we made no assumptions about them to begin with! That means it holds for the flag and the ciphertext we've been given too :)

## Recovering the Constants

Equation $(2)$ gives us a relation that holds for all plaintext/ciphertext pairs, but we don't know the $\gamma_{i, j}, \alpha_i, \beta_j$ and $\delta$. Fortunately, since encryption uses the public key (which we have), we can generate our own plaintexts and encrypt them to get valid plaintext/ciphertext pairs.

With a set of plaintext/ciphertext pairs, we can view equation $(2)$ as a system of linear equations in the unknowns $\gamma_{i, j}, \alpha_i, \beta_j$ and $\delta$ and use linear algebra techniques to solve for them. There are $n^2 + n + n + 1 = (n+1)^2$ unknowns, so we'll need $(n+1)^2$ plaintext/ciphertext pairs to successfully recover the constants.

Generating the plaintext/ciphertext pairs may take a while (though, not _that_ long if you're patient), so an easy optimisation we can do is choose sparse plaintext vectors; that is, plaintexts which have a lot of zero bits. Doing this speeds up polynomial evaluation which is the most expensive operation for encryption.

## Recovering the Flag

The hard work is mostly done. If we have the relation and the constants, then to recover a plaintext given a ciphertext all we need to do is plug in the $y_j$ values, and solve for the $x_i$ values. Again, this is done using linear algebra techniques, but in this case instead of solving a system of linear equations in the unknowns $\gamma_{i, j}, \alpha_i, \beta_j$ and $\delta$, we solve the system for the unknowns $x_0, x_1, \ldots, x_{n-1}$.

# References/Extra Reading

- [Jacques Patarin - Cryptanalysis of the Matsumoto and Imai Public KeyScheme of Eurocrypt'88](https://link.springer.com/content/pdf/10.1007%2F3-540-44750-4.pdf)
- [Adam Janovsky - Algebraic cryptanalysis of Hidden Field Equations family](https://is.muni.cz/th/rwbym/bthesis.pdf)
- [Nicolas T. Courtois - The security of Hidden Field Equations](http://www.minrank.org/hfesecsl.pdf)
