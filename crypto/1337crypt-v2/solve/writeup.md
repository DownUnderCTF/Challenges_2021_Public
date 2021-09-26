# Challenge Overview

The challenge claims to be a more complex version of [1337crypt](https://jsur.in/posts/2020-09-20-downunderctf-2020-writeups#1337crypt) from last year's DUCTF. Reading the solution for 1337crypt may help a bit with some initial ideas as both challenges play with the idea of partial knowledge. In both challenges, we are given hints to recover the prime factors, but the hints themselves seem to omit some bits of information. Specifically, the hints are the integer parts of some values that should actually contain a fractional part as well. As we will see (and as you may suspect :)), lattice techniques will help us to recover this missing information and therefore the primes.

## Flag Encryption

We start by looking at how the flag is encrypted so that we have a clear idea of what we need to recover it. The flag is encrypted in a way very similar to RSA. The only difference is that instead of using integers, we use [Gaussian integers](https://en.wikipedia.org/wiki/Gaussian_integer). If you aren't familiar with Gaussian integers, I highly recommend reading [this excellent blog post](https://blog.cryptohack.org/tetctf-2021) by CryptoHack for some extra background.

We work in the ring $(\mathbb{Z}/n\mathbb{Z})[i]$ (we will just write this as $\mathbb{Z}_n[i]$) where $n = pq$ is the RSA modulus. The flag is encoded as an element $m$, of $\mathbb{Z}_n[i]$ by choosing a random integer $r < n$ and computing $m = r + \mathrm{flag} \cdot i$.

The ciphertext is obtained by raising $m$ to the $e$th power. In the challenge, $e$ is 0x1337.

To decrypt the ciphertext, we must find the multiplicative inverse of $e$ modulo the order of $\mathbb{Z}_n[i]$. (Note: in this context, when we say "the order of $\mathbb{Z}_n[i]$" we mean the cardinality of the multiplicative group of $\mathbb{Z}_n[i]$) The order of $\mathbb{Z}_n[i]$ is $\varphi(n) = (p-1)(q-1)$, so to compute it, we'll need to recover the primes.

## Hints

The challenge generates 1337-bit primes $p$ and $q$ and gives us two hints, and the ciphertext. Using these hints, we need to recover $p$ and $q$.

### Hint 1

The first hint, which we will call $D$, is $D = p^2 + q^2$. This seems like a pretty big hint, and indeed if we were also given $n = pq$ we could easily recover the primes by finding the roots of a simple univariate polynomial. As far as I am aware, $D$ can't be used to directly recover $p$ and $q$ either; there are techniques such as factoring $p^2 + q^2 = (p + qi)(p - qi)$ over the Gaussian integers, but this requires factoring $D$ over the integers which may take a long time. That said, if you were able to find a solution using this hint alone I'd be interested in seeing it :)

### Hint 2

There is a lot more going on in the second hint. But firstly, some background. [Number field](https://en.wikipedia.org/wiki/Algebraic_number_field) is just a fancy name for an (finite) extension of the rational numbers $\mathbb{Q}$. The simplest number field is $\mathbb{Q}$ itself, and the rational complex numbers, $\mathbb{Q}(i)$ is also a number field.

We can see that a number field is constructed from $p$ and $q$. In Sage, the first argument to [NumberField](https://doc.sagemath.org/html/en/reference/number_fields/sage/rings/number_field/number_field.html#sage.rings.number_field.number_field.NumberField) is the defining polynomial. The roots of this polynomial specify the elements to be adjoined to $\mathbb{Q}$ to get the number field. We see that the defining polynomial for $K$ is $(x-p)^2 + q^2$, which has roots $p \pm qi$. Therefore, we define

$$
K = \mathbb{Q}(p + qi)
$$

(side note: we only need to adjoin one root since the other, it's conjugate, can be obtained from the root with usual field operations). In the handout code, $z = p + qi$ denotes this adjoined element.

Now, for the values we are given. We get two instances of values with the same form. For the $j$th hint ($j = 1, 2$), two 1337-bit numbers $a_j$ and $b_j$ are generated, as well as two $l$-bit numbers $c_j$ and $d_j$. Then, $x_j$ is computed as

$$
x_j = (a_j + 2^{-l} c_j) + (b_j + 2^{-l} d_j) z
$$

Lastly,

$$
|x_j|^2 = x_j \overline{x_j}
$$

is computed and we are given the three values $(\lfloor |x_j|^2 \rfloor, a_j, b_j)$. Note that $\overline{x_j}$ denotes the complex conjugate of $x_j$, so the value $x_j \overline{x_j}$ gives us the squared [complex modulus](https://en.wikipedia.org/wiki/Absolute_value#Complex_numbers) of $x_j$. For ease of reading, we will write $y$ instead of $\lfloor |x_j|^2 \rfloor$.

Importantly, we note that $x_j$ is an element of $K$ and its components are rational numbers with fractional parts. Similarly, $|x_j|^2$ is a rational number with a fractional part. However, we are only given the integer parts of these values, so it seems like we might be missing some information.

# Solution

Let's analyse the second hint in further detail and see if we can use it to recover the primes directly, or find a relation involving the primes that will help us to do so.

## Analysing Hint 2

There will be some tedious algebra, so to make things a bit more readable we will drop the subscripts. Note that we use hint 1 here since $p^2 + q^2$ appears. We have

$$
\begin{aligned}
    x &= (a + 2^{-l} c) + (b + 2^{-l} d) z \\
    &= (a + 2^{-l} c) + (b + 2^{-l} d) (p + qi) \\
    &= ((a + 2^{-l} c) + (b + 2^{-l} d) p) + (b + 2^{-l} d) qi \\
\implies |x|^2 &= ((a + 2^{-l} c) + (b + 2^{-l} d) p)^2 + ((b + 2^{-l} d)q)^2 \\
    &= (a + 2^{-l} c)^2 + 2(a + 2^{-l} c)(b + 2^{-l} d) p \\
        &\quad + (b + 2^{-l} d)^2 p^2 + (b + 2^{-l} d)^2 q^2 \\
    &= (a + 2^{-l} c)^2 + 2(a + 2^{-l} c)(b + 2^{-l} d) p + (b + 2^{-l}d)^2 D \\
    &= a^2 + 2 \cdot 2^{-l} ac + 2^{-2l} c^2 + 2 a b p + 2 \cdot 2^{-l} adp + 2 \cdot 2^{-l} bcp + 2 \cdot 2^{-2l} c d p \\
        &\quad + (b^2 + 2 \cdot 2^{-l} bd + 2^{-2l} d^2) D \\
    &= a^2 + 2 \cdot 2^{-l} ac + 2^{-2l} c^2 + 2 a b p + 2 \cdot 2^{-l} adp + 2 \cdot 2^{-l} bcp + 2 \cdot 2^{-2l} c d p \\
        &\quad + b^2 D + 2 \cdot 2^{-l} bd D + 2^{-2l} d^2 D
\end{aligned}
$$

Now, this looks like a mess and it kinda is, but fortunately we can clean it up a bit. Recall that $a$ and $b$ are 1337-bit numbers, while $c$ and $d$ are 338-bit numbers ($l = 338$). The following table gives the approximate size of each term (_when considered as an integer_), which we will use to reason with soon. Note that $D = p^2 + q^2$ is on the order of $2 \times 1337$ bits.

|Term|Size (in bits)|
|---|---|
|$a^2$|$2 \times 1337$|
|$2 \cdot 2^{-l} ac$|$1337$|
|$2^{-2l}c^2$|$0$|
|$2abp$|$3 \times 1337$|
|$2 \cdot 2^{-l} adp$|$2 \times 1337$|
|$2 \cdot 2^{-l} bcp$|$2 \times 1337$|
|$2 \cdot 2^{-2l} cdp$|$1337$|
|$b^2 D$|$4 \times 1337$|
|$2 \cdot 2^{-l} bd D$|$3 \times 1337$|
|$2^{-2l} d^2 D$|$2 \times 1337$|

Now, what we will do is divide (integer division) the entire expression by $2ab$. Because $2ab$ is around $2 \times 1337$ bits in size, we can more or less throw away any term whose size is $2 \times 1337$ or less. This leaves us with

$$
\begin{aligned}
    \frac{|x|^2}{2ab} = \frac{y}{2ab} &\approx p + \frac{(b^2 + 2 \cdot 2^{-l} bd) D}{2ab} \\
        &\approx p + \frac{b^2D}{2ab} + \frac{2^{-l}dD}{a}
\end{aligned}
$$

This approximation itself is very accurate, and only differs by a few bits due to the $2 \times 1337$ terms. However, we don't know $d$, so this equation isn't as useful for us. Instead, we write

$$
\begin{aligned}
    \frac{y}{2ab} &\approx p + \frac{b^2 D}{2ab} + \left \lfloor \frac{2^{-l} D}{a} \right \rfloor d \\
                  &= p + \frac{b^2 D}{2ab} + \left \lfloor \frac{2^{-l} D}{a} \right \rfloor d + k
\end{aligned} 
$$

where $|k| < 2^l$. Note that the approximation is off by a term of size approximately $l$ bits because of integer division rounding. We will omit the $\lfloor \rfloor$, but it should be understood that we are performing integer division.

## Using Hint 2

Now let's bring back the subscripts, noting that we have two instances:

$$
\begin{aligned}
\begin{cases}
    \frac{y_1}{2a_1 b_1} &= p + \frac{b_1^2 D}{2 a_1 b_1} + \frac{2^{-l} D}{a_1} d_1 + k_1 \\
    \frac{y_2}{2a_2 b_2} &= p + \frac{b_2^2 D}{2 a_2 b_2} + \frac{2^{-l} D}{a_2} d_2 + k_2 \\
\end{cases}
\end{aligned}
$$

Finally, let's combine these two equations to eliminate $p$. 

$$
\frac{y_1 - b_1^2 D}{2 a_1 b_1} - \frac{2^{-l} D}{a_1} d_1 - k_1 = \frac{y_2 - b_2^2 D}{2 a_2 b_2}- \frac{2^{-l} D}{a_2} d_2 - k_2
$$

Just so it's easier to read, let $t_j = \frac{y_j - b_j^2 D}{2 a_j b_j}$ and $s_j = \frac{2^{-l} D}{a_j}$. Then, rewriting the above equation, we have:

$$
t_1 - s_1 d_1 - k_1 = t_2 - s_2 d_2 - k_2
$$

or to put it in a more exciting way:

$$
f(d_1, d_2, k) = t_1 - s_1 d_1 - t_2 + s_2 d_2 - k = 0
$$

Now, $f$ has "small" integer roots $d_1, d_2$ and $k$. An algorithm for finding small roots of multivariate polyomials over the integers is described in this [paper](https://eprint.iacr.org/2007/088.pdf). Following a similar idea, [defund's coppersmith implementation](https://github.com/defund/coppersmith/) can also be used by working over an arbitrary ring $\mathbb{Z}/N\mathbb{Z}$ for some large $N$.

### Lattice Approach

However, we can also recover $d_1$ and $d_2$ with a very simple lattice. Consider the lattice generated by the rows of the following matrix:

$$
\begin{bmatrix}
    s_1 & 1 & 0 \\
    s_2 & 0 & 1 \\
    t_1 - t_2 & 0 & 0
\end{bmatrix}
$$

The short vector $(k, -d_1, d_2)$ is an element of this matrix, given by the linear combination of $-d_1$ times the first row, $d_2$ times the second row, and $1$ times the third row. LLL finds this vector.

## Recovering the Primes

Now that we have $d$, it is straightforward to recover $p$. We use the approximation we found earlier:

$$
\begin{aligned}
    \frac{y}{2ab} &\approx p + \frac{(b^2 + 2 \cdot 2^{-l} bd) D}{2ab} \\
    \implies p &\approx \frac{y - (b^2 + 2 \cdot 2^{-l} bd) D}{2ab}
\end{aligned}
$$

This approximation is accurate to all but a few bits, which we can easily exhaust over, checking if $D - p^2$ is a square to know which candidate for $p$ is correct. We then compute $q$ as the square root of $D - p^2$.

## Getting the Flag

We've already discussed how to decrypt the ciphertext given that we have the prime factors. Compute $d \equiv e^{-1} \pmod{(p-1)(q-1)}$ as in regular RSA and raise $c$ to the $d$th power. The flag is in the imaginary component of the result.
