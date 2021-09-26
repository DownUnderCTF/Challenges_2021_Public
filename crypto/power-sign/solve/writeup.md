## Challenge Overview

We are given the code running on a server that implements a signature scheme. We can ask the server to sign one message, then we are challenged to forge a signature for a random message.

The signature scheme resembles the [Rabin signature algorithm](https://en.wikipedia.org/wiki/Rabin_signature_algorithm). The public key is an RSA modulus $N = pq$ whose prime factorisation is the private key. A message $M$ is signed by first computing a _randomised hash_ $H(M, u)$ (where $u$ is random) of $M$. If $H(M, u)$ has a square root modulo $N$, a square root $x$ modulo $N$ is computed and the signature $(x, u)$ is outputted. Otherwise, we try again with a different $u$. Note that computing square roots modulo $N$, or even determining whether a number has a square root modulo $N$ is equivalent to factoring $N$. To verify a signature $(x, u)$ for the message $M$, we simply check that the equality $x^2 \equiv H(m, u) \pmod N$ holds.

In the challenge, the primes generated are of the form $p \equiv 3 \pmod 4$. This is done because if $p$ is a prime such that $p \equiv 3 \pmod 4$, then if a square root of $a \in \{ 0, \ldots, p-1 \}$ exists, it can be easily computed as $\pm a^{\frac{p+1}{4}} \mod p$. To compute a square root of $c$ modulo $N$, we compute square roots of $c$ modulo $p$ and modulo $q$, then combine them with the Chinese Remainder Theorem.

## Security of Rabin Signatures

Before we proceed, we'll take a look at an easy attack against a simplified variant of the Rabin signature algorithm. Specifically, we consider a variant that does not use a hash function at all, i.e. to sign a message $M$ the signer simply computes a square root of $M$ modulo $N$. For simplicity, we assume that all the messages to be signed actually do have square roots modulo $N$, though it does not really matter. There is one trivial attack; anyone can "forge" a valid signature for $M$ if $M$ is a perfect square. For example, if $M = 9$, then $x = 3$ is a valid signature since $x^2 \equiv m \pmod N$.

More interestingly however, it turns out that we can recover the private key given access to a signing oracle. We do this by choosing a random $x < N$ and ask the oracle to sign $x^2 \mod N$. It returns a square root $y$ of $x^2$ modulo $N$. Now, if $y \neq \pm x \pmod N$, then we have

$$
\begin{aligned}
    x^2 &\equiv y^2 \pmod N \\
    \implies x^2 - y^2 &\equiv 0 \pmod N \\
    \implies x^2 - y^2 &= kN \quad \text{for some $k$} \\
    \implies (x-y)(x+y) &= kN
\end{aligned}
$$

so $\gcd(x-y, N)$ reveals a nontrivial factor of $N$.

## The Hash Function

This section and the next are somewhat algebra-heavy and basic results from algebra are used without proof for brevity. It may be worthwhile to read up on finite fields, field extensions and Galois theory (for later) if they are unfamiliar concepts.

We learned the importance of a good, randomised hash function in the previous section. And more importantly, we learned that a hash function which is simply the identity map (i.e. sends any input to itself), is completely insecure. We will now take a look at the hash function in the challenge.

Choose a composite integer $n$ and a proper divisor $m$ (in the challenge we have $n = 15, m = 3$). Let $r$ be the smallest prime number following $N$, where $N$ is the signer's public key. We will work in an extension field $K = \mathbb{F}_{r^n} \cong \mathbb{F}_r[x]/(f)$ of $\mathbb{F}_r$, where $f \in \mathbb{F}_r[x]$ is a public degree $n$ irreducible polynomial. Let $z = x + (f)$. Then $z$ generates $K$ and $\{ 1, z, z^2, \ldots, z^{n-1} \}$ is basis for $K$ when viewed as an $n$-dimensional $\mathbb{F}_r$-vector space. That is, elements in $K$ can be written in the form $a_0 + a_1 z + \cdots + a_{n-1} z^{n-1}$ where $a_i \in \mathbb{F}_r$.

The randomised hash function $H$ takes as input a message $M$ and an integer $u$. Write $M$ in terms of powers of $r$:

$$
M = M_0 + M_1 r + M_2 r^2 + \cdots + M_k r^k
$$

where $M_i < r$. Then, $M$ is converted to an element $h$ in $K$ by computing

$$
h = M_k + M_{k-1} z + M_{k-2} z^2 + \cdots + M_0 z^k
$$

To obtain the hash, the function computes $(h + uz)^{r^m}$ which we write as

$$
(h + uz)^{r^m} = a_0 + a_1 z + \cdots + a_{n-1} z^{n-1}
$$

The output is $a_0$.

## Choosing a Message to be Signed

After the server provides us with its public key, it prompts us to send a message to be signed. Note that (in the `sign` function) $u$ isn't chosen randomly; it starts at $1$ and increments until $H(M, u)$ is a square. There is also a peculiar restriction on the message; it has to be larger than $N^m$ and smaller than $N^n$.

If we were able to send messages of any size for the server to sign, we can easily find a message that will help us to recover the private key. Specifically, we would choose a random $s < N$ and send the message $(r - 1) + (s^2 \mod N) r$. The hash function will convert this to $h = (s^2 \mod N) + (r - 1)z$ and output the constant term in $(h + uz)^{r^m}$ which happens to just be $s^2 \mod N$ since all elements $a \in \mathbb{F}_r$ satisfy $a^r = a$ by Fermat's Little Theorem. So when the server signs this, we have the exact same situation as the attack described two sections ago. However, the size check prevents this attack.

Recall that the identity map is insecure as a hash function for the reasons given two sections ago. It turns out that our particular hash function is the identity map on a specific subset, or rather, subfield of $K$ other than $\mathbb{F}_r$. We have

$$
H(M, u) = (h + uz)^{r^m}
$$

where $h$ is the element in $K$ we obtain by converting $M$. We can write this as a composition $H = f \circ g$ where

$$
g(M, u) = h + uz \qquad f(x) = x^{r^m}
$$

The goal will be to find fixed points of $H$, which can be done by finding fixed points of $f$ since we can easily manipulate the result of $g(M, u)$ by carefully choosing $M$. Fixed points of $f$ satisfy

$$
f(x) = x \implies x^{r^m} = x \implies x^{r^m} - x = 0
$$

Note that for a finite field $E$ of order $r^m$, the elements of $E$ are given by the roots of $x^{r^m} - x$. This follows from the fact that the multiplicative group $E^\times = E - \{ 0 \}$ is a cyclic group of order $r^m - 1$, so if $\alpha \in E$, then $\alpha^{r^m - 1} = 1$ and so $\alpha^{r^m} = \alpha$. That $E^\times$ is cyclic of order $r^m - 1$ follows from the structure theorem for finite abelian groups which states that any finite abelian group is a direct product of cyclic groups. There are a lot of references online for these results and their proofs.

So, to solve for the roots of $x^{r^m} - x$ we simply need to look at elements in the finite field $E$ of order $r^m$. Since $m$ divides $n$, then this field is actually a subfield of $K$ because if $x$ satisfies $x^{r^m} = x$, then it also satisfies

$$
\begin{aligned}
    x^{r^n} &= x^{r^{km}} \\
            &= x^{(r^m)^k} \\
            &= x^{(r^m)(r^m)^{k-1}} \\
            &= (x^{r^m})^{(r^m)^{k-1}} \\
            &= x^{(r^m)^{k-1}} \\
            &\quad \vdots \\
            &= x
\end{aligned}
$$

(and it can also be checked that $E$ actually is a field). This is good for us as it means we can write the elements in terms of $z$ which is what the server will be expecting.

Let $z_E$ be a generator of $E$. Because $E$ is a subfield of $K$, then $z_E$ can be written as

$$
z_E = e_0 + e_1 z + \cdots e_{n-1} z^{n-1}
$$

where $e_i \in \mathbb{F}_r$. Choose a random $s < N$. We will want to find an element in $K$ of the form

$$
(s^2 \mod N) + a_1 z + \cdots a_n z^{n-1}
$$

such that when $H$ is applied to this element, the constant term remains as $s^2 \mod N$ which will be the output of the hash function. To do this, we will find an element in $E$ with $s^2 \mod N$ as its constant term, and then subtract $z$ from it to account for the randomising value $u$ which we can predict will be $1$.

The element in $K$ we are interested in is obtained by computing

$$
(s^2 \mod N) e_0^{-1} z_E - z = (s^2 \mod N) + a_1 z + \cdots + a_n z^{n-1}
$$

To send this to the server, we encode it as an integer:

$$
a_n + a_{n-1} r + \cdots + a_1 r^{n-2} + (s^2 \mod N) r^{n-1}
$$

The server will compute for us a square root $y$ of $s^2 \mod N$ and if we have $y \neq \pm s$, we can easily recover the private key using the technique described two sections ago.

Once we have the private key, we can use the provided functions in the handout code to sign the challenge message and capture the flag.

### Easier Solution

I was made aware of this by [S3v3ru5's](https://twitter.com/S3v3ru5_) solve during the CTF, but choosing the message to be signed can actually be quite simple (though fundamentally relies on most of the above theory); the idea is to shift the goal posts a bit and instead of trying to find a fixed message, we find a message whose hash is something we can control. We do this by noting that since $x^{r^n} = x$ for all $x \in K$, then for any of our chosen $x \in K$, if we send $x^{r^{n - m}} - zu$, then after being hashed, the result is exactly $x$. I imagine most teams would have solved this way instead of finding the subfield which is quite a bit more complicated. I obviously lacked the hindsight to spot this solution when writing the challenge, but it's pretty neat :)

## Alternative Approach via Linearity Properties

This solution idea is due to [rkm0959](https://twitter.com/rkm0959) who taught me this during the CTF after he solved it. Instead of looking at the fields involved, we can simply note that the hash function has some nice linearity properties. In particular

$$
H(M, u) = H(M, 0) + u H(0, 1) \pmod r
$$

So to forge a signature for any given $M$, we simply let $x = 1$ and solve for $u$:

$$
\begin{aligned}
    x^2 &= H(M, u) \\
\implies x &= H(M, u) \qquad \text{since $x = 1$} \\
\implies x &= H(M, 0) + u H(0, 1) \\
\implies u &= H(0, 1)^{-1}(x - H(M, 0))
\end{aligned}
$$

Then, $(x, u)$ is a valid signature for $M$.

This attack doesn't need to use the signing oracle and shows that the signature scheme is completely broken when using this hash function. Pretty cool solution!

## Alternative Approach via Galois Theory

Alternatively, one might recognise the resemblance of the function $f$ with the Frobenius map $\phi : K \rightarrow K, x \mapsto x^r$ which is an $\mathbb{F}_r$-automorphism that generates the Galois group $G$ of $K/\mathbb{F}_r$. Note that $G$ is cyclic and of order $n$ as $\phi^n : K \rightarrow K, x \mapsto x^{r^n}$ is the identity map. The Fundamental Theorem of Galois Theory tells us that there is a one-to-one correspondence between the subgroups of the Galois group of $K$, and the intermediate fields of $K$. Explicitly, for a given subgroup $H$ of $G$, the corresponding intermediate field of $K$ is given by the fixed field $K^H$, the set of all elements in $K$ which are fixed by all of the maps in $H$. Another result, sometimes known as the Fixed Field Theorem, tells us that the order of $H$ is equal to the degree of $K$ as an extension of $K^H$. We use this, along with the fact that the subfields of $K$ are given by $\mathbb{F}_{r^d}$ where $d$ divides $n$, to find the fixed fields.

In the challenge, we have $n = 15$, so the Galois group $G$ is isomorphic to $\mathbb{Z}/15\mathbb{Z}$. The table below lists out the subgroups of $G$ and their corresponding intermediate fields ($\mathrm{id}$ denotes the identity map):

|Subgroup of $G$|Intermediate Field of $K$|
|---|---|
|$H_0 = \{ \mathrm{id} \}$|$K^{H_0} = K$ (all elements are fixed by $\mathrm{id}$)|
|$H_1 = \{ \mathrm{id}, \phi^5, \phi^{10} \}$|$K^{H_1} = \mathbb{F}_{r^5}$|
|$H_2 = \{ \mathrm{id}, \phi^3, \phi^6, \phi^9, \phi^{12} \}$|$K^{H_2} = \mathbb{F}_{r^3}$|
|$G$|$K^G = \mathbb{F}_r$ (only $\mathbb{F}_r$ is fixed by all automorphisms)|

From this, we can see that $\mathbb{F}_{r^3}$ is fixed by $\phi^3$.