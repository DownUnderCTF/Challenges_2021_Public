# Challenge Overview

We are tasked with cheating as a participant of a secret sharing scheme. A secret value is split into three shares and we are given one of them. We are able to run the share combiner once and we will be given the output for it. Then, we must send a share to the combiner again to forge a specific output, and finally, we must send the server the real secret.

## Secret Sharing Scheme

The secret sharing scheme in the challenge is very simple. Notably, it is also not _verifiable_, so it is relatively easy to cheat.

The scheme splits a secret into three shares and requires all three to recover the secret. Let $p$ be a prime number and let $s$ be the secret. The dealer chooses two random numbers $1 < r_1, r_2 < p$ and computes the three shares:

$$
\begin{aligned}
    s_1 &\equiv r_1 r_2 s \pmod p \\
    s_2 &\equiv r_1^2 r_2 s \pmod p \\
    s_3 &\equiv r_1 r_2^2 s \pmod p
\end{aligned}
$$

To combine three shares $(s_1, s_2, s_3)$, the combiner computes

$$
s \equiv \frac{s_1^3}{s_2 s_3} \pmod p
$$

(you should check for yourself that this computes the correct secret if the shares are correct!). Note that when we divide by $s_2 s_3$ here, we are actually multiplying by the [modular multiplicative inverse](https://en.wikipedia.org/wiki/Modular_multiplicative_inverse) of $s_2 s_3$ modulo $p$.

## Cheating

We control $s_1$, so how can we use this to both reveal the secret to only us, and also to forge a fake secret $s'$?

### Faking a Secret

The first time we send our shares to the combiner, we are able to send almost anything and somehow convince our friends everything is fine. We use this to gain some information that will help us to fake a secret.

Let's consider what happens if we send $s_1 = 1$ as our share to the combiner. The combiner will compute and give us

$$
\frac{1}{s_2 s_3} \pmod p
$$

This is useful to us, because if we want to send another share $s_1'$ to the combiner such that the revealed secret is $s'$, all we need to do is compute $s_1'$ as follows:

$$
\begin{aligned}
    s' &\equiv \frac{(s_1')^3}{s_2 s_3} \pmod p \\
    \implies (s_1')^3 &\equiv s' s_2 s_3 \pmod p \\
    \implies s_1' &\equiv (s' s_2 s_3)^{\frac{1}{3}} \pmod p
\end{aligned}
$$

Note that here, $(s' s_2 s_3)^{\frac{1}{3}}$ means the modular cube root of $s' s_2 s_3$ modulo $p$, that is, a number which equals to $s' s_2 s_3$ when cubed and reduced modulo $p$. There are algorithms online that may help to compute this, and SageMath also has inbuilt functionalities for this.

### Revealing the Real Secret

We already have everything we need to reveal the real secret. We have $\frac{1}{s_2 s_3} \pmod p$ from the first time running the combiner, so all we need to do is use our real share and compute

$$
s \equiv \frac{s_1^3}{s_2 s_3} \pmod p
$$

Sending this to the server gets us the flag :)
