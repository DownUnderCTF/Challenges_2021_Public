# Canary

**Author:** 247CTF.com

**Category:** misc

**Difficulty:** Moderate

_Can you sneak the secret CTF code past the canary hidden in the challenge mine?_

## Description
The challenge requires you to set a specific string in a buffer. If the string is set in the correct location, you receive the flag.

However, a canary value is also set _before_ the string and if the canary value is not valid, you won’t receive the flag.

In order to write the string at the specific location, you first need to overwrite the canary - which means you need to know the canary's value in order to solve the challenge.

The canary is calculated on each request based on the RC4 algorithm (initialised with a random, unpredictable key).  To generate the canary - for each request, RC4 is called on 2 buffers of zero'd memory.

The RC4 algorithm has a bug - the swap function uses xor swap, however there is no check to verify whether the input pointers are equal.

If they are equal, the output will not result in a swap - but in the values being zero'd out.

After _enough_ calls to RC4 with this bug, the first 16 bytes of the RC4 sbox will become zero - which means the canary will also be zero and is therefore predictable (`x ^ x == 0` for any `x`).

## Writeup
A solve script can be found in ./solve

1. Send _enough_ requests to the service to zero out the RC4 sbox
2. _Predict_ the canary (`\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00`)
3. Send the canary and the 247DUCTF string _after_ the canary

## Setup
**Files to be provided:**

* `canary`
* `canary.c`

The following file(s) in the `publish/` directory must be executable:

* `canary`
