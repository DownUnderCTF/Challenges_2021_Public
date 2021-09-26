As the flag heavily references the OG talk, this is a known cryptographic failure of PS3 signed software, with the use of a static k.

In order to recover the private key, two signatures with identical `r` and the order of the curve used is required.
The web service provides an "Update audit log", providing update URLs and correlating OEM signatures. The signatures are PEM-encoded ASN.1 sequences containing just two integers, r and s.
Once the player has identified signatures with an identical `r`, they must also identify the hashing algorithm used so that they recover the `z` (leftmost bits of a digest).
The HTML source has a `DEBUG` section providing the resulting hash digest, which is 512-bit. After identifying the hash to be 512-bit, the player can then recover the private key.

Note: calculations below are done in modulo `n`, where `n` is the order of the P-256 curve.
The two `z` variables must be recovered by using the hashing algorithm and taking its leftmost 256 bits:
```
bytes_to_long(SHA3_512(url)) >> 256
```
These `z` variables can then be used with the two `s` variables from the identified signatures to recover the nonce `k`:
```
k = (z1 - z2) / (s1 - s2)
```
The private key `d` can now be calculated using one of signatures and its `k`:
```
d = ((s * k) - z) / r
```

All the player has to do now is specify the scalar `d` when constructing a `secp256r1` key, and then sign the URL `https://EVILCODE/` using ECDSA.
