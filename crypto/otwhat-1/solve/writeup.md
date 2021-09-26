As the flag shows, this is a known signing failure of early versions of the Wii software.

The first mistake is the use of `strcmp`, as this C function considers strings, it terminates at a null byte as C strings are null-terminated.
The attack exploits this by having the actual hash and the hash from the signature start with a null byte, such that according to `strcmp`, both "strings" are zero-length, and are hence equivalent.

```
while not hash_found:
    padding = randbytes(2)
    url = "https://EVILCODE/" + padding
    digest = SHA3_512(url)
    hash_found = digest[0] == 0
```

The player is expected to derive the hash function by analysing the sample signature provided by the web app; the public key is in the HTML source, and decrypted signature carries padding, and then a DER-encoded hash indicated to be SHA3-512.


Forging a signature would be difficult if not for the second mistake; there are no checks to see if the decrypted signature has valid padding. This is alluded to in the "debug" section of the HTML source code:
```
update.c:69:main(): strcmp(hash, &decrypted_signature[512 - 64]) = ...
```
Meaning, we just need a signature, such that s ^ e mod n has the 448th byte as zero.
```
forged_signature = random.randbytes(256)
while pow(int.from_bytes(forged_signature, "big"), key.e, key.n).to_bytes(key.size_in_bytes(), "big")[-64] != 0:
    forged_signature = random.randbytes(256)
```
