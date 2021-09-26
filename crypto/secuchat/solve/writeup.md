# Solution
Sift through combinations of the population of RSA keys until a common prime is found (this is improbable in the wild, but is infinitely easier than factoring, see [Ron was wrong, Whit is right](https://eprint.iacr.org/2012/064.pdf).

From the challenge description and database schema infer the crypto scheme used in the chat, that is, shared keys for AES-256-CBC encrypted with RSA and OAEP.

Decrypt the messages one by one until the flag is found.
