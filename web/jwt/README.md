# JWT

**Author:** 247CTF.com

**Category:** Web

**Difficulty:** ?

_Everyone knows you can offline brute force HS256. Is RS256 vulnerable too?_

## Description
When accessing the application URL, you are provided with the source code. 

The application has 2 routes - one to get a token and the other to get a flag.

The token received sets your admin status as false - to get the flag you need a token which sets your admin status to true.

The token is making use of RS256 and the public key is not disclosed - however the key can be derived from the tokens.

Once derived, it can be noted that the public key is 'small' (773 bits) and can be factored.

Once factored, the private key can be created and a token with the admin status set to true can be forged.

## Writeup
1. Get two JWT tokens (`curl 127.0.0.1:5000/get_token`)
2. Derive the public key (https://github.com/silentsignal/rsa_sign2n)
3. Extract the modulus (`openssl rsa -pubin -in blah -modulus`)
4. Factor the modulus (`./msieve -q blah`)
5. Create the private key (https://github.com/ius/rsatool)
6. Forge a token (`import jwt;private_key=open('priv').read();token=jwt.encode({'admin':True},private_key,algorithm='RS256')`)
7. Grab the flag (`curl -X POST -d "jwt=blah" http://127.0.0.1:5000/get_flag`)
