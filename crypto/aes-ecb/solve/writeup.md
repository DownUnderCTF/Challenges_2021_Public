# Easily Can Break

## Discovering the Vulnerability

The included server code shows `AES-128-ECB` encryption oracle using the encryption key as padding.

```python
    key = open('key.txt', 'r').read().strip().encode() # my usual password

    ...

    cipher = AES.new(key, AES.MODE_ECB)
    ct = cipher.encrypt(pad(pt+key))
```

Since the key is used for padding and ECB mode creates identical ciphertext for repeated (plaintext, key) pairs, recovery of the key is possible.

## Developing the exploit

Connecting to the server returns the encrypted plaintext in base64. This comprises of `flag + input + key + pad`. Confirming with an empty input:
```python
Enter plaintext:
hHDUv8AMj0x84xv5DLAfnVkMtioxRT87gskSJLPCnICbxdZ2EbAlvdn8lZjYaWuV
```
Checking the length of the ciphertext shows it is three blocks:
```bash
echo 'hHDUv8AMj0x84xv5DLAfnVkMtioxRT87gskSJLPCnICbxdZ2EbAlvdn8lZjYaWuV' | base64 -d | xxd
00000000: 8470 d4bf c00c 8f4c 7ce3 1bf9 0cb0 1f9d  .p.....L|.......
00000010: 590c b62a 3145 3f3b 82c9 1224 b3c2 9c80  Y..*1E?;...$....
00000020: 9bc5 d676 11b0 25bd d9fc 9598 d869 6b95  ...v..%......ik.
```

As the server is `AES-128`, the key size must be 16 bytes, which is one block (16 bytes = 128 bits). This is guaranteed to be (at least partially) in the last block of the ciphertext. This reveals that the length of the flag is between 17-32 bytes, to produce a ciphertext of 3 blocks.

The idea is to send a plaintexts of a specific length that will be padded with some bytes of the key, which we can then determine the value of by comparing ciphertexts. 

This is best explained with an example for the first byte of the key:
```
Step 1: input 15 bytes of plaintext, e.g. 15*"A".
The ciphertext returned will be Encrypt(flag + 15*"A" + key + pad)
The third block of the ciphertext will then be Encrypt(15*"A" + key[0])

Step 2: Store the third block of ciphertext as "target"

Step 3: input 15*"A" + x, where x is a guess of a key byte

Step 4: compare the saved "target" with the third block of the ciphertext
Repeat step 3-4 for all possible values of x.
When they match, the first byte of the key has been successfully guessed

Repeat step 1, decrementing the number of "A"s to reveal each subsequent byte of the key
```

Once the key has been recovered, the ciphertext can be decrypted to reveal the flag.

## Execution: recovering the flag

Finding the key. Since the source file says the key is the password, the characters must be printable. This narrows the keyspace to ASCII:
```python
# each byte position in the block (16)
for i in range(16, 0, -1):
    partial = b"A"*(i-1)
    s.recvline()
    s.sendline(partial)
    b = s.recvline()
    target = get_block(b, 3)

    # each possible ascii byte value for that position
    for j in range(33, 127):
        k = bytes([j])
        s.recvline()
        s.sendline(partial + key + k)
        b = s.recvline()
        res = get_block(b, 3)

        # compare with padded output
        if res == target:
            key += k
            break
```

Now the key has been discovered, decrypt the ciphertext:

```
ct = b64decode("hHDUv8AMj0x84xv5DLAfnVkMtioxRT87gskSJLPCnICbxdZ2EbAlvdn8lZjYaWuV")
cipher = AES.new(key, AES.MODE_ECB)
flag = cipher.decrypt(ct)
flag{ECB_M0DE_K3YP4D_D474_L34k5}
```
Solved.

