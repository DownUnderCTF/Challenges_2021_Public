# deadcode solution
## Solving the challenge
### Identify the vulnerability
The source code wasn't provided for the challenge requiring the use of a decompiler or disassembler such as Ghidra, radare, ida or objdump. After reverse engineering the binary, it is evident through the use of the unsafe function `gets` in combination with a fixed size char array `feature[16]` that the code is vulnerable to a buffer overflow.

The binary features a section of code that isn't reachable through normal execution which is called 'deadcode', it's here that the system calls '/bin/sh' which spawns a bin shell. This is referenced in the challenge description by noting the "code isn't (a)live yet". 

### Exploit time
After identifying the value we need to set `long code` to access the deadcode and the size of the char array that the gets stores its value in (16 chars/bytes), we can start to build our exploit. By using 16 'A's we can fill the char array, then we have to overwrite the base pointer (RBP) which is 8 bytes, we can use 8 'B's to denote this. Finally, in little endian format we can overwrite the long variable `code` stored on the stack, this is: \xde\xc0\xad\xde. 

Piecing this all together, we get `AAAAAAAAAAAAAAAABBBBBBBB\xde\xc0\xad\xde`. This can either be put into a solve script or exploited using echo as shown below.

## Exploit:
Local execution:

```
(echo -e "AAAAAAAAAAAAAAAABBBBBBBB\xde\xc0\xad\xde";cat)  | ./deadcode
```

Remote execution:

```
(echo -e "AAAAAAAAAAAAAAAABBBBBBBB\xde\xc0\xad\xde";cat) | nc <host> <port>
```
