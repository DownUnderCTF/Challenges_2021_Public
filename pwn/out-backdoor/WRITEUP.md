# outBackdoor solution
## Solving the challenge
### Identify the vulnerability
The source code wasn't provided for the challenge requiring the use of a decompiler or disassembler such as Ghidra, radare, ida or objdump. After reverse engineering the binary, it is evident through the use of the unsafe function `gets` in combination with a fixed size char array `feature[16]` that the code is vulnerable to a buffer overflow.

The binary features a seperate function `outBackdoor` in the code that isn't reachable through normal execution which is called 'deadcode', it's here that the system calls '/bin/sh' which spawns a bin shell. In order to reach code, we need to use ROP.

### Exploit time
Using objdump, we can disassemble the binary and locate the address of the function `outBackdoor` which is `00000000004011d7`. After identifying the size of the char array that the `gets` stores its value in (16 chars/bytes), we can start to build our exploit. By using 16 'A's we can fill the char array, then we have to overwrite the base pointer (RBP) which is 8 bytes, we can use 8 'B's to denote this. 

As documented below in the sidenote section, I was able to form an exploit at this stage on my local machine however not on the remote machine due to a common pitfall when doing ROP which is believed to be the 'MOVAPS' issue. On my local machine, I could then overwrite the return address of the `main` function with the address of the `outBackdoor` function, this is 4011d7. However to workaround this issue on other hosts, you need to add a ROP/RET gadget to the exploit chain to align the stack. From the disassembly, we can identify a `ret` instruction in another function, in this case, in the `_init` function there is the `retq` instruction shown below:
`401016:  c3    retq`

The `retq` instruction pops a qword off the top of the stack and jumps to that address, so we can combine this address (401016) with some padding (5 bytes worth) and finally the address of the outBackdoor (4011d7) function we found earlier which will be jumped to after the the `retq` instruction in `_init` is executed.

Piecing this all together in little endian format, we get `AAAAAAAAAAAAAAAABBBBBBBB\x16\x10\x40\x00\x00\x00\x00\x00\xd7\x11\x40`. This can either be put into a solve script or exploited using echo as shown below.

Working exploit (on most hosts):

```
(echo -e "AAAAAAAAAAAAAAAABBBBBBBB\x16\x10\x40\x00\x00\x00\x00\x00\xd7\x11\x40"; cat;) | nc 0.0.0.0 1337
```

Alternative exploit (only works on some hosts):

```
(echo -e "AAAAAAAAAAAAAAAABBBBBBBB\xd7\x11\x40\x00\x00"; cat;)  | ./outBackdoor
```

### Sidenote
When testing this challenge on my local machine, the below exploit works perfectly and pops a shell. However when doing remote testing, one of the challenge reviewers noted that the below exploit wasn't working. They were very helpful in finding and explaining why this was the case, so big shoutout to them! They know who they are! :)
