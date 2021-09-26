import os
os.environ['PWNLIB_NOTERM'] = 'True'
from pwn import *
from parse import parse

FAKE_COORDS = 5754622710042474278449745314387128858128432138153608237186776198754180710586599008803960884
p = 13318541149847924181059947781626944578116183244453569385428199356433634355570023190293317369383937332224209312035684840187128538690152423242800697049469987
F = Zmod(p)

conn = remote('0.0.0.0', 1337)
s3 = list(parse('Your share is: {:d}\n', conn.recvline().decode()))[0]
conn.sendlineafter(': ', '1')

s2s3_inv = list(parse('The secret is revealed: {:d}\n', conn.recvline().decode()))[0]
fake_share = F(FAKE_COORDS / s2s3_inv).nth_root(3)
conn.sendlineafter(': ', str(fake_share))

real_coords = pow(s3, 3, p) * s2s3_inv
conn.sendlineafter(': ', str(real_coords))

print(conn.recv().decode())
