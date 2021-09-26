#!/usr/bin/python3

# writing this was kinda hard, works for the testing env
# reference: https://www.cse.scu.edu/~tschwarz/coen252_07Fall/Lectures/FAT.html

from time import sleep
from sys import stderr
from os import environ
from socket import socket, AF_INET6, SOCK_DGRAM
from pwn import p32, u8, u16, u32
from ipaddress import ip_address
from typing import List

MAX_BYTES_PER_MESSAGE = 64
MAX_RETRIES = 10
BYTES_PER_WORD = 4
PORT = 1337
BASE_IP = ip_address('2600:1900:4120:5fb8::')
DEBUG = not not environ.get('DEBUG')



def get_word(base_ip: ip_address, sock: socket, data: List[int], offset: int) -> bytearray:
    # use the first data entry to store the count of network calls
    if offset + 1 < len(data) and data is not None:
        return data[offset + 1]
    ip = str(base_ip + offset)
    sock.sendto(b'', (ip, PORT))

    addr = ('', 0, 0, 0)
    retries = 0
    while addr[0] != ip and retries < MAX_RETRIES:
        if DEBUG: print('getting word at offset', offset, file=stderr)
        if retries > 0:
            print("waiting to retry offset", offset, file=stderr)
            sleep(5)
        
        packet, addr = sock.recvfrom(MAX_BYTES_PER_MESSAGE)

        if int(packet) == -1:
            addr = ('', 0, 0, 0)
        retries += 1
    
    if retries > MAX_RETRIES:
        raise RuntimeError("could not get word at", ip)
    
    if offset + 1 >= len(data):
        data += [None for _ in range(offset - len(data) + 2)]
    
    data[offset + 1] = p32(int(packet))
    data[0] += 1
    return data[offset + 1]

def get_data(base_ip: ip_address, sock: socket, data: List[int], offset: int, length: int) -> bytearray:
    if offset < 0:
        raise ValueError("offset has to be greater than or equal to 0")
    if length <= 0:
        raise ValueError("length has to be greater than 0")

    of_start = offset // BYTES_PER_WORD
    of_end = (offset + length) // BYTES_PER_WORD
    b_start = offset % BYTES_PER_WORD
    b_end = (offset + length) % BYTES_PER_WORD
    words = []
    for i in range(of_start, of_end + 1):
        words.append(get_word(base_ip, sock, data, i))

    
    if len(words) == 1:
        return words[0][b_start:b_end]

    return b''.join([words[0][b_start:]] + words[1:-1] + [words[-1][:b_end]])

def solve():
    data = [0]
    sock = socket(AF_INET6, SOCK_DGRAM)
    sock.bind(('', 0))

    mauf = get_data(BASE_IP, sock, data, 0x3, 8)
    print('mauf', mauf)

    bytes_per_sector = u16(get_data(BASE_IP, sock, data, 0xb, 2))
    print('bytes_per_sector', bytes_per_sector)

    sectors_per_cluster = u8(get_data(BASE_IP, sock, data, 0xd, 1))
    print('sectors_per_cluster', sectors_per_cluster)

    fats = u8(get_data(BASE_IP, sock, data, 0x10, 1))
    print('fats', fats)

    roots = u16(get_data(BASE_IP, sock, data, 0x11, 2))
    print('roots', roots)

    sectors_per_fat = u16(get_data(BASE_IP, sock, data, 0x16, 2))
    print('sectors_per_fat', sectors_per_fat)
    
    n_hidden_sectors = u32(get_data(BASE_IP, sock, data, 0x1c, 4))
    print('n_hidden_sectors', n_hidden_sectors)

    n_sectors = u32(get_data(BASE_IP, sock, data, 0x20, 4))
    print('n_sectors', n_sectors)

    label = get_data(BASE_IP, sock, data, 0x2b, 11)
    print('label', label)

    #fat = get_sector(BASE_IP, sock, data, bytes_per_sector, sectors_per_cluster)
    #print(fat)
    #root = get_sector(BASE_IP, sock, data, bytes_per_sector, sectors_per_cluster + (sectors_per_fat * 2))
    fat_start = sectors_per_cluster * bytes_per_sector
    root_dir_start = (sectors_per_cluster + (sectors_per_fat * fats)) * bytes_per_sector

    # list files and find FLAG.txt ()
    for i in range(bytes_per_sector // 32):
        ent = get_data(BASE_IP, sock, data, root_dir_start + (i*32), 32)
        filename = ent[:8]
        if filename == b'\x00' * 8:
            break
        filename = filename.decode('ascii', 'ignore')
        print('filename', filename)

        ext = ent[8:8+3]
        print('ext', ext)

        first_cluster = u16(ent[0x1a:0x1a + 2])
        print('first_cluster', first_cluster)

        size = u32(ent[0x1c:0x1c + 4])
        print('size', size)

        print()

        if 'FLAG' in filename:
            break
    
    # look for the flag in the FAT
    # probably unneeded since its a small file
    # clus_fat = get_data(BASE_IP, sock, data, fat_start + 2*first_cluster, 2)
    # look up the cluster straight away
    cluster_start = root_dir_start + ((first_cluster + 2) * sectors_per_cluster * bytes_per_sector)
    print(get_data(BASE_IP, sock, data, cluster_start, size))

    print('network calls made:', data[0])


if __name__ == '__main__':
    solve()

