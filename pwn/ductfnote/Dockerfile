FROM ghcr.io/downunderctf/docker-vendor/nsjail:ubuntu-21.04

RUN apt update && apt install patchelf -y && rm -rf /var/lib/apt/lists/*

COPY ./challenge/libc-2.31.so /home/ctf/chal/libc.so.6
COPY ./challenge/ld-2.31.so /home/ctf/chal/ld-2.31.so
COPY ./challenge/flag.txt /home/ctf/chal/flag.txt
COPY ./challenge/ductfnote /home/ctf/chal/pwn
RUN patchelf --set-rpath /chal/ --set-interpreter /chal/ld-2.31.so /home/ctf/chal/pwn
