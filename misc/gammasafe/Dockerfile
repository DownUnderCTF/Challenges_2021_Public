FROM ghcr.io/downunderctf/docker-vendor/nsjail:ubuntu-18.04

COPY ./challenge/flag.txt /home/ctf/chal/
COPY ./challenge/server.py /home/ctf/chal/pwn
RUN chmod +x /home/ctf/chal/pwn
