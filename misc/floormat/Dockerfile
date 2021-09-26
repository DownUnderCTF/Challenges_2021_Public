FROM ghcr.io/downunderctf/docker-vendor/nsjail:ubuntu-18.04

WORKDIR /home/ctf
COPY ./src/flag.txt chal/
COPY ./src/floormat.py chal/pwn
RUN chmod +x /home/ctf/chal/pwn
