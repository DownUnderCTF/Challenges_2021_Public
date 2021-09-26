FROM ghcr.io/downunderctf/docker-vendor/nsjail:ubuntu-21.04

RUN pip install pycryptodome

COPY ./challenge/flag.txt /home/ctf/chal/
COPY ./challenge/key.txt /home/ctf/chal/
COPY ./challenge/aes-ecb.py /home/ctf/chal/pwn
