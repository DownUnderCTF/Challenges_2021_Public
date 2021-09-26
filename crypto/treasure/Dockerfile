FROM ghcr.io/downunderctf/docker-vendor/nsjail:ubuntu-21.04

RUN pip install pycryptodome

COPY ./challenge/flag.txt /home/ctf/chal/
COPY ./challenge/secret.py /home/ctf/chal/
COPY ./challenge/treasure.py /home/ctf/chal/pwn
