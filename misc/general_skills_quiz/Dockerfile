FROM ghcr.io/downunderctf/docker-vendor/nsjail:ubuntu-18.04

COPY /challenge/challenge.py /home/ctf/chal/pwn
COPY /challenge/wordlist.10000 /home/ctf/chal/wordlist.txt

RUN chmod +x /home/ctf/chal/pwn

ENV TIME_LIMIT 30