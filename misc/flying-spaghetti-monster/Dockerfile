FROM ghcr.io/downunderctf/docker-vendor/nsjail:ubuntu-21.04

COPY ./challenge/requirements.txt /home/ctf/chal/
RUN pip install -r /home/ctf/chal/requirements.txt

COPY ./challenge/fsm.py /home/ctf/chal/
COPY ./challenge/fsm.txt /home/ctf/chal/
COPY ./challenge/canned.json /home/ctf/chal/
COPY ./challenge/flag.txt /home/ctf/chal/
COPY ./challenge/server.py /home/ctf/chal/
COPY ./challenge/pow.py /home/ctf/chal/
COPY ./challenge/entry.sh /home/ctf/chal/pwn

ENV TIME_LIMIT 300
ENV CPU_SHARES_MS=300
