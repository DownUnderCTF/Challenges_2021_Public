FROM tiangolo/uwsgi-nginx-flask:python3.8

ENV LISTEN_PORT 1337

EXPOSE 1337

RUN pip3 install pycryptodome

COPY challenge/app/main.py /app
COPY challenge/app/secp256r1.key /app
COPY challenge/app/update.log /app
