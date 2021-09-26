FROM tiangolo/uwsgi-nginx-flask:python3.8

RUN pip3 install pyjwt[crypto]

COPY ./challenge/chall.py /app/main.py
COPY ./challenge/priv /app/priv
COPY ./challenge/pub /app/pub
COPY ./challenge/flag.txt /app/flag.txt
