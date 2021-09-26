FROM python:3

RUN apt-get update && \
    apt-get install -y iproute2 && \
    rm -rf /var/lib/apt/lists/*

COPY ./challenge /app

COPY ./requirements.txt /requirements.txt

RUN /usr/bin/touch /var/log/request-proxy.log

RUN pip install -r /requirements.txt

CMD ["/usr/local/bin/python", "-u" ,"/app/main.py"]