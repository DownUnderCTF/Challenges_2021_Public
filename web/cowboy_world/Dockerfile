FROM python:3.9-slim

COPY ./requirements.txt /app/requirements.txt

WORKDIR /app

RUN pip3 install -r requirements.txt

COPY ./challenge /app/

CMD ["gunicorn", "-w", "2", "-b", "0.0.0.0:5000", \
    "--access-logfile", "-", \
    "--access-logformat", "%({x-forwarded-for}i)s %(l)s %(u)s %(t)s \"%(r)s\" %(s)s %(b)s \"%(f)s\" \"%(a)s\"", \
    "--forwarded-allow-ips=*", "app:app"]
