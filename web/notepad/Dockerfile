FROM python:3.9-slim

RUN pip install --no-cache-dir quart quart-rate-limiter aioredis requests uvicorn[standard] gunicorn

WORKDIR /srv
COPY ./src/ /srv/
COPY ./flag.txt /srv/

ENTRYPOINT [ "gunicorn", "-b", "0.0.0.0:5000", "-k", "uvicorn.workers.UvicornWorker", "app:app" ]