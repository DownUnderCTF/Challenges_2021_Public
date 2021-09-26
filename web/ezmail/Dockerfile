FROM python:3.9-slim

WORKDIR /app

RUN pip install --no-cache-dir fastapi uvicorn[standard] aioredis ldap3 python-jose gunicorn slowapi

COPY ./src /app

ENTRYPOINT [ "gunicorn", "-b", "0.0.0.0:8000", "-k", "uvicorn.workers.UvicornWorker", "main:app" ]
