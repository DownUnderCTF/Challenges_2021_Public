FROM python:3.9-slim-buster AS base

FROM base AS build

COPY requirements.txt /tmp/requirements.txt

ENV VIRTUAL_ENV="/opt/venv"
ENV PATH="$VIRTUAL_ENV/bin:$PATH"

RUN python3 -m venv "$VIRTUAL_ENV" \
 && pip install -r /tmp/requirements.txt


FROM base AS dist

RUN groupadd -g 1000 -r ctf && useradd -u 1000 --no-log-init -r -g ctf ctf
USER ctf

ENV VIRTUAL_ENV="/opt/venv"
ENV PATH="$VIRTUAL_ENV/bin:$PATH"

COPY --from=build /opt/venv "$VIRTUAL_ENV"

WORKDIR /srv
COPY ./src /srv

EXPOSE 1337/tcp

ENTRYPOINT [ "uvicorn", "app:app" ]
CMD [ "--host", "0.0.0.0", "--port", "1337", "--workers", "2", "--forwarded-allow-ips=*", "--proxy-headers" ]

