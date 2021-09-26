FROM node:16-slim as base
FROM base as build
WORKDIR /build

COPY ./package*.json .
COPY ./yarn.lock .
RUN yarn install --frozen-lockfile

FROM base as dist

RUN groupadd -g 1001 -r ctf && useradd -u 1001 --no-log-init -r -g ctf ctf

RUN apt-get update \
  && apt-get install --no-install-recommends -y zip iptables \
  && rm -rf /var/lib/apt/lists/*

COPY ./flag.txt /

WORKDIR /srv

USER ctf
COPY --from=build /build/node_modules/ ./node_modules/
COPY ./src/ ./

ENTRYPOINT [ "node", "/srv/app.js" ]
