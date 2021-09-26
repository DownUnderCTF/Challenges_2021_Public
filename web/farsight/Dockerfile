FROM node:16 as base
FROM base as build

WORKDIR /build
COPY ./package*.json ./
COPY tsconfig.json .
COPY src src

RUN npm install
RUN npx tsc --build

FROM base as dist

WORKDIR /srv
COPY --from=build /build/package.json /srv/
COPY --from=build /build/node_modules/ /srv/node_modules/

COPY ./src/assets/ /srv/app/assets/

COPY --from=build /build/build/ /srv/app/
COPY ./frontend /srv/frontend

ENTRYPOINT [ "node", "app/app.js" ]
