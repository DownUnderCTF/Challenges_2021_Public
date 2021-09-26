BEGIN;

DROP TABLE IF EXISTS page_ref;
DROP TABLE IF EXISTS page;
DROP TABLE IF EXISTS site;
DROP TABLE IF EXISTS "user";

CREATE TABLE "user" (
    id SERIAL PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    password TEXT NOT NULL
);

CREATE TABLE site (
    id SERIAL PRIMARY KEY,
    name   TEXT    NOT NULL,
    public BOOLEAN NOT NULL,
    config TEXT    NOT NULL,
    owner  INTEGER NOT NULL REFERENCES "user"(id)
);

CREATE TABLE page (
    id SERIAL PRIMARY KEY,
    name    TEXT    NOT NULL,
    content TEXT    NOT NULL,
    site    INTEGER NOT NULL REFERENCES site(id)
);

CREATE TABLE page_ref (
    site INTEGER NOT NULL REFERENCES site(id),
    page INTEGER NOT NULL REFERENCES page(id)
);

COMMIT;