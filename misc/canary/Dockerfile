FROM ghcr.io/downunderctf/docker-vendor/bin-builder:ubuntu-18.04 AS build
COPY ./publish/canary.c /build/
RUN gcc -o /build/pwn /build/canary.c

FROM ghcr.io/downunderctf/docker-vendor/nsjail:ubuntu-18.04
COPY --from=build /build/pwn /home/ctf/chal/pwn
COPY nsjail.cfg /home/ctf/
COPY flag.txt /home/ctf/chal/
EXPOSE 1337/tcp
