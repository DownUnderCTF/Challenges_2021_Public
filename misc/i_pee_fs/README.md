# i-pee fs

**Category**: misc

**Difficulty**: Easy - Medium

**Author**: dot

**Flavor Text**: _I'm currently working on a new project called i-pee fs, which can be hosted on your average run of the mill potato. Don't mash it too hard..._

## Description
This challenge involves burning a lot of IPv6 addresses.

## Writeup
> will add a solve script.

I haven't tried solving this one yet, but in theory it's possible.

Each IPv6 address which is part of the prefix hosts a different number. When you hit the endpoint, it will send back a UDP packet with
a 32-bit integer in ASCII. By iterating through IPv6 addresses, you should be able to see that the hidden message is in fact a FAT
filesystem with some garbage files taking most of the space.

There are also some rate limits applied too make the challenge more difficult, players wil only be able to request a maximum of 1024
numbers (4096 bytes) per minute per /56. The rate limiter will return -1 for the rest of the minute when it has been reached.

Therefore, a player should use their knowledge of the filesystem in order to traverse it efficiently and find the file with the flag.

I guess some competitors could get their hands on a /48 and use that to brute force as an unintended solution, but also the server
might break if that happens...


## Setup
This will be hosted on a separate box as it requires some special IPv6 configuration.

1. Compile the go.
2. Run generate.sh to generate the filesystem image
3. Add the IP to the loopback table `sudo ip -6 route add local <prefix>::/96 dev lo`
4. Start the challenge.
