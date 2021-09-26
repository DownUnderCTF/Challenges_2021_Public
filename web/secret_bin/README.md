# Secrets Bin

**Category**: Web

**Difficulty**: Easy - Medium

**Author**: todo#7331

**Flavor Text**: _Since everyone loves dumping their secrets into pastebin, I decided to make a dedicated service for it instead! I've added few secrets myself to inflate our marketing numbers, I wonder if you can find them._

## Description

UUIDv1s are predictable, this challenge essentially involves identifying that fact and using it to IDOR some secrets.

## Writeup

_A solve script can be found in ./solve_

UUIDv1 is composed of a timestamp, clock_seq, and node_id, these are predictable values and if a timestamp is known the expected search size is generally very small.
Specifically the UUID construction looks like.
```
E.g.    bdd28aba-f461-11eb-8a53-00155d1c46cb
Format: TTTTTTTT-TTTT-1TTT-CCCC-NNNNNNNNNNNN

1 -> Literal 1 (identifies version)
T -> Timestamp (60 bits) = 1ebf461bdd28aba
C -> Clock Seq (14 bits) = 8a53
N -> Node Id   (48 bits) = 00155d1c46cb
```
We will attempt to find interesting timestamps, then the set of clock_seqs and node_ids. We can futher use this information to construct valid uuids to fetch secrets.

1. We notice the presence of a `/api/stats` endpoint which gives high precision timestamps when a few secrets were created. These will be mapped to the `T` section of the uuid.
2. We can then create a large number of secrets to try and identify `clock_seq` and `node_ids`, after hitting this endpoint a few times, we notice we have 4 possible values.
```
CCCC-NNNNNNNNNNNN
8421-00155d1c46cb
8b1e-0401b7194601
880f-000d3acaef36
bb4c-0050568f00a9
```
3. We can construct a UUID using this information with 4 possible guesses for each timestamp we initially identified.
4. We try to get the secrets associated with these uuids, as there is no auth we will be able to retrieve the secret if our guess is valid.
5. Our flag is one of these secrets.


## Running
`docker-compose up`
