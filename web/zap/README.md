# Zap

**Category**: Web

**Difficulty**: Easy - Medium

**Author**: todo#7331

## Flavour

I recently built a small zip application as a service and I was wondering if you could pen-test it for me. It's still in beta and a bit unstable at the moment so don't feel afraid to restart the machine!

## Description

**This challenge uses per-team containers**

This challenge is a relatively straightforward parameter pollution? -> prototype pollution -> argument injection -> rce. Players can post to a endpoint which will call the `zip` command in order to compress a file specified by the player.

This challenge, whilst built for players, is also intended as a POC of per-team-containers for next year. If another challenge actually requires per-team-containers do not include this challenge.

## Writeup

_A solve script can be found in ./solve_

1. Players look through the source code to see the `nested-object-assign@1.0.3` this version is vulnerable to a prototype pollution vuln.
2. Players realised they need to set `Object.prototype.extra_opts` to be an array of extra opts in order to argument inject the `zip` command.
3. Notably zip takes the `--unzip-command <command>` argument which when called with `--test` will execute the command, subsituting `{}` for the name of zip archive.
4. Whilst it initially seems difficult to pass a javascript object / array to trigger the prototype pollution with, it turns out multer's body parser will automagically assemble complex javascript objects if parameters are specified in a certain format
   1. I.e. posting `a[k2]=1 a[k2]=2` will result in the `{a: {k1: 1, k2: 2}}` object being assembled
   2. I.e. posting `a[0]=1 a[1]=2` will result in the `{a: [1, 2]}` array being assembled
5. We can hence use this behaviour to construct a pollution payload
   1. `__proto__[extra_opts][0]=-T`
   2. `__proto__[extra_opts][1]=-TT`
   3. `__proto__[extra_opts][2]=ls > {} #` Here the `{}` will be replaced by the archive name allowing us to exfil easily, the `#` is nessecary to prevent `zip` from passing us a extra unwanted arg.
6. We can then `ls /` to find `flag.txt` and `cat` it to win.

## Running

`docker-compose up --build`

This challenge should not be shared between teams.

- prototype pollution will effect everyone, and since it persists everyone's chal will break
- this has rce and is intentionally very weakly hardened
