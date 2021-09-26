#/usr/bin/env python3
import collections
import subprocess
import time
import re

import networkx
import pwn
import sympy
import yarl

import fsm

x = sympy.symbols("x")

def get_coeffs(f):
    c = f.subs(x, 0)
    p = f.subs(x, 1) - c
    return p, c

def walk(g, al, c):
    for bl, zz, ed in g.in_edges(al, data=True):
        assert zz == al
        p_, c_ = get_coeffs(ed["f"])
        if c - c_ == 0:
            yield ed["n"]
            return
        q, r = divmod(c - c_, p_)
        if r == 0:
            try:
                yield from walk(g, bl, q)
            except GeneratorExit:
                pass
            else:
                yield ed["n"]
                return
    else:
        raise GeneratorExit

def solve(g, f, sf):
    a, c = get_coeffs(f)
    ts = time.time()
    r = "".join(chr(e) for e in walk(g, sf, c))
    te = time.time()
    pwn.log.info(f"solve took {te - ts} seconds")
    return r

# Set up the server and load our graph at the same time since it's slow
pwn.context.log_level = "debug"
pwn.context.timeout = 2
if pwn.args.HOST:
    u = yarl.URL(pwn.args.HOST)
    assert u.scheme == "tcp", "Use tcp://host:port"
    t = pwn.remote(u.host, u.port)
    G = fsm.FSM.load(open("../challenge/fsm.txt")).g
else:
    # run in challenge/ dir to test solve locally
    t = pwn.process(["python", "./server.py"])
    G = fsm.FSM.load(open("./fsm.txt")).g

# Wait until the server is good to go
has_pow = t.recvline_contains((
    b"Are you ready to achieve enlightenment?",
    b"== proof-of-work: enabled =="
))
if "proof-of-work: enabled" in has_pow.decode("ascii", "ignore"):
    pwn.log.info("pow detected: solving pow")
    pow = (t.recvline_contains(b"python3")
        .decode("ascii", "ignore")
        .strip()
        .split()[-1])
    s = pwn.process(["../challenge/pow.py", "solve", pow])
    s.recvline_contains(b'Solution:\n')
    s.recvline()
    t.sendline(s.recvline()[:-1])
    t.recvline_contains(b"Are you ready to achieve enlightenment?")

STATE_DELIM = b" -> "
while True:
    # Wait for lines with " -> " in them
    l = t.recvline()
    if not l or STATE_DELIM not in l:
        continue
    pwn.log.info("Need to solve %s", l)
    fe, sf = l.split(STATE_DELIM)
    f, sf = sympy.Poly(fe.decode()), int(sf)
    d = solve(G, f, sf)
    pwn.log.info("Decoded %s", d)
    try:
        t.sendline(d.encode())
    except EOFError:
        pwn.log.info("Server closed the connection")
        break
    except TimeoutError:
        if i == 0:
            continue
        raise
assert "DUCTF{" in d, d
