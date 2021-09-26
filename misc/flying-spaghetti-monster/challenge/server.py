#!/usr/bin/env python3
import base64
import inspect
import json
import random
import signal
import string
import threading

import fsm

FLAG = open("flag.txt", "r").read().strip()
FLAG_TEXT = f"""
<:) {FLAG}
We know a great deal about the properties of gravity, yet we know nothing about
the cause of the force itself. Why are particles attracted to one other? If we
review the literature, we find a lot of material dealing with the properties of
gravity, but very little dealing with the underlying cause of this attraction.
Until we have a proven answer to this question, it seems irresponsible to
instruct students in what is, ultimately, just a theory. However, if we must
discuss the theory of gravity at all, then it's reasonable that all suggested
theories should be given equal time, since none have been proven or disproven.
Therefore, I formally submit that the Flying Spaghetti Monster is behind this
strange and often misunderstood force.
"""

# Reflow any multi-line text
def clean(data):
    return " ".join(inspect.cleandoc(data).splitlines())

def die(*_):
    print("The pirates have disrupted your path, better luck next time")
    raise SystemExit
signal.signal(signal.SIGALRM, die)

class ChallengeFSM(fsm.FSM):
    @staticmethod
    def get_resp(f_expr, final_state, timeout=0):
        print(f"{f_expr} -> {final_state}")
        if timeout > 0:
            print(f"Pirate attack incoming in {timeout} seconds")
            signal.alarm(timeout)
        try:
            return input().strip()
        finally:
            # Cancel the alarm
            signal.alarm(0)

    @staticmethod
    def _check_resp(data, resp):
        if data != resp:
            print("You have deviated from the path")
            raise SystemExit

    @classmethod
    def run_canned(cls):
        canned_data = json.load(open("canned.json"))
        for entry in canned_data:
            data, timeout = entry["data"], entry.get("timeout", 0)
            f_expr, final_state = entry["f_expr"], entry["final_state"]
            resp = cls.get_resp(f_expr, final_state, timeout=timeout)
            cls._check_resp(data, resp)

    def check_canned(self):
        canned_data = json.load(open("canned.json"))
        for entry in canned_data:
            data = entry["data"]
            f_expr, final_state = entry["f_expr"], entry["final_state"]
            f, sf = self.get_comp(data)
            assert f_expr == str(f.as_expr())
            assert final_state == sf

    def challenge(self, data, timeout=0):
        f, sf = self.get_comp(data)
        resp = self.get_resp(f.as_expr(), sf, timeout=timeout)
        self._check_resp(data, resp)

# We expect to have a set of initial challenges which are pre-computed so that
# we're not loading the FSM data into memory unless the player had already
# shown that they know how to respond properly. We have a sanity check later
# which ensures that we are made aware of any drift in the canned challenges
# and the generated FSM.
print("Are you ready to achieve enlightenment?")
try:
    ChallengeFSM.run_canned()
except Exception:
    print("I am broken :( Please contact the organisers and quote reference:")
    print("\tICUP")
    raise SystemExit

# Now we do a deathrun with random challenges so we need to load the FSM data
busy_text = (
    "Are you ready, kids?",
    "Aye, aye, Captain!",
    "I can't hear you!",
    "Aye, aye, captain!",
    "Oh!",
    "...",
    "Ohhhhh!",
    "...",
    "Okay look, we're loading data and it's going slow",
    "Really slow apparently",
    "Wow, what?",
    ":(",
)
loaded_event = threading.Event()
def look_busy():
    for l in busy_text:
        print(l)
        if loaded_event.wait(1):
            return
    while True:
        print("sorry")
        if loaded_event.wait(1):
            return

t = threading.Thread(target=look_busy)
t.start()
FSM_OBJ = ChallengeFSM.load(open("fsm.txt"))
try:
    FSM_OBJ.check_canned()
except AssertionError:
    print("I am broken :( Please contact the organisers and quote reference:")
    print("\tBOFA")
    raise SystemExit
finally:
    loaded_event.set()

get_junk = lambda n: "".join(random.choice(string.ascii_letters) for _ in range(n))

lyrics = (
    "who lives in a pineapple under the sea?",
    "absorbent and yellow and porous is he",
    "if nautical nonsense be something you wish",
    "then drop on the deck and flop like a fish!",
)
for l in lyrics:
    print(l)
    FSM_OBJ.challenge(f"{get_junk(48)} {get_junk(48)}", 1)

# Lots of random bytes at the end of this one extends solve time and ensures
# they have an online solver which can deal with time limits
FSM_OBJ.challenge("ravioli ravioli give me the formuoli! " + get_junk(150), 2)

# Finally we'll send them the flag and tell them to have fun ;)
f, sf = FSM_OBJ.get_comp(clean(FLAG_TEXT))
print("The pirates left some booty floating in the ocean as they fled")
print(f"{f.as_expr()} -> {sf}")
