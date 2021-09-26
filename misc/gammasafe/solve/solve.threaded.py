# Author: github/uint0
import time
import socket
import contextlib
import concurrent.futures

MAX_THREADS = 8
MIN_SAMPLE_SIZE = 16

remote = ('0.0.0.0', 1337)

@contextlib.contextmanager
def challenge_sock():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5)
    sock.connect(remote)
    try:
        sock.recv(1024)
        yield sock
    finally:
        sock.close()

def make_guess(guess):
    with challenge_sock() as sock:
        start = time.time()
        sock.send(guess.hex().encode() + b'\n')
        sock.recv(1024)
        return time.time() - start


def check_outlier(times):
    if len(times) < MIN_SAMPLE_SIZE:
        return None

    longest, next_longest, *_ = sorted(times, key=lambda k: times[k], reverse=True)
    
    return longest if times[longest] - times[next_longest] > 0.5 else None


def guess_character(known):
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        # Manually submit as it allows us to control early exits better
        guesses = [known + bytes([g]) for g in range(256)]
        submissions = [executor.submit(make_guess, g) for g in guesses]

        times = {}
        for g, s in zip(guesses, submissions):
            print(g.hex(), end='\r')
            times[g] = s.result()
            if o := check_outlier(times):
                for s in submissions: s.cancel()
                return o

    assert False, "Could not find longest"

def solve():
    known = b''
    while len(known) < 4:
        print(known.hex(), end='\r')
        known = guess_character(known)
    
    return known


if __name__ == '__main__':
    print(solve().hex())
