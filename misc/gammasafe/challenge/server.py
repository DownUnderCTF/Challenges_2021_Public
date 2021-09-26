#!/usr/bin/python3.8
import time

FLAG = open("flag.txt", "r").read().strip()
SECRET = b"&\xc6\x02\xf2"


def main():
    print("SATELITE CONNECTION ESTABLISHED")
    print("-" * 40)
    print("Warning: This console is restricted to")
    print("users authorised by the Space Agency for")
    print("administration purposes only.")
    print("Unauthorized access is unlawful under")
    print("intergalactic treaties and will be")
    print("prosecuted to the fullest extent")
    print("of the law.")
    print("-" * 40)

    attempts = 0
    while attempts < 3:
        print("Signed source IP address (hex): ", end="")

        try:
            guess = bytes.fromhex(input())
        except:
            print("Parsing error. Disconnecting...")
            return

        for a, b in zip(SECRET, guess):
            if a != b:
                break
            time.sleep(1.2)

        if SECRET == guess:
            print("Authenticated. Recorded satelite data decodes to the following:")
            print(FLAG)
            return

        print("Incorrect handshake. This attempt has been logged.")
        attempts += 1

    print("Attempt limit reached. Disconnecting...")


if __name__ == "__main__":
    main()
