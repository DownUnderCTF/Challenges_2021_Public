#!/usr/bin/env python
import sys
import sqlite3
import itertools
from math import gcd
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

db = sys.argv[1] if len(sys.argv) > 1 else './publish/secuchat.db'
cur = (conn := sqlite3.connect(db)).cursor()

cur.execute("SELECT * FROM User;")
users = [(name, RSA.importKey(k)) for name, k in cur]
for (an, ak), (bn, bk) in itertools.combinations(users, 2):
    if (p := gcd(ak.n, bk.n)) > 1:
        break

print(an, bn)
ak = RSA.construct((ak.n, 65537, pow(65537, -1, (p - 1) * ((q := (ak.n // p)) - 1)), p, q))
bk = RSA.construct((bk.n, 65537, pow(65537, -1, (p - 1) * ((q := (bk.n // p)) - 1)), p, q))


for user, rsa_key in [(an, ak), (bn, bk)]:
    oaep = PKCS1_OAEP.new(rsa_key)
    cur.execute('''
        SELECT
            Conversation.id,
            initiator,
            peer,
            encrypted_aes_key_for_initiator,
            encrypted_aes_key_for_peer,
            iv
        FROM Conversation
        INNER JOIN Parameters
            ON Parameters.id = Conversation.initial_parameters
        WHERE initiator = ? OR peer = ?;
    ''', (user, user))

    for cid, initiator, peer, initiator_key, peer_key, iv in cur.fetchall():
        print(f"{cid}: {initiator} & {peer}")
        attribute = ""
        aes = None
        if initiator == user:
            attribute = "encrypted_aes_key_for_initiator"
            aes = AES.new(oaep.decrypt(initiator_key), AES.MODE_CBC, iv=iv)
        else:
            attribute = "encrypted_aes_key_for_peer"
            aes = AES.new(oaep.decrypt(peer_key), AES.MODE_CBC, iv=iv)

        cur.execute('''
        SELECT
            encrypted_message,
            from_initiator,
        ''' + f"{attribute}, " + '''
            iv
        FROM Message
        INNER JOIN Parameters
            ON Parameters.id = next_parameters
        WHERE conversation = ?
        ORDER BY
            timestamp ASC;
        ''', (cid,))
        for message, from_initiator, key, iv in cur.fetchall():
            print(f"{[peer, initiator][from_initiator]}:", message := unpad(aes.decrypt(message), AES.block_size).decode())
            if "DUCTF" in message:
                break

            aes = AES.new(oaep.decrypt(key), AES.MODE_CBC, iv=iv)
        if "DUCTF" in message:
            break

    if "DUCTF" in message:
        break

conn.close()
