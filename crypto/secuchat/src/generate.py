import sys
from faker import Faker
import sqlite3
import random
from Crypto.PublicKey import RSA
from Crypto.Util.number import getStrongPrime
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Util.Padding import pad
from datetime import datetime

FLAG = open("flag.txt", "r").read().strip()

cursor = (conn := sqlite3.connect(sys.argv[1])).cursor()

fake = Faker('en_AU')

random_keys = [(fake.user_name(), RSA.generate(2048)) for i in range(29)]

common = random.choice(random_keys)[1].p
q = getStrongPrime(1024)
vulnerable = (fake.user_name(), RSA.construct((
    common * q,
    65537,
    pow(65537, -1, (common - 1) * (q - 1)),
    common,
    q
)))

cursor.executescript('''
    CREATE TABLE User (
        username TEXT PRIMARY KEY,
        rsa_key BLOB
    );

    CREATE TABLE Parameters (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        encrypted_aes_key_for_initiator BLOB,
        encrypted_aes_key_for_peer BLOB,
        iv BLOB
    );

    CREATE TABLE Conversation (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        initiator TEXT,
        peer TEXT,
        initial_parameters INTEGER,
        FOREIGN KEY (initiator) REFERENCES User(username),
        FOREIGN KEY (peer) REFERENCES User(username),
        FOREIGN KEY (initial_parameters) REFERENCES Parameters(id),
        UNIQUE(initiator, peer)
    );

    CREATE TABLE Message (
        conversation INTEGER,
        timestamp INTEGER,
        from_initiator BOOL,
        next_parameters INTEGER,
        encrypted_message BLOB,
        FOREIGN KEY (conversation) REFERENCES Conversation(id),
        FOREIGN KEY (next_parameters) REFERENCES Parameters(id)
    );
''')


cursor.executemany('''
    INSERT INTO User(username, rsa_key) VALUES (?, ?);
''', [(u, k.publickey().exportKey("DER")) for u, k in random.sample(random_keys + [vulnerable], len(random_keys) + 1)])
print("Generated users")

all_keys = dict(random_keys + [vulnerable])

def insert_parameters(encrypted_for_initiator, encrypted_for_peer, iv):
    cursor.execute('''
        INSERT INTO Parameters(encrypted_aes_key_for_initiator, encrypted_aes_key_for_peer, iv) VALUES (?, ?, ?);
    ''', (encrypted_for_initiator, encrypted_for_peer, iv))
    cursor.execute('''
        SELECT id FROM Parameters WHERE rowid = ?;
    ''', (cursor.lastrowid,))
    return cursor.fetchone()[0]


def new_conversation(initiator, peer, messages, timestamp):
    initiator_oaep = PKCS1_OAEP.new(all_keys[initiator])
    peer_oaep = PKCS1_OAEP.new(all_keys[peer])
    key = get_random_bytes(32)
    iv = get_random_bytes(16)
    cursor.execute('''
        INSERT INTO Conversation(initiator, peer, initial_parameters) VALUES (?, ?, ?);
    ''', (initiator, peer, insert_parameters(initiator_oaep.encrypt(key), peer_oaep.encrypt(key), iv)))
    cursor.execute('''
        SELECT id FROM Conversation WHERE rowid = ?;
    ''', (cursor.lastrowid,))
    conversation_id = cursor.fetchone()[0]
    timestamp += random.randint(1, 100)
    result = []
    for message in messages:
        encrypted = AES.new(key, AES.MODE_CBC, iv=iv).encrypt(pad(message[1].encode(), AES.block_size))
        key = get_random_bytes(32)
        iv = get_random_bytes(16)
        result.append((
            conversation_id,
            timestamp,
            message[0],
            insert_parameters(initiator_oaep.encrypt(key), peer_oaep.encrypt(key), iv),
            encrypted
        ))
        timestamp += random.randint(2, 20)

    return result

all_messages = []

now = int(datetime.now().timestamp())

for i in range(45):
    initiator, peer = random.sample(list(all_keys.keys()), 2)
    while True:
        cursor.execute('''
            SELECT COUNT(1) FROM Conversation WHERE (initiator = ? AND peer = ?) OR (peer = ? AND initiator = ?);
        ''', (initiator, peer, initiator, peer))
        if cursor.fetchone()[0] == 0:
            break
        initiator, peer = random.sample(list(all_keys.keys()), 2)

    all_messages += new_conversation(initiator, peer, [(bool(random.getrandbits(1)), fake.sentence()) for i in range(random.randint(4, 10))], now)

initiator = vulnerable[0]
peer = random.choice(list(all_keys.keys()))
while True:
    cursor.execute('''
        SELECT COUNT(1) FROM Conversation WHERE (initiator = ? AND peer = ?) OR (peer = ? AND initiator = ?);
    ''', (initiator, peer, initiator, peer))
    if cursor.fetchone()[0] == 0:
        break
    peer = random.choice(list(all_keys.keys()))

all_messages += new_conversation(initiator, peer, [
    (True, f"hey {fake.sentence()}"),
    (False, f"hey {fake.sentence()}"),
    (True, f"here's the flag btw {fake.sentence()}"),
    (True, f"{FLAG} {fake.sentence()}"),
    (False, f"cheers {fake.sentence()}"),
], now)

cursor.executemany('''
    INSERT INTO Message(conversation, timestamp, from_initiator, next_parameters, encrypted_message) VALUES (?, ?, ?, ?, ?);
''', all_messages)

conn.commit()

conn.close()
