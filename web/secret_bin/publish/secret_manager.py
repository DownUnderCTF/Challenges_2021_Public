import os
import uuid
import random

import aioredis

redis = aioredis.from_url(f"redis://{os.environ.get('REDIS_HOST', 'localhost')}")


async def get_secret(secret_id: uuid.UUID):
    return await redis.get(secret_id.int)


async def create_secret(secret_content: bytes):
    secret_id = make_secret_id()
    await redis.set(secret_id.int, secret_content)
    return secret_id


async def get_metadata():
    return {
        "past_week": list(sorted(get_past_week_secrets())),
        "total_secret_count": await redis.dbsize()
    }

def get_past_week_secrets():
    return [
        __stub_get_uuid_time_as_timestamp(uuid_key) for uuid_key in __stub_get_past_week_secret_uuids()
    ]

def make_secret_id():
    return __stub_generate_uuid1()


# Stub function signatures
from typing import List
def __stub_generate_uuid1() -> uuid.UUID:
    """Stubbed since it contains infra magic, basically just returns a uuidv1"""
    # uuid.uuidv1()
    pass

def __stub_get_past_week_secret_uuids() -> List[uuid.UUID]:
    """Stubbed since it contains infra magic, basically just returns a list of uuidv1s"""
    # await aioredis.lrange()
    pass

def __stub_get_uuid_time_as_timestamp(uuid: uuid.UUID) -> float:
    # return magic(uuid.time)
    pass
