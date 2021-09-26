import logging
import uuid
from typing import Dict, List, Optional

import aioredis
import ldap3

import config
from models import IdentityProviders, IdType, MessageInfo, MessageStatus

redis = aioredis.from_url(f"redis://{config.REDIS_HOST}")
ldap = ldap3.Server(config.LDAP_HOST)


def ldap_to_ezmail_id(user_cns: List[str]) -> Dict[str, IdType]:
    ezmail_users = {}
    with ldap3.Connection(
        ldap, client_strategy=ldap3.SAFE_SYNC, auto_bind=True
    ) as conn:
        for user_cn in user_cns:
            success, _res_meta, res, _query_meta = conn.search(
                "dc=ductf,dc=org",
                f"(&(objectclass=*)(cn={user_cn}))",
                attributes=["uid"],
            )
            if success:
                ezmail_users[user_cn] = uuid.UUID(res[0]["attributes"]["uid"][0])
    return ezmail_users


async def set_message_processing_status(message_id: IdType, status: MessageStatus):
    await redis.set(f"msg|{message_id.hex}|status", str(status))


async def get_message_processing_status(message_id: IdType) -> Optional[MessageStatus]:
    status = await redis.get(f"msg|{message_id.hex}|status")
    return status and MessageStatus(status.decode())


async def send_message(message_spec: MessageInfo, identity_provider: IdentityProviders):
    try:
        recipients = ldap_to_ezmail_id(message_spec.recipients)
        ezmail_recipients = list(recipients.values())
        ldap_recipients = list(recipients.keys())

        message_spec.recipients = ldap_recipients

        async with redis.pipeline(transaction=True) as pipe:
            tr = pipe.set(f"msg|{message_spec.id.hex}", message_spec.json())
            tr.lpush(f"usr|{message_spec.sender.hex}|send", message_spec.id.hex)
            for recipient in ezmail_recipients:
                tr.lpush(f"usr|{recipient.hex}|recv", message_spec.id.hex)
            await tr.execute()

        await set_message_processing_status(message_spec.id, "sent")
    except Exception as e:
        logging.exception("An error occurred when sending a message")
        await set_message_processing_status(message_spec.id, "failed")


async def get_message(message_id: IdType):
    msg = await redis.get(f"msg|{message_id.hex}")
    return msg and MessageInfo.parse_raw(msg.decode())


async def get_user_sent(user_id: IdType):
    msg_ids = await redis.lrange(f"usr|{user_id.hex}|send", 0, -1)
    return [uuid.UUID(hex=msg_id.decode()) for msg_id in msg_ids]


async def get_user_recv(user_id: IdType):
    msg_ids = await redis.lrange(f"usr|{user_id.hex}|recv", 0, -1)
    return [uuid.UUID(hex=msg_id.decode()) for msg_id in msg_ids]
