import enum
import uuid
from typing import List, Literal

import pydantic

IdType = uuid.UUID


class IdentityProviders(str, enum.Enum):
    LDAP = "ldap"


class MessageStatus(str, enum.Enum):
    QUEUED = "queued"
    SENT = "sent"
    FAILED = "failed"


class UserRole(str, enum.Enum):
    ANONYMOUS = "anonymous"
    LDAP_USER = "ldap"


class MessageBase(pydantic.BaseModel):
    recipients: List[str]
    content: str


class MessageToSend(MessageBase):
    identity_provider: IdentityProviders


class MessageInfo(MessageBase):
    id: IdType
    sender: uuid.UUID


class User(pydantic.BaseModel):
    user_id: IdType
    user_role: UserRole


class TokenResponse(pydantic.BaseModel):
    access_token: str
    token_type: Literal["bearer"]
