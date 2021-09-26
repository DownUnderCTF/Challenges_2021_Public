import json
import uuid
from typing import List

import jose
import jose.jwt
from fastapi import (BackgroundTasks, Body, Depends, FastAPI, HTTPException,
                     Request, Response, status)
from fastapi.security import OAuth2PasswordBearer
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_ipaddr
from slowapi.errors import RateLimitExceeded

import config
import message as msg_lib
from models import (IdType, MessageInfo, MessageStatus, MessageToSend,
                    TokenResponse, User, UserRole)

openapi_description = """
API documentation for Ezmail

Get started by requesting an anonymous api token!
""".strip()

limiter = Limiter(key_func=get_ipaddr)
app = FastAPI(title="Ezmail", description=openapi_description)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

oauth2_scheme = OAuth2PasswordBearer("token")


def issue_token(user: User) -> str:
    # :thonk:
    return jose.jwt.encode(
        json.loads(user.json()), config.SECRET_KEY, algorithm="HS256"
    )


async def current_user(token: str = Depends(oauth2_scheme)) -> User:
    try:
        payload = jose.jwt.decode(token, config.SECRET_KEY)
    except jose.JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return User(**payload)


@app.get("/", include_in_schema=False)
async def index():
    return {"swagger": "/docs", "redoc": "/redoc", "openapi": "/openapi.json"}


@app.post(
    "/message",
    status_code=status.HTTP_202_ACCEPTED,
    response_model=IdType,
    tags=["message"],
)
@limiter.limit("4/second")
async def send_message(
    request: Request,
    message: MessageToSend,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(current_user),
):
    if len(message.recipients) > 8:
        raise HTTPException(
            status=status.HTTP_400_BAD_REQUEST,
            detail="Ezmail only supports messaging up to 8 people at a time",
        )

    message_id = uuid.uuid4()
    await msg_lib.set_message_processing_status(message_id, "queued")

    background_tasks.add_task(
        msg_lib.send_message,
        MessageInfo(
            id=message_id,
            sender=current_user.user_id,
            recipients=message.recipients,
            content=message.content,
        ),
        message.identity_provider,
    )

    return message_id


@app.get(
    "/message/{message_id}",
    response_model=MessageInfo,
    responses={404: {"description": "Message could not be found. Check its status at /message/{message_id}/status"}},
    tags=["message"]
)
@limiter.limit("12/second")
async def get_message(request: Request, message_id: IdType, current_user: User = Depends(current_user)):
    return await msg_lib.get_message(message_id) or Response(
        status_code=status.HTTP_404_NOT_FOUND
    )


@app.get("/message/{message_id}/status", response_model=MessageStatus, tags=["message"])
@limiter.limit("12/second")
async def get_message_status(
    request: Request, message_id: IdType, current_user: User = Depends(current_user)
):
    return await msg_lib.get_message_processing_status(message_id)


@app.get("/me/inbox", response_model=List[IdType], tags=["me"])
@limiter.limit("8/second")
async def get_inbox(request: Request, current_user: User = Depends(current_user)):
    if current_user.user_role == UserRole.ANONYMOUS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Anonymous users cannot recieve messages",
        )
    return await msg_lib.get_user_recv(current_user.user_id)


@app.get("/me/sent", response_model=List[IdType], tags=["me"])
@limiter.limit("8/second")
async def get_sendbox(request: Request, current_user: User = Depends(current_user)):
    return await msg_lib.get_user_sent(current_user.user_id)


@app.get("/me", response_model=User, tags=["me"])
async def get_me(current_user: User = Depends(current_user)):
    return current_user


@app.post("/token", response_model=TokenResponse, tags=["auth"])
@limiter.limit("24/minute")
async def get_token(request: Request):
    return {
        "access_token": issue_token(
            User(user_id=uuid.uuid4(), user_role=UserRole.ANONYMOUS)
        ),
        "token_type": "bearer",
    }
