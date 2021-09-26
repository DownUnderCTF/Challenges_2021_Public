import uuid

from starlette.applications import Starlette
from starlette.responses import PlainTextResponse, JSONResponse
from starlette.routing import Route, Mount
from starlette.staticfiles import StaticFiles

import secret_manager


async def get_secret(request):
    secret_id = request.path_params['secret']
    secret = await secret_manager.get_secret(secret_id)

    return PlainTextResponse(secret, status_code=(404 if secret is None else 200))


async def create_secret(request):
    secret = await request.body()
    secret_id = await secret_manager.create_secret(secret)

    return PlainTextResponse(str(secret_id))


async def get_stats(request):
    return JSONResponse({
        "stats": await secret_manager.get_metadata()
    })


app = Starlette(
    routes=[
        Mount("/api", routes=[
            Route("/secret/{secret:uuid}", get_secret,    methods=["get"]),
            Route("/secret",               create_secret, methods=["post"]),
            Route("/stats",                get_stats,     methods=["get"])
        ]),
        Mount('/', app=StaticFiles(directory='static', html=True), name="static"),
    ]
)
