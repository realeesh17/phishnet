"""Azure Functions Python v2 entry point for the FastAPI ASGI application."""

import azure.functions as func

from app.main import app as fastapi_app

app = func.AsgiFunctionApp(
    app=fastapi_app,
    http_auth_level=func.AuthLevel.ANONYMOUS,
)
