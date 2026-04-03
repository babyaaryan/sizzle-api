"""
Cloudflare Worker entry point — bridges to FastAPI via ASGI.
"""
from workers import WorkerEntrypoint
import asgi
from app import app


class Default(WorkerEntrypoint):
    async def fetch(self, request):
        return await asgi.fetch(app, request, self.env)
