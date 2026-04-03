"""
Cloudflare Worker entry point — lightweight Python handler.
"""
from workers import WorkerEntrypoint
from app import handle_request


class Default(WorkerEntrypoint):
    async def on_fetch(self, request):
        return await handle_request(request, self.env)
