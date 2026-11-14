"""
Cloudflare Python Worker Entrypoint for Wude Mart Backend.
"""

from workers import WorkerEntrypoint
import asgi
from app_main import app


class Default(WorkerEntrypoint):
    async def fetch(self, request):
        return await asgi.fetch(app, request, self.env, self.ctx)

    async def on_fetch(self, request):
        return await self.fetch(request)
