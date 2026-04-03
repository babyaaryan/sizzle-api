"""
Supabase PostgREST client — replaces SQLAlchemy for Cloudflare Workers.
Uses httpx to talk to Supabase REST API.
"""

import httpx
from typing import Any


class SupabaseClient:
    """Lightweight Supabase PostgREST client."""

    def __init__(self, url: str, key: str):
        self.base_url = f"{url}/rest/v1"
        self.headers = {
            "apikey": key,
            "Authorization": f"Bearer {key}",
            "Content-Type": "application/json",
            "Prefer": "return=representation",
        }

    async def select(
        self,
        table: str,
        columns: str = "*",
        filters: dict[str, str] | None = None,
        order: str | None = None,
        limit: int | None = None,
        offset: int | None = None,
        single: bool = False,
    ) -> list[dict] | dict | None:
        params: dict[str, str] = {"select": columns}
        if filters:
            params.update(filters)
        if order:
            params["order"] = order
        if limit:
            params["limit"] = str(limit)
        if offset:
            params["offset"] = str(offset)

        headers = {**self.headers}
        if single:
            headers["Accept"] = "application/vnd.pgrst.object+json"

        async with httpx.AsyncClient() as client:
            r = await client.get(
                f"{self.base_url}/{table}", headers=headers, params=params
            )
            if r.status_code == 406 and single:
                return None
            r.raise_for_status()
            return r.json()

    async def insert(
        self, table: str, data: dict | list[dict]
    ) -> list[dict]:
        async with httpx.AsyncClient() as client:
            r = await client.post(
                f"{self.base_url}/{table}", headers=self.headers, json=data
            )
            r.raise_for_status()
            return r.json()

    async def update(
        self, table: str, data: dict, filters: dict[str, str]
    ) -> list[dict]:
        params = {**filters}
        async with httpx.AsyncClient() as client:
            r = await client.patch(
                f"{self.base_url}/{table}",
                headers=self.headers,
                json=data,
                params=params,
            )
            r.raise_for_status()
            return r.json()

    async def delete(self, table: str, filters: dict[str, str]) -> None:
        async with httpx.AsyncClient() as client:
            r = await client.delete(
                f"{self.base_url}/{table}",
                headers=self.headers,
                params=filters,
            )
            r.raise_for_status()

    async def rpc(self, function_name: str, params: dict | None = None) -> Any:
        """Call a Supabase database function."""
        async with httpx.AsyncClient() as client:
            r = await client.post(
                f"{self.base_url}/rpc/{function_name}",
                headers=self.headers,
                json=params or {},
            )
            r.raise_for_status()
            return r.json()

    async def count(self, table: str, filters: dict[str, str] | None = None) -> int:
        headers = {
            **self.headers,
            "Prefer": "count=exact",
            "Range-Unit": "items",
            "Range": "0-0",
        }
        params: dict[str, str] = {"select": "id"}
        if filters:
            params.update(filters)
        async with httpx.AsyncClient() as client:
            r = await client.get(
                f"{self.base_url}/{table}", headers=headers, params=params
            )
            r.raise_for_status()
            content_range = r.headers.get("content-range", "*/0")
            total = content_range.split("/")[-1]
            return int(total) if total != "*" else 0


# Global instance — initialized per request from env
_client: SupabaseClient | None = None


def init_client(url: str, key: str) -> SupabaseClient:
    global _client
    _client = SupabaseClient(url, key)
    return _client


def get_db() -> SupabaseClient:
    if not _client:
        raise RuntimeError("Supabase client not initialized")
    return _client
