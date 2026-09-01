import redis.asyncio as aioredis
from app.config import settings
import structlog

log = structlog.get_logger()


class RedisClient:
    _client: aioredis.Redis = None

    @classmethod
    async def connect(cls):
        cls._client = aioredis.from_url(
            settings.REDIS_URL,
            encoding="utf-8",
            decode_responses=True,
            max_connections=20,
        )
        await cls._client.ping()
        log.info("Redis connected")

    @classmethod
    async def disconnect(cls):
        if cls._client:
            await cls._client.aclose()

    @classmethod
    def get_client(cls) -> aioredis.Redis:
        return cls._client

    @classmethod
    async def get(cls, key: str) -> str | None:
        return await cls._client.get(key)

    @classmethod
    async def set(cls, key: str, value: str, ex: int = None):
        await cls._client.set(key, value, ex=ex)

    @classmethod
    async def delete(cls, *keys: str):
        await cls._client.delete(*keys)

    @classmethod
    async def exists(cls, key: str) -> bool:
        return bool(await cls._client.exists(key))

    @classmethod
    async def incr(cls, key: str, ex: int = None) -> int:
        value = await cls._client.incr(key)
        if ex:
            await cls._client.expire(key, ex)
        return value

    @classmethod
    async def sadd(cls, key: str, *values: str):
        await cls._client.sadd(key, *values)

    @classmethod
    async def sismember(cls, key: str, value: str) -> bool:
        return bool(await cls._client.sismember(key, value))

    # ── Rate Limiting ─────────────────────────────────────────────────
    @classmethod
    async def check_rate_limit(cls, identifier: str, limit: int, window: int) -> tuple[bool, int]:
        """Returns (is_allowed, remaining)"""
        key = f"rate_limit:{identifier}"
        count = await cls.incr(key, ex=window)
        remaining = max(0, limit - count)
        return count <= limit, remaining

    # ── Token Blocklist (for logout) ──────────────────────────────────
    @classmethod
    async def blocklist_token(cls, jti: str, expire_seconds: int):
        await cls._client.set(f"blocklist:{jti}", "1", ex=expire_seconds)

    @classmethod
    async def is_token_blocked(cls, jti: str) -> bool:
        return await cls.exists(f"blocklist:{jti}")

    # ── URL dedup bloom filter (simplified via set) ────────────────────
    @classmethod
    async def mark_url_seen(cls, url_hash: str):
        await cls._client.sadd("seen_urls", url_hash)
        # Note: In production use Redis Bloom Filter module

    @classmethod
    async def is_url_seen(cls, url_hash: str) -> bool:
        return bool(await cls._client.sismember("seen_urls", url_hash))
