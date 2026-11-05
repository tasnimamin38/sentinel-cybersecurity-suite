"""Redis-backed, cross-instance sliding-window request limiter.

Uses Redis server time and a Lua script so the prune/count/add decision is
atomic even when multiple API workers receive requests concurrently.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from uuid import uuid4

from redis.asyncio import Redis
from redis.exceptions import RedisError

_SLIDING_WINDOW_SCRIPT = """
local key = KEYS[1]
local limit = tonumber(ARGV[1])
local window_ms = tonumber(ARGV[2])
local member = ARGV[3]

local redis_time = redis.call('TIME')
local now_ms = (tonumber(redis_time[1]) * 1000) + math.floor(tonumber(redis_time[2]) / 1000)
local cutoff_ms = now_ms - window_ms

redis.call('ZREMRANGEBYSCORE', key, '-inf', cutoff_ms)
local count = redis.call('ZCARD', key)

if count >= limit then
    local oldest = redis.call('ZRANGE', key, 0, 0, 'WITHSCORES')
    local retry_ms = 0
    if oldest[2] then
        retry_ms = math.max(1, tonumber(oldest[2]) + window_ms - now_ms)
    end
    return {0, retry_ms, 0}
end

redis.call('ZADD', key, now_ms, member)
redis.call('PEXPIRE', key, window_ms + 1000)
return {1, 0, limit - count - 1}
"""


@dataclass(frozen=True, slots=True)
class RateLimitDecision:
    allowed: bool
    remaining: int
    retry_after_seconds: int


class RateLimiterUnavailable(RuntimeError):
    """Raised when the shared rate-limit store cannot make a safe decision."""


class RedisSlidingWindowLimiter:
    """True rolling-window limits shared by all API instances."""

    def __init__(self, client: Redis):
        self._client = client

    async def check(self, key: str, limit: int, window_seconds: int) -> RateLimitDecision:
        if not key or not 1 <= limit <= 100_000 or not 1 <= window_seconds <= 86_400:
            raise ValueError("Invalid rate-limit key or policy.")

        try:
            allowed, retry_ms, remaining = await self._client.eval(
                _SLIDING_WINDOW_SCRIPT,
                1,
                key,
                limit,
                window_seconds * 1000,
                uuid4().hex,
            )
        except RedisError as exc:
            raise RateLimiterUnavailable("Shared rate-limit storage is unavailable.") from exc

        return RateLimitDecision(
            allowed=bool(int(allowed)),
            remaining=max(0, int(remaining)),
            retry_after_seconds=max(1, math.ceil(int(retry_ms) / 1000)) if int(retry_ms) else 0,
        )
