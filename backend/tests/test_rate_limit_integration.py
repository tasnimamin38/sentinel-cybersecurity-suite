import asyncio
import os
from uuid import uuid4

import pytest
from redis.asyncio import Redis

from app.services.rate_limit import RedisSlidingWindowLimiter


def test_real_redis_executes_atomic_sliding_window_policy():
    redis_url = os.environ.get("SENTINEL_TEST_REDIS_URL")
    if not redis_url:
        pytest.skip("A dedicated Redis integration service is not configured.")

    async def exercise():
        client = Redis.from_url(redis_url, decode_responses=False)
        key = f"sentinel:test:rate:{uuid4().hex}"
        limiter = RedisSlidingWindowLimiter(client)
        try:
            first = await limiter.check(key, 2, 5)
            second = await limiter.check(key, 2, 5)
            third = await limiter.check(key, 2, 5)

            assert first.allowed is True
            assert first.remaining == 1
            assert second.allowed is True
            assert second.remaining == 0
            assert third.allowed is False
            assert third.remaining == 0
            assert 1 <= third.retry_after_seconds <= 5
        finally:
            await client.delete(key)
            await client.aclose()

    asyncio.run(exercise())
