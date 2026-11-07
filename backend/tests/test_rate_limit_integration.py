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
        concurrent_key = f"sentinel:test:rate:concurrent:{uuid4().hex}"
        limiter = RedisSlidingWindowLimiter(client)
        try:
            first = await limiter.check(key, 2, 5)
            second = await limiter.check(key, 2, 5)
            third = await limiter.check(key, 2, 5)
            assert first.allowed is True and first.remaining == 1
            assert second.allowed is True and second.remaining == 0
            assert third.allowed is False and third.remaining == 0
            assert 1 <= third.retry_after_seconds <= 5

            concurrent = await asyncio.gather(
                *(limiter.check(concurrent_key, 5, 30) for _ in range(25))
            )
            assert sum(decision.allowed for decision in concurrent) == 5
            assert all(decision.remaining >= 0 for decision in concurrent)
        finally:
            await client.delete(key, concurrent_key)
            await client.aclose()

    asyncio.run(exercise())
