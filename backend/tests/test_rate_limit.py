import asyncio

import pytest
from redis.exceptions import RedisError

from app.services.rate_limit import (
    _SLIDING_WINDOW_SCRIPT,
    RateLimiterUnavailable,
    RedisSlidingWindowLimiter,
)


class FakeRedis:
    def __init__(self, result=None, error=None):
        self.result = result if result is not None else [1, 0, 4]
        self.error = error
        self.calls = []

    async def eval(self, *args):
        self.calls.append(args)
        if self.error:
            raise self.error
        return self.result


def test_lua_script_uses_redis_server_time_and_atomic_sorted_set_window():
    assert "redis.call('TIME')" in _SLIDING_WINDOW_SCRIPT
    assert "ZREMRANGEBYSCORE" in _SLIDING_WINDOW_SCRIPT
    assert "ZCARD" in _SLIDING_WINDOW_SCRIPT
    assert "ZADD" in _SLIDING_WINDOW_SCRIPT
    assert "PEXPIRE" in _SLIDING_WINDOW_SCRIPT


def test_allowed_request_returns_remaining_budget():
    redis = FakeRedis([1, 0, 4])
    result = asyncio.run(RedisSlidingWindowLimiter(redis).check("sentinel:rate:ip:abc", 5, 60))
    assert result.allowed is True
    assert result.remaining == 4
    assert result.retry_after_seconds == 0
    assert redis.calls[0][2] == "sentinel:rate:ip:abc"
    assert redis.calls[0][4] == 60_000


def test_denied_request_rounds_retry_after_up_to_a_whole_second():
    result = asyncio.run(
        RedisSlidingWindowLimiter(FakeRedis([0, 1_250, 0])).check("sentinel:rate:ip:abc", 2, 60)
    )
    assert result.allowed is False
    assert result.remaining == 0
    assert result.retry_after_seconds == 2


def test_redis_failure_is_explicit_and_never_fails_open():
    limiter = RedisSlidingWindowLimiter(FakeRedis(error=RedisError("offline")))
    with pytest.raises(RateLimiterUnavailable):
        asyncio.run(limiter.check("sentinel:rate:client:abc", 5, 60))


def test_invalid_policy_is_rejected_before_redis_call():
    redis = FakeRedis()
    limiter = RedisSlidingWindowLimiter(redis)
    with pytest.raises(ValueError):
        asyncio.run(limiter.check("", 5, 60))
    with pytest.raises(ValueError):
        asyncio.run(limiter.check("key", 0, 60))
    assert redis.calls == []
