import asyncio
import unittest

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


class RedisSlidingWindowTests(unittest.TestCase):
    def test_lua_script_uses_server_time_and_atomic_sorted_set_window(self):
        self.assertIn("redis.call('TIME')", _SLIDING_WINDOW_SCRIPT)
        self.assertIn("ZREMRANGEBYSCORE", _SLIDING_WINDOW_SCRIPT)
        self.assertIn("ZCARD", _SLIDING_WINDOW_SCRIPT)
        self.assertIn("ZADD", _SLIDING_WINDOW_SCRIPT)
        self.assertIn("PEXPIRE", _SLIDING_WINDOW_SCRIPT)

    def test_allowed_request_returns_remaining_budget(self):
        redis = FakeRedis([1, 0, 4])
        limiter = RedisSlidingWindowLimiter(redis)
        result = asyncio.run(limiter.check("sentinel:rate:client:abc", 5, 60))

        self.assertTrue(result.allowed)
        self.assertEqual(result.remaining, 4)
        self.assertEqual(result.retry_after_seconds, 0)
        self.assertEqual(redis.calls[0][0], _SLIDING_WINDOW_SCRIPT)
        self.assertEqual(redis.calls[0][1], 1)
        self.assertEqual(redis.calls[0][2], "sentinel:rate:client:abc")
        self.assertEqual(redis.calls[0][4], 60_000)

    def test_denied_request_rounds_retry_after_up_to_a_whole_second(self):
        limiter = RedisSlidingWindowLimiter(FakeRedis([0, 1_250, 0]))
        result = asyncio.run(limiter.check("sentinel:rate:ip:abc", 2, 60))

        self.assertFalse(result.allowed)
        self.assertEqual(result.remaining, 0)
        self.assertEqual(result.retry_after_seconds, 2)

    def test_redis_failure_is_explicit_and_never_fails_open(self):
        limiter = RedisSlidingWindowLimiter(FakeRedis(error=RedisError("offline")))
        with self.assertRaises(RateLimiterUnavailable):
            asyncio.run(limiter.check("sentinel:rate:client:abc", 5, 60))

    def test_invalid_policy_is_rejected_before_redis_call(self):
        redis = FakeRedis()
        limiter = RedisSlidingWindowLimiter(redis)
        with self.assertRaises(ValueError):
            asyncio.run(limiter.check("", 5, 60))
        with self.assertRaises(ValueError):
            asyncio.run(limiter.check("key", 0, 60))
        self.assertEqual(redis.calls, [])


if __name__ == "__main__":
    unittest.main()
