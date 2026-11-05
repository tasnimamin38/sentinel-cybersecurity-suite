import asyncio
import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from app.services.network_safety import (
    UnsafeResolution,
    assert_public_dns_resolution_async,
)


class FakeAnswer:
    def __init__(self, addresses):
        self.rrset = (
            [SimpleNamespace(address=address) for address in addresses] if addresses else None
        )


class AsyncDnsSafetyTests(unittest.IsolatedAsyncioTestCase):
    @patch(
        "app.services.network_safety.dns.asyncresolver.Resolver.resolve",
        new_callable=AsyncMock,
    )
    async def test_public_a_answer_and_empty_aaaa_answer_are_accepted(self, resolve):
        async def answer(_hostname, record_type, **_kwargs):
            return FakeAnswer(["8.8.8.8"] if record_type == "A" else [])

        resolve.side_effect = answer
        result = await assert_public_dns_resolution_async("example.com", timeout=2)
        self.assertEqual(result, ["8.8.8.8"])
        self.assertEqual(resolve.await_count, 2)

    @patch(
        "app.services.network_safety.dns.asyncresolver.Resolver.resolve",
        new_callable=AsyncMock,
    )
    async def test_any_private_answer_rejects_mixed_dns_set(self, resolve):
        async def answer(_hostname, record_type, **_kwargs):
            if record_type == "A":
                return FakeAnswer(["8.8.8.8", "10.0.0.8"])
            return FakeAnswer([])

        resolve.side_effect = answer
        with self.assertRaises(UnsafeResolution):
            await assert_public_dns_resolution_async("example.com", timeout=2)

    @patch(
        "app.services.network_safety.dns.asyncresolver.Resolver.resolve",
        new_callable=AsyncMock,
    )
    async def test_dns_timeout_fails_closed(self, resolve):
        async def slow_answer(*_args, **_kwargs):
            await asyncio.sleep(1)

        resolve.side_effect = slow_answer
        with self.assertRaises(UnsafeResolution):
            await assert_public_dns_resolution_async("example.com", timeout=0.5)


if __name__ == "__main__":
    unittest.main()
