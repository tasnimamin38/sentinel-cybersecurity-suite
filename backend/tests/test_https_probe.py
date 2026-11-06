import ssl
import unittest
from unittest.mock import AsyncMock, patch

from app.services.https_probe import HttpsProbeError, inspect_https_endpoint


class FakeTLS:
    def getpeercert(self):
        return {"notAfter": "Dec 31 23:59:59 2030 GMT"}

    def cipher(self):
        return ("TLS_AES_128_GCM_SHA256", "TLSv1.3", 128)

    def version(self):
        return "TLSv1.3"


class FakeReader:
    async def readuntil(self, separator):
        return (
            b"HTTP/1.1 200 OK\r\n"
            b"Strict-Transport-Security: max-age=31536000\r\n"
            b"Content-Security-Policy: default-src 'self'\r\n"
            b"\r\n"
        )


class FakeWriter:
    def __init__(self):
        self.payload = b""
        self.tls = FakeTLS()

    def write(self, payload):
        self.payload += payload

    async def drain(self):
        return None

    def get_extra_info(self, name):
        return self.tls if name == "ssl_object" else None

    def close(self):
        return None

    async def wait_closed(self):
        return None


class HttpsProbeTests(unittest.IsolatedAsyncioTestCase):
    @patch("app.services.https_probe.ssl.create_default_context")
    @patch("app.services.https_probe.asyncio.open_connection", new_callable=AsyncMock)
    async def test_enforces_tls_1_2_minimum(self, open_connection, create_context):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        create_context.return_value = context
        open_connection.return_value = (FakeReader(), FakeWriter())

        await inspect_https_endpoint("example.com", ["8.8.8.8"], timeout=2)

        self.assertEqual(context.minimum_version, ssl.TLSVersion.TLSv1_2)
        self.assertIs(open_connection.await_args.kwargs["ssl"], context)

    @patch("app.services.https_probe.asyncio.open_connection", new_callable=AsyncMock)
    async def test_connects_to_validated_ip_with_original_hostname_sni_and_host_header(
        self, open_connection
    ):
        writer = FakeWriter()
        open_connection.return_value = (FakeReader(), writer)

        result = await inspect_https_endpoint("example.com", ["8.8.8.8"], timeout=2)

        self.assertEqual(result["status_code"], 200)
        self.assertEqual(result["connected_address"], "8.8.8.8")
        self.assertEqual(result["tls"]["protocol"], "TLSv1.3")
        self.assertEqual(open_connection.await_args.kwargs["host"], "8.8.8.8")
        self.assertEqual(open_connection.await_args.kwargs["server_hostname"], "example.com")
        self.assertIn(b"Host: example.com", writer.payload)
        self.assertIn(b"Connection: close", writer.payload)

    @patch("app.services.https_probe.asyncio.open_connection", new_callable=AsyncMock)
    async def test_private_address_is_rejected_before_network_connection(self, open_connection):
        with self.assertRaises(HttpsProbeError):
            await inspect_https_endpoint("example.com", ["127.0.0.1"], timeout=2)
        open_connection.assert_not_awaited()

    @patch("app.services.https_probe.asyncio.open_connection", new_callable=AsyncMock)
    async def test_empty_or_oversized_address_set_is_rejected(self, open_connection):
        with self.assertRaises(HttpsProbeError):
            await inspect_https_endpoint("example.com", [], timeout=2)
        open_connection.assert_not_awaited()


if __name__ == "__main__":
    unittest.main()
