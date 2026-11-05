import asyncio
import unittest

from app.services.request_limits import RequestBodySizeLimitMiddleware


class RequestBodySizeLimitTests(unittest.TestCase):
    def _scope(self, path="/api/v1/secrets/scan", headers=None):
        return {
            "type": "http",
            "asgi": {"version": "3.0"},
            "http_version": "1.1",
            "method": "POST",
            "scheme": "http",
            "path": path,
            "raw_path": path.encode(),
            "query_string": b"",
            "headers": headers or [],
            "client": ("127.0.0.1", 12345),
            "server": ("testserver", 80),
        }

    def _run(self, middleware, scope, messages):
        sent = []
        app_called = False

        async def receive():
            nonlocal messages
            if messages:
                return messages.pop(0)
            return {"type": "http.request", "body": b"", "more_body": False}

        async def send(message):
            sent.append(message)

        async def app(scope, receive, send):
            nonlocal app_called
            app_called = True
            while True:
                event = await receive()
                if event["type"] == "http.request" and not event.get("more_body", False):
                    break
            await send({"type": "http.response.start", "status": 200, "headers": []})
            await send({"type": "http.response.body", "body": b"ok"})

        middleware.app = app
        asyncio.run(middleware(scope, receive, send))
        return sent, app_called

    def test_declared_content_length_is_rejected_before_body_read(self):
        middleware = RequestBodySizeLimitMiddleware(lambda *args: None, max_bytes=1024)
        scope = self._scope(headers=[(b"content-length", b"1025")])
        sent, app_called = self._run(middleware, scope, [])
        self.assertFalse(app_called)
        self.assertEqual(sent[0]["status"], 413)
        self.assertIn((b"cache-control", b"no-store"), sent[0]["headers"])

    def test_chunked_body_is_counted_even_without_content_length(self):
        middleware = RequestBodySizeLimitMiddleware(lambda *args: None, max_bytes=1024)
        scope = self._scope()
        messages = [
            {"type": "http.request", "body": b"A" * 700, "more_body": True},
            {"type": "http.request", "body": b"B" * 400, "more_body": False},
        ]
        sent, app_called = self._run(middleware, scope, messages)
        self.assertTrue(app_called)
        self.assertEqual(sent[0]["status"], 413)

    def test_non_api_paths_are_not_subject_to_api_body_policy(self):
        middleware = RequestBodySizeLimitMiddleware(lambda *args: None, max_bytes=1024)
        scope = self._scope(path="/healthz", headers=[(b"content-length", b"1500")])
        sent, app_called = self._run(
            middleware,
            scope,
            [{"type": "http.request", "body": b"x" * 1500, "more_body": False}],
        )
        self.assertTrue(app_called)
        self.assertEqual(sent[0]["status"], 200)


if __name__ == "__main__":
    unittest.main()
