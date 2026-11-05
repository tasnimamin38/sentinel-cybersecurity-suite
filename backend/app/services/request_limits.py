"""Pure-ASGI request body guard for API resource-consumption limits."""

from __future__ import annotations

from uuid import uuid4

from starlette.responses import JSONResponse


class _RequestBodyTooLarge(Exception):
    pass


class RequestBodySizeLimitMiddleware:
    """Reject oversized API bodies before JSON parsing or endpoint execution.

    Content-Length is used as an early rejection hint, while the receive wrapper
    enforces the same cap for chunked or missing-length requests.
    """

    def __init__(self, app, *, max_bytes: int):
        if max_bytes < 1024:
            raise ValueError("max_bytes must be at least 1024.")
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or not scope.get("path", "").startswith("/api/v1/"):
            await self.app(scope, receive, send)
            return

        headers = {key.lower(): value for key, value in scope.get("headers", [])}
        declared_length = headers.get(b"content-length")
        if declared_length:
            try:
                if int(declared_length) > self.max_bytes:
                    await self._reject(scope, receive, send)
                    return
            except ValueError:
                # Let the HTTP server/framework handle malformed lengths.
                pass

        received = 0
        response_started = False

        async def limited_receive():
            nonlocal received
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > self.max_bytes:
                    raise _RequestBodyTooLarge
            return message

        async def tracked_send(message):
            nonlocal response_started
            if message["type"] == "http.response.start":
                response_started = True
            await send(message)

        try:
            await self.app(scope, limited_receive, tracked_send)
        except _RequestBodyTooLarge:
            if not response_started:
                await self._reject(scope, receive, send)

    async def _reject(self, scope, receive, send):
        response = JSONResponse(
            status_code=413,
            content={"detail": "Request body exceeds the configured API size limit."},
            headers={
                "Cache-Control": "no-store",
                "X-Content-Type-Options": "nosniff",
                "X-Frame-Options": "DENY",
                "X-Request-ID": uuid4().hex,
            },
        )
        await response(scope, receive, send)
