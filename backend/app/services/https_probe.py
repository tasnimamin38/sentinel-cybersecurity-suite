"""Bounded HTTPS header probe pinned to an already validated public IP.

The connection is made to a literal address from the validated DNS answer set.
TLS certificate validation and SNI still use the original hostname. The probe
reads response headers only; it never downloads or executes the response body.
"""

import asyncio
import ipaddress
import ssl
from contextlib import suppress
from datetime import UTC, datetime

MAX_HEADER_BYTES = 65_536
MAX_ADDRESSES = 16
USER_AGENT = "SENTINEL-Defensive-Posture/0.2"


class HttpsProbeError(RuntimeError):
    """Raised when a safe, bounded HTTPS header probe cannot be completed."""


def _remaining(deadline: float) -> float:
    remaining = deadline - asyncio.get_running_loop().time()
    if remaining <= 0:
        raise TimeoutError("HTTPS probe deadline exceeded.")
    return remaining


def _parse_response_headers(raw: bytes) -> tuple[int, str, dict[str, str]]:
    try:
        lines = raw.decode("iso-8859-1").split("\r\n")
        status_parts = lines[0].split(" ", 2)
        if len(status_parts) < 2 or not status_parts[0].startswith("HTTP/"):
            raise ValueError
        status_code = int(status_parts[1])
        http_version = status_parts[0]
        headers: dict[str, str] = {}
        for line in lines[1:]:
            if not line:
                break
            if line[:1] in (" ", "\t") or ":" not in line:
                continue
            name, value = line.split(":", 1)
            key = name.strip().lower()
            if not key:
                continue
            normalized_value = value.strip()
            headers[key] = (
                f"{headers[key]}, {normalized_value}" if key in headers else normalized_value
            )
        return status_code, http_version, headers
    except (UnicodeDecodeError, ValueError, IndexError) as exc:
        raise HttpsProbeError("Target returned an invalid HTTP response header block.") from exc


async def _probe_one(hostname: str, address: str, deadline: float) -> dict:
    context = ssl.create_default_context()
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.set_alpn_protocols(["http/1.1"])
    reader, writer = await asyncio.wait_for(
        asyncio.open_connection(
            host=address,
            port=443,
            ssl=context,
            server_hostname=hostname,
            limit=MAX_HEADER_BYTES,
        ),
        timeout=_remaining(deadline),
    )
    try:
        request = (
            f"GET / HTTP/1.1\r\n"
            f"Host: {hostname}\r\n"
            f"User-Agent: {USER_AGENT}\r\n"
            "Accept: */*\r\n"
            "Connection: close\r\n\r\n"
        ).encode("ascii")
        writer.write(request)
        await asyncio.wait_for(writer.drain(), timeout=_remaining(deadline))
        raw_headers = await asyncio.wait_for(
            reader.readuntil(b"\r\n\r\n"),
            timeout=_remaining(deadline),
        )
        if len(raw_headers) > MAX_HEADER_BYTES:
            raise HttpsProbeError("Target response headers exceed the configured safety limit.")
        status_code, http_version, headers = _parse_response_headers(raw_headers)

        tls_socket = writer.get_extra_info("ssl_object")
        if tls_socket is None:
            raise HttpsProbeError("TLS session metadata was unavailable.")
        certificate = tls_socket.getpeercert()
        expiry_raw = certificate.get("notAfter")
        expiry = (
            datetime.fromtimestamp(ssl.cert_time_to_seconds(expiry_raw), tz=UTC)
            if expiry_raw
            else None
        )
        cipher = tls_socket.cipher()
        return {
            "status_code": status_code,
            "http_version": http_version,
            "headers": headers,
            "tls": {
                "protocol": tls_socket.version(),
                "cipher": cipher[0] if cipher else None,
                "certificate_expires_at": expiry.isoformat() if expiry else None,
                "certificate_days_remaining": (expiry - datetime.now(UTC)).days if expiry else None,
            },
            "connected_address": address,
        }
    finally:
        writer.close()
        with suppress(Exception):
            await asyncio.wait_for(writer.wait_closed(), timeout=0.5)


async def inspect_https_endpoint(
    hostname: str,
    validated_addresses: list[str],
    timeout: float = 8.0,
) -> dict:
    """Probe only validated public addresses while retaining hostname TLS identity."""
    if not 0 < timeout <= 20:
        raise HttpsProbeError("HTTPS timeout must be greater than 0 and at most 20 seconds.")
    if not validated_addresses or len(validated_addresses) > MAX_ADDRESSES:
        raise HttpsProbeError("DNS answer set is empty or exceeds the configured safety limit.")

    safe_addresses: list[str] = []
    for raw_address in validated_addresses:
        try:
            address = ipaddress.ip_address(raw_address)
        except ValueError as exc:
            raise HttpsProbeError("DNS answer set contains an invalid IP address.") from exc
        if not address.is_global:
            raise HttpsProbeError("DNS answer set contains a non-public IP address.")
        safe_addresses.append(str(address))

    deadline = asyncio.get_running_loop().time() + timeout
    failures = 0
    for address in dict.fromkeys(safe_addresses):
        if deadline <= asyncio.get_running_loop().time():
            break
        try:
            return await _probe_one(hostname, address, deadline)
        except (
            TimeoutError,
            OSError,
            ssl.SSLError,
            asyncio.IncompleteReadError,
            asyncio.LimitOverrunError,
        ):
            failures += 1
        except HttpsProbeError:
            raise
    raise HttpsProbeError(
        f"No validated public address completed the HTTPS header probe ({failures} attempt(s))."
    )
