import asyncio
import ipaddress
import socket

import dns.asyncresolver
import dns.resolver


class UnsafeResolution(ValueError):
    pass


def _validate_public_addresses(addresses: set[str]) -> list[str]:
    if not addresses:
        raise UnsafeResolution("Target hostname returned no addresses.")
    normalized: list[str] = []
    for raw in sorted(addresses):
        try:
            address = ipaddress.ip_address(raw)
        except ValueError as exc:
            raise UnsafeResolution("Target DNS response contained an invalid IP address.") from exc
        if not address.is_global:
            raise UnsafeResolution(
                "Target resolves to a non-public, private, reserved or link-local address."
            )
        normalized.append(str(address))
    return normalized


def assert_public_dns_resolution(hostname: str, port: int = 443) -> list[str]:
    """Synchronous compatibility helper for tests and local diagnostics."""
    try:
        records = socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)
    except OSError as exc:
        raise UnsafeResolution("Target hostname could not be resolved.") from exc
    addresses = {record[4][0] for record in records}
    return _validate_public_addresses(addresses)


async def assert_public_dns_resolution_async(
    hostname: str,
    timeout: float = 3.5,
) -> list[str]:
    """Resolve A and AAAA under one bounded DNS lifetime and fail closed."""
    if not 0.5 <= timeout <= 10:
        raise UnsafeResolution("DNS timeout must be between 0.5 and 10 seconds.")

    resolver = dns.asyncresolver.Resolver(configure=True)
    resolver.timeout = min(1.5, timeout)
    resolver.lifetime = timeout

    async def query_addresses(record_type: str) -> list[str]:
        try:
            answer = await resolver.resolve(
                hostname,
                record_type,
                raise_on_no_answer=False,
                lifetime=timeout,
            )
        except dns.resolver.NXDOMAIN as exc:
            raise UnsafeResolution("Target hostname does not exist in DNS.") from exc
        except (dns.resolver.NoNameservers, dns.resolver.LifetimeTimeout) as exc:
            raise UnsafeResolution(
                "Target DNS resolution failed or exceeded its deadline."
            ) from exc
        except dns.exception.Timeout as exc:
            raise UnsafeResolution("Target DNS resolution exceeded its deadline.") from exc
        if answer.rrset is None:
            return []
        return [str(record.address) for record in answer.rrset]

    try:
        address_sets = await asyncio.wait_for(
            asyncio.gather(query_addresses("A"), query_addresses("AAAA")),
            timeout=timeout + 0.15,
        )
    except TimeoutError as exc:
        raise UnsafeResolution("Target DNS resolution exceeded its deadline.") from exc

    addresses = {address for result in address_sets for address in result}
    return _validate_public_addresses(addresses)
