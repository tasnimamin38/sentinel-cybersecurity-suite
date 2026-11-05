import ipaddress
import socket


class UnsafeResolution(ValueError):
    pass


def assert_public_dns_resolution(hostname: str, port: int = 443) -> list[str]:
    try:
        records = socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)
    except OSError as exc:
        raise UnsafeResolution("Target hostname could not be resolved.") from exc
    addresses = sorted({record[4][0] for record in records})
    if not addresses:
        raise UnsafeResolution("Target hostname returned no addresses.")
    for raw in addresses:
        address = ipaddress.ip_address(raw)
        if not address.is_global:
            raise UnsafeResolution(
                "Target resolves to a non-public, private, reserved or link-local address."
            )
    return addresses