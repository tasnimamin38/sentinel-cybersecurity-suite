import socket
import ssl
from datetime import UTC, datetime


def inspect_tls(hostname: str, timeout: float = 4.0) -> list[dict]:
    context = ssl.create_default_context()
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    with socket.create_connection((hostname, 443), timeout=timeout) as raw_socket:
        with context.wrap_socket(raw_socket, server_hostname=hostname) as connection:
            certificate = connection.getpeercert()
            cipher = connection.cipher()
            expiry_raw = certificate.get("notAfter")
            expiry = (
                datetime.strptime(expiry_raw, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=UTC)
                if expiry_raw
                else None
            )
            days_remaining = (expiry - datetime.now(UTC)).days if expiry else None
            findings = []
            if days_remaining is not None and days_remaining <= 14:
                findings.append(
                    {
                        "code": "TLS_CERT_EXPIRING",
                        "title": "TLS certificate expires soon",
                        "severity": "high" if days_remaining <= 3 else "medium",
                        "category": "tls",
                        "description": f"The certificate has {days_remaining} days remaining.",
                        "recommendation": "Renew the certificate and verify automated certificate lifecycle monitoring.",
                    }
                )
            return [
                {
                    "protocol": connection.version(),
                    "cipher": cipher[0] if cipher else None,
                    "certificate_expires_at": expiry.isoformat() if expiry else None,
                    "certificate_days_remaining": days_remaining,
                },
                findings,
            ]
