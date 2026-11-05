import asyncio

import httpx

from app.services.dns_posture import inspect_dns_posture
from app.services.network_safety import assert_public_dns_resolution
from app.services.risk import calculate_risk
from app.services.scope import authorize_domain
from app.services.security_headers import evaluate_security_headers
from app.services.tls import inspect_tls


async def assess_domain(target: str, allowed_domains: list[str], timeout: float = 8.0) -> dict:
    domain = authorize_domain(target, allowed_domains)
    resolved_addresses = assert_public_dns_resolution(domain)
    findings: list[dict] = []
    evidence: dict = {"resolved_addresses": resolved_addresses, "web": {}, "tls": {}, "dns": {}}

    try:
        async with httpx.AsyncClient(
            verify=True,
            timeout=httpx.Timeout(timeout),
            follow_redirects=False,
            trust_env=False,
            headers={"User-Agent": "SENTINEL-Defensive-Posture/0.1"},
        ) as client:
            async with client.stream("GET", f"https://{domain}/") as response:
                evidence["web"] = {
                    "status_code": response.status_code,
                    "http_version": response.http_version,
                }
                findings.extend(evaluate_security_headers(dict(response.headers)))
    except (httpx.HTTPError, OSError) as exc:
        findings.append(
            {
                "code": "HTTPS_CHECK_FAILED",
                "title": "HTTPS response could not be assessed",
                "severity": "medium",
                "category": "web-security",
                "description": f"The safe HTTPS request failed: {type(exc).__name__}.",
                "recommendation": "Verify the hostname, HTTPS availability and network policy; no redirect was followed.",
            }
        )

    tls_result, dns_result = await asyncio.gather(
        asyncio.to_thread(inspect_tls, domain),
        asyncio.to_thread(inspect_dns_posture, domain),
        return_exceptions=True,
    )
    if isinstance(tls_result, Exception):
        findings.append(
            {
                "code": "TLS_CHECK_FAILED",
                "title": "TLS certificate inspection failed",
                "severity": "medium",
                "category": "tls",
                "description": f"TLS inspection failed: {type(tls_result).__name__}.",
                "recommendation": "Check TLS availability, certificate trust and firewall policy.",
            }
        )
    else:
        evidence["tls"], tls_findings = tls_result
        findings.extend(tls_findings)

    if isinstance(dns_result, Exception):
        findings.append(
            {
                "code": "DNS_POSTURE_FAILED",
                "title": "DNS posture checks were incomplete",
                "severity": "low",
                "category": "dns",
                "description": f"DNS posture inspection failed: {type(dns_result).__name__}.",
                "recommendation": "Verify authoritative DNS availability and resolver connectivity.",
            }
        )
    else:
        evidence["dns"], dns_findings = dns_result
        findings.extend(dns_findings)

    risk = calculate_risk(findings)
    return {
        "target": domain,
        "status": "completed",
        "score": risk["score"],
        "risk_level": risk["level"],
        "counts": risk["counts"],
        "findings": findings,
        "evidence": evidence,
    }