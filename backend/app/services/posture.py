import asyncio

from app.services.dns_posture import inspect_dns_posture
from app.services.https_probe import HttpsProbeError, inspect_https_endpoint
from app.services.risk import calculate_risk
from app.services.scope import authorize_domain
from app.services.security_headers import evaluate_security_headers


def _tls_expiry_findings(days_remaining: int | None) -> list[dict]:
    if days_remaining is None or days_remaining > 30:
        return []
    return [
        {
            "code": "TLS_CERT_EXPIRING",
            "title": "TLS certificate expires soon",
            "severity": "high" if days_remaining <= 3 else "medium",
            "category": "tls",
            "confidence": 1.0,
            "description": f"The certificate has {days_remaining} days remaining.",
            "recommendation": "Renew the certificate and verify automated certificate lifecycle monitoring.",
        }
    ]


async def assess_domain(
    target: str,
    allowed_domains: list[str],
    timeout: float = 8.0,
    context: dict | None = None,
) -> dict:
    domain = authorize_domain(target, allowed_domains)
    from app.services.network_safety import assert_public_dns_resolution_async

    resolved_addresses = await assert_public_dns_resolution_async(domain, timeout=min(timeout, 3.5))
    findings: list[dict] = []
    evidence: dict = {
        "resolved_addresses": resolved_addresses,
        "web": {},
        "tls": {},
        "dns": {},
        "assessment_context": context or {},
    }

    try:
        web_result = await inspect_https_endpoint(domain, resolved_addresses, timeout=timeout)
        evidence["web"] = {
            "status_code": web_result["status_code"],
            "http_version": web_result["http_version"],
            "connected_address": web_result["connected_address"],
        }
        evidence["tls"] = web_result["tls"]
        findings.extend(evaluate_security_headers(web_result["headers"]))
        findings.extend(_tls_expiry_findings(web_result["tls"]["certificate_days_remaining"]))
    except HttpsProbeError as exc:
        findings.append(
            {
                "code": "HTTPS_CHECK_FAILED",
                "title": "HTTPS and TLS could not be safely assessed",
                "severity": "medium",
                "category": "transport-security",
                "confidence": 0.8,
                "description": str(exc),
                "recommendation": "Verify HTTPS availability, certificate trust, DNS records and outbound egress policy.",
            }
        )

    try:
        evidence["dns"], dns_findings = await asyncio.to_thread(
            inspect_dns_posture, domain, min(timeout, 4.0)
        )
        findings.extend(dns_findings)
    except Exception as exc:
        findings.append(
            {
                "code": "DNS_POSTURE_FAILED",
                "title": "DNS posture checks were incomplete",
                "severity": "low",
                "category": "dns",
                "confidence": 0.6,
                "description": f"DNS posture inspection failed: {type(exc).__name__}.",
                "recommendation": "Verify authoritative DNS availability and resolver connectivity.",
            }
        )

    risk = calculate_risk(findings, context=context)
    return {
        "target": domain,
        "status": "completed",
        "score": risk["score"],
        "risk_level": risk["level"],
        "counts": risk["counts"],
        "risk_explanation": risk["explanation"],
        "findings": findings,
        "evidence": evidence,
    }
