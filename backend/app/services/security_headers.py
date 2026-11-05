def _finding(code: str, title: str, severity: str, description: str, recommendation: str) -> dict:
    return {
        "code": code,
        "title": title,
        "severity": severity,
        "description": description,
        "recommendation": recommendation,
        "category": "web-security",
    }


def evaluate_security_headers(headers: dict[str, str]) -> list[dict]:
    normalized = {str(key).lower(): str(value) for key, value in headers.items()}
    findings: list[dict] = []

    if "strict-transport-security" not in normalized:
        findings.append(
            _finding(
                "MISSING_HSTS",
                "HTTP Strict Transport Security is not present",
                "high",
                "The response does not advertise an HSTS policy.",
                "After confirming all subdomains support HTTPS, deploy a suitable Strict-Transport-Security policy.",
            )
        )
    if "content-security-policy" not in normalized:
        findings.append(
            _finding(
                "MISSING_CSP",
                "Content Security Policy is not present",
                "medium",
                "The response does not include a Content-Security-Policy header.",
                "Define a restrictive CSP based on the application's actual script, style, image and connection requirements.",
            )
        )
    if normalized.get("x-content-type-options", "").lower() != "nosniff":
        findings.append(
            _finding(
                "MISSING_NOSNIFF",
                "MIME sniffing protection is missing",
                "low",
                "X-Content-Type-Options is absent or does not use nosniff.",
                "Set X-Content-Type-Options: nosniff.",
            )
        )
    csp = normalized.get("content-security-policy", "").lower()
    if "x-frame-options" not in normalized and "frame-ancestors" not in csp:
        findings.append(
            _finding(
                "MISSING_FRAME_PROTECTION",
                "Clickjacking protection is not apparent",
                "medium",
                "Neither X-Frame-Options nor a CSP frame-ancestors directive was detected.",
                "Set frame-ancestors in Content-Security-Policy; use X-Frame-Options for legacy clients where needed.",
            )
        )
    if "referrer-policy" not in normalized:
        findings.append(
            _finding(
                "MISSING_REFERRER_POLICY",
                "Referrer Policy is not present",
                "low",
                "The response does not define a Referrer-Policy.",
                "Set Referrer-Policy to a policy appropriate for the application, such as strict-origin-when-cross-origin.",
            )
        )
    if "permissions-policy" not in normalized:
        findings.append(
            _finding(
                "MISSING_PERMISSIONS_POLICY",
                "Permissions Policy is not present",
                "low",
                "The response does not define a Permissions-Policy.",
                "Explicitly disable browser features the application does not need.",
            )
        )
    if "x-powered-by" in normalized:
        findings.append(
            _finding(
                "TECHNOLOGY_DISCLOSURE",
                "Server technology disclosure header detected",
                "low",
                "The response includes an X-Powered-By header.",
                "Remove unnecessary technology disclosure headers.",
            )
        )
    return findings
