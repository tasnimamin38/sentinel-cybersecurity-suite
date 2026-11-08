import re


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

    hsts = normalized.get("strict-transport-security")
    if not hsts:
        findings.append(
            _finding(
                "MISSING_HSTS",
                "HTTP Strict Transport Security is not present",
                "high",
                "The response does not advertise an HSTS policy.",
                "After confirming all subdomains support HTTPS, deploy a suitable Strict-Transport-Security policy.",
            )
        )
    else:
        max_age = re.search(r"(?:^|;)\s*max-age\s*=\s*(\d+)", hsts, re.IGNORECASE)
        if not max_age or int(max_age.group(1)) < 31_536_000:
            findings.append(
                _finding(
                    "HSTS_MAX_AGE_SHORT",
                    "HSTS max-age is missing or shorter than one year",
                    "low",
                    "The HSTS max-age directive is absent or below 31,536,000 seconds.",
                    "After testing HTTPS readiness, consider an HSTS max-age of at least one year.",
                )
            )
        if "includesubdomains" not in hsts.lower():
            findings.append(
                _finding(
                    "HSTS_SUBDOMAINS_NOT_COVERED",
                    "HSTS does not cover subdomains",
                    "info",
                    "The HSTS policy does not include the includeSubDomains directive.",
                    "If every subdomain is HTTPS-capable, consider includeSubDomains to extend browser enforcement.",
                )
            )

    csp = normalized.get("content-security-policy", "").lower()
    if not csp:
        findings.append(
            _finding(
                "MISSING_CSP",
                "Content Security Policy is not present",
                "medium",
                "The response does not include a Content-Security-Policy header.",
                "Define a restrictive CSP based on the application's actual script, style, image and connection requirements.",
            )
        )
    else:
        directives: dict[str, list[str]] = {}
        for item in csp.split(";"):
            parts = item.strip().split()
            if parts:
                # CSP uses the first occurrence of a directive; ignore duplicates.
                directives.setdefault(parts[0], parts[1:])

        has_script_fallback = "script-src" in directives or "default-src" in directives
        if not has_script_fallback:
            findings.append(
                _finding(
                    "CSP_SCRIPT_POLICY_UNRESTRICTED",
                    "CSP does not define a script-source fallback",
                    "high",
                    "Neither script-src nor default-src is present. Script requests not covered by a more specific script-src-elem directive may fall back to an unrestricted policy.",
                    "Define a restrictive script-src directive, or a suitable default-src fallback, and separately review script-src-elem and script-src-attr where used.",
                )
            )
        script_sources = directives.get("script-src", directives.get("default-src", []))
        if "'unsafe-eval'" in script_sources:
            findings.append(
                _finding(
                    "CSP_UNSAFE_EVAL",
                    "CSP permits unsafe JavaScript evaluation",
                    "high",
                    "The effective script policy includes 'unsafe-eval'.",
                    "Remove unsafe-eval and replace dynamic evaluation with safer application patterns.",
                )
            )
        if "'unsafe-inline'" in script_sources:
            findings.append(
                _finding(
                    "CSP_UNSAFE_INLINE_SCRIPT",
                    "CSP permits inline scripts",
                    "medium",
                    "The effective script policy includes 'unsafe-inline'.",
                    "Prefer nonces or hashes for required inline scripts and remove broad inline-script permission.",
                )
            )
        if "*" in script_sources:
            findings.append(
                _finding(
                    "CSP_WILDCARD_SCRIPT_SOURCE",
                    "CSP allows scripts from any source",
                    "high",
                    "The effective script policy contains a wildcard source.",
                    "Replace wildcard script sources with explicit trusted origins.",
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
    has_frame_ancestors = bool(directives.get("frame-ancestors")) if csp else False
    if "x-frame-options" not in normalized and not has_frame_ancestors:
        findings.append(
            _finding(
                "MISSING_FRAME_PROTECTION",
                "Clickjacking protection is not apparent",
                "medium",
                "Neither X-Frame-Options nor a CSP frame-ancestors directive was detected.",
                "Set frame-ancestors in Content-Security-Policy; use X-Frame-Options for legacy clients where needed.",
            )
        )
    referrer = normalized.get("referrer-policy", "").lower()
    if not referrer:
        findings.append(
            _finding(
                "MISSING_REFERRER_POLICY",
                "Referrer Policy is not present",
                "low",
                "The response does not define a Referrer-Policy.",
                "Set Referrer-Policy to a policy appropriate for the application, such as strict-origin-when-cross-origin.",
            )
        )
    elif referrer in {"unsafe-url", "no-referrer-when-downgrade"}:
        findings.append(
            _finding(
                "REFERRER_POLICY_WEAK",
                "Referrer Policy may disclose excessive URL information",
                "low",
                f"The response uses the {referrer} policy.",
                "Consider strict-origin-when-cross-origin or no-referrer based on application requirements.",
            )
        )
    permissions = normalized.get("permissions-policy", "").lower()
    if not permissions:
        findings.append(
            _finding(
                "MISSING_PERMISSIONS_POLICY",
                "Permissions Policy is not present",
                "low",
                "The response does not define a Permissions-Policy.",
                "Explicitly disable browser features the application does not need.",
            )
        )
    elif re.search(r"(?:^|[,;])\s*[a-z-]+\s*=\s*\*", permissions):
        findings.append(
            _finding(
                "PERMISSIONS_POLICY_WILDCARD",
                "Permissions Policy contains a wildcard allowlist",
                "medium",
                "At least one browser feature is allowed for all origins.",
                "Replace wildcard feature allowlists with explicit trusted origins or disable unused features.",
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
