CONTROL_CATALOG = [
    {
        "id": "SNT-ASSET-01",
        "family": "Asset governance",
        "title": "Authorized asset ownership",
        "description": "Every managed asset has an owner, scope reference and time-bounded authorization.",
        "mapped_findings": [],
        "operational": "Asset registry",
    },
    {
        "id": "SNT-WEB-01",
        "family": "Secure configuration",
        "title": "Browser security response headers",
        "description": "Review HSTS, CSP, MIME sniffing, framing, referrer and permissions controls.",
        "mapped_findings": [
            "MISSING_HSTS",
            "MISSING_CSP",
            "MISSING_NOSNIFF",
            "MISSING_FRAME_PROTECTION",
            "MISSING_REFERRER_POLICY",
            "MISSING_PERMISSIONS_POLICY",
            "TECHNOLOGY_DISCLOSURE",
            "HSTS_MAX_AGE_SHORT",
            "HSTS_SUBDOMAINS_NOT_COVERED",
            "CSP_UNSAFE_EVAL",
            "CSP_UNSAFE_INLINE_SCRIPT",
            "CSP_WILDCARD_SCRIPT_SOURCE",
            "REFERRER_POLICY_WEAK",
            "PERMISSIONS_POLICY_WILDCARD",
        ],
        "operational": "HTTPS posture assessment",
    },
    {
        "id": "SNT-EMAIL-01",
        "family": "Email domain protection",
        "title": "Sender authentication posture",
        "description": "Inspect MX, SPF, DMARC, CAA, MTA-STS and SMTP TLS reporting DNS posture without changing DNS records.",
        "mapped_findings": [
            "DNS_MX_MISSING",
            "DNS_SPF_MISSING",
            "DNS_SPF_MULTIPLE",
            "DNS_SPF_PERMISSIVE",
            "DNS_SPF_NEUTRAL",
            "DNS_SPF_SOFTFAIL",
            "DNS_DMARC_MISSING",
            "DNS_DMARC_MULTIPLE",
            "DNS_DMARC_MONITOR_ONLY",
            "DNS_DMARC_POLICY_INVALID",
            "DNS_CAA_MISSING",
            "DNS_MTA_STS_MISSING",
            "DNS_TLS_RPT_MISSING",
            "DNS_POSTURE_INCOMPLETE",
        ],
        "operational": "DNS posture assessment",
    },
    {
        "id": "SNT-TLS-01",
        "family": "Transport protection",
        "title": "TLS certificate lifecycle",
        "description": "Inspect certificate trust metadata and expiry using validated HTTPS transport.",
        "mapped_findings": ["TLS_CERT_EXPIRING", "HTTPS_CHECK_FAILED"],
        "operational": "DNS-pinned HTTPS assessment",
    },
    {
        "id": "SNT-SECRET-01",
        "family": "Credential hygiene",
        "title": "Secret exposure prevention",
        "description": "Detect selected credential-like patterns while returning redacted evidence only.",
        "mapped_findings": [
            "EXPOSED_GITHUB_TOKEN",
            "EXPOSED_AWS_ACCESS_KEY",
            "EXPOSED_SLACK_TOKEN",
            "EXPOSED_PRIVATE_KEY",
        ],
        "operational": "Secret hygiene library",
    },
]


def controls_for_findings(findings: list[dict]) -> list[dict]:
    codes = {str(item.get("code")) for item in findings}
    results = []
    for control in CONTROL_CATALOG:
        matched = sorted(codes.intersection(control["mapped_findings"]))
        results.append(
            {
                **control,
                "matched_findings": matched,
                "status": "attention" if matched else "not_observed",
            }
        )
    return results
