import dns.resolver


def inspect_dns_posture(hostname: str) -> tuple[dict, list[dict]]:
    resolver = dns.resolver.Resolver()
    resolver.timeout = 2.0
    resolver.lifetime = 4.0
    result = {"mx": False, "spf": False, "dmarc": False}
    findings: list[dict] = []

    try:
        answers = resolver.resolve(hostname, "MX")
        result["mx"] = len(answers) > 0
    except (
        dns.resolver.NoAnswer,
        dns.resolver.NXDOMAIN,
        dns.resolver.NoNameservers,
        dns.exception.Timeout,
    ):
        findings.append(
            {
                "code": "DNS_MX_MISSING",
                "title": "No MX records detected",
                "severity": "info",
                "category": "dns",
                "description": "No mail exchanger record was returned for the target domain.",
                "recommendation": "Confirm whether the domain is intended to receive email.",
            }
        )

    try:
        txt_records = resolver.resolve(hostname, "TXT")
        spf_records = [
            record.to_text().strip('"')
            for record in txt_records
            if "v=spf1" in record.to_text().lower()
        ]
        result["spf"] = bool(spf_records)
    except (
        dns.resolver.NoAnswer,
        dns.resolver.NXDOMAIN,
        dns.resolver.NoNameservers,
        dns.exception.Timeout,
    ):
        spf_records = []
    if not result["spf"]:
        findings.append(
            {
                "code": "DNS_SPF_MISSING",
                "title": "SPF record not detected",
                "severity": "medium",
                "category": "dns",
                "description": "No SPF TXT policy was detected at the domain apex.",
                "recommendation": "Publish one well-formed SPF policy covering legitimate senders; avoid multiple SPF records.",
            }
        )

    try:
        dmarc_records = resolver.resolve(f"_dmarc.{hostname}", "TXT")
        result["dmarc"] = any("v=dmarc1" in record.to_text().lower() for record in dmarc_records)
    except (
        dns.resolver.NoAnswer,
        dns.resolver.NXDOMAIN,
        dns.resolver.NoNameservers,
        dns.exception.Timeout,
    ):
        pass
    if not result["dmarc"]:
        findings.append(
            {
                "code": "DNS_DMARC_MISSING",
                "title": "DMARC policy not detected",
                "severity": "medium",
                "category": "dns",
                "description": "No DMARC TXT policy was detected at _dmarc.",
                "recommendation": "Deploy DMARC with reporting first, then progress policy enforcement after validating legitimate senders.",
            }
        )
    return result, findings