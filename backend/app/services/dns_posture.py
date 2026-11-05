import re

import dns.exception
import dns.resolver


def _records(resolver, name: str, record_type: str) -> list[str]:
    try:
        answers = resolver.resolve(name, record_type)
        return [answer.to_text().replace('"', "") for answer in answers]
    except (
        dns.resolver.NoAnswer,
        dns.resolver.NXDOMAIN,
        dns.resolver.NoNameservers,
        dns.exception.Timeout,
    ):
        return []


def _finding(code: str, title: str, severity: str, description: str, recommendation: str) -> dict:
    return {
        "code": code,
        "title": title,
        "severity": severity,
        "category": "dns",
        "confidence": 0.95,
        "description": description,
        "recommendation": recommendation,
    }


def inspect_dns_posture(hostname: str) -> tuple[dict, list[dict]]:
    resolver = dns.resolver.Resolver()
    resolver.timeout = 2.0
    resolver.lifetime = 4.0
    findings: list[dict] = []

    mx_records = _records(resolver, hostname, "MX")
    spf_records = [
        record.strip()
        for record in _records(resolver, hostname, "TXT")
        if re.match(r"^v=spf1(?:\s|$)", record.strip(), re.IGNORECASE)
    ]
    dmarc_records = [
        record.strip()
        for record in _records(resolver, f"_dmarc.{hostname}", "TXT")
        if re.match(r"^v=dmarc1(?:\s|;|$)", record.strip(), re.IGNORECASE)
    ]
    caa_records = []
    caa_source = None
    labels = hostname.split(".")
    # CAA processing walks up the DNS label tree. A subdomain without its own
    # CAA RRset may still inherit the policy published by a parent domain.
    for index in range(len(labels)):
        candidate = ".".join(labels[index:])
        caa_records = _records(resolver, candidate, "CAA")
        if caa_records:
            caa_source = candidate
            break
    mta_sts_records = [
        record.strip()
        for record in _records(resolver, f"_mta-sts.{hostname}", "TXT")
        if re.match(r"^v=stsv1(?:\s|;|$)", record.strip(), re.IGNORECASE)
    ]
    tls_rpt_records = [
        record.strip()
        for record in _records(resolver, f"_smtp._tls.{hostname}", "TXT")
        if re.match(r"^v=tlsrptv1(?:\s|;|$)", record.strip(), re.IGNORECASE)
    ]

    result = {
        "mx": bool(mx_records),
        "spf": bool(spf_records),
        "spf_record_count": len(spf_records),
        "dmarc": bool(dmarc_records),
        "dmarc_policy": None,
        "caa": bool(caa_records),
        "caa_source": caa_source,
        "mta_sts": bool(mta_sts_records),
        "tls_rpt": bool(tls_rpt_records),
    }

    if not mx_records:
        findings.append(
            _finding(
                "DNS_MX_MISSING",
                "No MX records detected",
                "info",
                "No mail exchanger record was returned for the target domain.",
                "Confirm whether the domain is intended to receive email; no MX record may be expected for non-mail domains.",
            )
        )

    if not spf_records:
        findings.append(
            _finding(
                "DNS_SPF_MISSING",
                "SPF record not detected",
                "medium",
                "No SPF TXT policy was detected at the domain apex.",
                "Publish one well-formed SPF policy covering legitimate senders; avoid multiple SPF records.",
            )
        )
    elif len(spf_records) > 1:
        findings.append(
            _finding(
                "DNS_SPF_MULTIPLE",
                "Multiple SPF records detected",
                "high",
                f"{len(spf_records)} SPF records were returned; receivers can treat this as a permanent SPF error.",
                "Consolidate authorized senders into one SPF record and remove duplicate SPF TXT policies.",
            )
        )
    else:
        terminal = re.search(r"(?:^|\s)([+\-~?]?)all(?:\s|$)", spf_records[0], re.IGNORECASE)
        qualifier = terminal.group(1) if terminal else None
        if qualifier in ("", "+"):
            findings.append(
                _finding(
                    "DNS_SPF_PERMISSIVE",
                    "SPF policy permits every sender",
                    "high",
                    "The SPF policy ends with an allow-all mechanism.",
                    "Replace the allow-all mechanism with a policy that enumerates legitimate senders and uses an appropriate restrictive terminal mechanism.",
                )
            )
        elif qualifier == "?":
            findings.append(
                _finding(
                    "DNS_SPF_NEUTRAL",
                    "SPF policy ends in neutral",
                    "medium",
                    "The SPF policy does not explicitly authorize or reject unmatched senders.",
                    "Review legitimate sending infrastructure and choose an intentional terminal policy.",
                )
            )
        elif qualifier == "~":
            findings.append(
                _finding(
                    "DNS_SPF_SOFTFAIL",
                    "SPF policy uses softfail",
                    "low",
                    "Unmatched senders receive a softfail result rather than an explicit fail.",
                    "After validating all legitimate senders, consider whether an explicit fail policy is appropriate.",
                )
            )

    if not dmarc_records:
        findings.append(
            _finding(
                "DNS_DMARC_MISSING",
                "DMARC policy not detected",
                "medium",
                "No DMARC TXT policy was detected at _dmarc.",
                "Deploy DMARC with reporting first, then progress policy enforcement after validating legitimate senders.",
            )
        )
    elif len(dmarc_records) > 1:
        findings.append(
            _finding(
                "DNS_DMARC_MULTIPLE",
                "Multiple DMARC records detected",
                "high",
                "More than one DMARC policy was returned; receivers may treat the policy as invalid.",
                "Publish exactly one DMARC record at _dmarc and remove duplicates.",
            )
        )
    else:
        policy_match = re.search(
            r"(?:^|;)\s*p\s*=\s*(none|quarantine|reject)(?:;|$)", dmarc_records[0], re.IGNORECASE
        )
        policy = policy_match.group(1).lower() if policy_match else None
        result["dmarc_policy"] = policy
        if policy == "none":
            findings.append(
                _finding(
                    "DNS_DMARC_MONITOR_ONLY",
                    "DMARC is in monitoring-only mode",
                    "low",
                    "The published DMARC policy uses p=none and does not request quarantine or rejection.",
                    "Review aggregate reports and move to quarantine or reject when legitimate sending sources are aligned.",
                )
            )
        elif policy is None:
            findings.append(
                _finding(
                    "DNS_DMARC_POLICY_INVALID",
                    "DMARC policy tag could not be interpreted",
                    "medium",
                    "A DMARC version record exists, but a valid p= policy was not detected.",
                    "Validate the DMARC record syntax and publish exactly one supported p= policy.",
                )
            )

    if not caa_records:
        findings.append(
            _finding(
                "DNS_CAA_MISSING",
                "CAA policy not detected",
                "low",
                "No Certification Authority Authorization record was returned for the hostname.",
                "Consider publishing CAA records that identify the certificate authorities permitted to issue certificates for this domain.",
            )
        )

    if mx_records and not mta_sts_records:
        findings.append(
            _finding(
                "DNS_MTA_STS_MISSING",
                "MTA-STS policy discovery record not detected",
                "low",
                "The domain has MX records but no _mta-sts TXT discovery record was detected.",
                "If supported by your mail infrastructure, publish MTA-STS discovery and host a valid HTTPS policy file.",
            )
        )
    if mx_records and not tls_rpt_records:
        findings.append(
            _finding(
                "DNS_TLS_RPT_MISSING",
                "SMTP TLS reporting record not detected",
                "info",
                "The domain has MX records but no _smtp._tls TLS-RPT TXT record was detected.",
                "Consider publishing TLS-RPT to receive reports about SMTP TLS delivery failures.",
            )
        )

    return result, findings
