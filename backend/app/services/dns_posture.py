import re
import time

import dns.exception
import dns.resolver


def _records(resolver, name: str, record_type: str, deadline: float) -> tuple[list[str], bool]:
    """Return records and whether the lookup completed authoritatively."""
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        return [], False
    try:
        answers = resolver.resolve(name, record_type, lifetime=remaining)
        return [answer.to_text().replace('"', "") for answer in answers], True
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        return [], True
    except (dns.resolver.NoNameservers, dns.exception.Timeout):
        return [], False


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


def inspect_dns_posture(hostname: str, timeout: float = 4.0) -> tuple[dict, list[dict]]:
    """Inspect DNS posture with one shared fail-closed time budget."""
    resolver = dns.resolver.Resolver()
    resolver.timeout = min(1.0, timeout)
    resolver.lifetime = timeout
    deadline = time.monotonic() + timeout
    findings: list[dict] = []
    incomplete_checks: list[str] = []

    mx_records, mx_complete = _records(resolver, hostname, "MX", deadline)
    if not mx_complete:
        incomplete_checks.append("MX")

    apex_txt, spf_complete = _records(resolver, hostname, "TXT", deadline)
    if not spf_complete:
        incomplete_checks.append("SPF")
    spf_records = [
        record.strip()
        for record in apex_txt
        if re.match(r"^v=spf1(?:\s|$)", record.strip(), re.IGNORECASE)
    ]

    dmarc_txt, dmarc_complete = _records(resolver, f"_dmarc.{hostname}", "TXT", deadline)
    if not dmarc_complete:
        incomplete_checks.append("DMARC")
    dmarc_records = [
        record.strip()
        for record in dmarc_txt
        if re.match(r"^v=dmarc1(?:\s|;|$)", record.strip(), re.IGNORECASE)
    ]

    caa_records = []
    caa_source = None
    caa_complete = True
    labels = hostname.split(".")
    # CAA processing walks up the DNS label tree; parent records may govern a subdomain.
    for index in range(len(labels)):
        candidate = ".".join(labels[index:])
        caa_records, caa_complete = _records(resolver, candidate, "CAA", deadline)
        if not caa_complete:
            incomplete_checks.append("CAA")
            break
        if caa_records:
            caa_source = candidate
            break

    mta_sts_records = []
    mta_sts_complete = True
    tls_rpt_records = []
    tls_rpt_complete = True
    if mx_records and mx_complete:
        mta_txt, mta_sts_complete = _records(resolver, f"_mta-sts.{hostname}", "TXT", deadline)
        if not mta_sts_complete:
            incomplete_checks.append("MTA-STS")
        mta_sts_records = [
            record.strip()
            for record in mta_txt
            if re.match(r"^v=stsv1(?:\s|;|$)", record.strip(), re.IGNORECASE)
        ]

        rpt_txt, tls_rpt_complete = _records(resolver, f"_smtp._tls.{hostname}", "TXT", deadline)
        if not tls_rpt_complete:
            incomplete_checks.append("TLS-RPT")
        tls_rpt_records = [
            record.strip()
            for record in rpt_txt
            if re.match(r"^v=tlsrptv1(?:\s|;|$)", record.strip(), re.IGNORECASE)
        ]

    result = {
        "complete": not incomplete_checks,
        "incomplete_checks": list(dict.fromkeys(incomplete_checks)),
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

    if mx_complete and not mx_records:
        findings.append(
            _finding(
                "DNS_MX_MISSING",
                "No MX records detected",
                "info",
                "No mail exchanger record was returned for the target domain.",
                "Confirm whether the domain is intended to receive email; no MX record may be expected for non-mail domains.",
            )
        )

    if spf_complete:
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

    if dmarc_complete:
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
                r"(?:^|;)\s*p\s*=\s*(none|quarantine|reject)(?:;|$)",
                dmarc_records[0],
                re.IGNORECASE,
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

    if caa_complete and not caa_records:
        findings.append(
            _finding(
                "DNS_CAA_MISSING",
                "CAA policy not detected",
                "low",
                "No CAA record was found at the hostname or any parent DNS label.",
                "Consider publishing CAA records that identify the certificate authorities permitted to issue certificates for this domain.",
            )
        )

    if mx_records and mx_complete:
        if mta_sts_complete and not mta_sts_records:
            findings.append(
                _finding(
                    "DNS_MTA_STS_MISSING",
                    "MTA-STS policy discovery record not detected",
                    "low",
                    "The domain has MX records but no _mta-sts TXT discovery record was detected.",
                    "If supported by your mail infrastructure, publish MTA-STS discovery and host a valid HTTPS policy file.",
                )
            )
        if tls_rpt_complete and not tls_rpt_records:
            findings.append(
                _finding(
                    "DNS_TLS_RPT_MISSING",
                    "SMTP TLS reporting record not detected",
                    "info",
                    "The domain has MX records but no _smtp._tls TLS-RPT TXT record was detected.",
                    "Consider publishing TLS-RPT to receive reports about SMTP TLS delivery failures.",
                )
            )

    if incomplete_checks:
        findings.append(
            _finding(
                "DNS_POSTURE_INCOMPLETE",
                "Some DNS posture checks did not complete",
                "low",
                "The shared DNS lookup budget expired or a resolver failure prevented a definitive answer for: "
                + ", ".join(dict.fromkeys(incomplete_checks))
                + ". Missing-record findings were suppressed for those checks.",
                "Repeat the assessment when the configured resolver is healthy; do not interpret incomplete checks as missing records.",
            )
        )

    return result, findings
