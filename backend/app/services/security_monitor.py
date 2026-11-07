"""Defensive request classification and trusted-proxy evidence helpers."""

from __future__ import annotations

import hashlib
import hmac
import json
from datetime import UTC, datetime, timedelta
from ipaddress import ip_address, ip_network

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models import AuditEvent
from app.services.audit import record_audit_event
from urllib.parse import unquote


_HONEYPOT_PATHS: tuple[tuple[str, str], ...] = (
    ("/.env", "sensitive_file_probe"),
    ("/.git", "repository_metadata_probe"),
    ("/.aws", "sensitive_file_probe"),
    ("/wp-admin", "admin_console_probe"),
    ("/wp-login.php", "admin_console_probe"),
    ("/phpmyadmin", "admin_console_probe"),
    ("/adminer.php", "admin_console_probe"),
    ("/actuator/env", "sensitive_file_probe"),
    ("/server-status", "server_status_probe"),
    ("/.well-known/sentinel-canary", "decoy_canary_probe"),
)


def classify_honeypot_path(path: str) -> str | None:
    """Return a stable rule ID for a known decoy path, otherwise None.

    Query strings are intentionally irrelevant. A path only matches an exact
    decoy or a child path, so names such as '.env.example' are not false hits.
    """
    decoded = unquote((path or "").split("?", 1)[0], errors="replace")
    normalized = decoded.replace("\\", "/").casefold()
    if not normalized.startswith("/"):
        normalized = "/" + normalized
    for prefix, rule_id in _HONEYPOT_PATHS:
        if normalized == prefix or normalized.startswith(prefix + "/"):
            return rule_id
    return None


def resolve_client_ip(
    *,
    peer_ip: str | None,
    x_real_ip: str | None,
    trusted_proxy_cidrs: list[str] | tuple[str, ...] = (),
) -> str:
    """Trust X-Real-IP only when the immediate peer is in an operator allowlist.

    X-Forwarded-For is deliberately not accepted. The reverse proxy must
    overwrite X-Real-IP from its actual socket peer, never append caller input.
    """
    try:
        peer = ip_address(peer_ip or "")
    except ValueError:
        return "unknown"

    trusted = False
    for cidr in trusted_proxy_cidrs:
        try:
            if peer in ip_network(cidr, strict=False):
                trusted = True
                break
        except ValueError:
            # Invalid proxy configuration is ignored here; startup validation
            # rejects it before production requests are accepted.
            continue

    if trusted and x_real_ip:
        try:
            candidate = ip_address(x_real_ip.strip())
            if not candidate.is_unspecified and not candidate.is_multicast:
                return candidate.compressed
        except ValueError:
            pass
    return peer.compressed


def sanitize_user_agent(value: str | None, *, max_length: int = 256) -> str:
    """Keep a short printable user-agent label; never store arbitrary headers."""
    if not value:
        return ""
    cleaned = "".join(character for character in value if character.isprintable())
    return cleaned[:max_length]


def classify_security_response(path: str, status_code: int) -> dict[str, str] | None:
    """Classify defensive signals after routing/authentication has completed."""
    honeypot_rule = classify_honeypot_path(path)
    if honeypot_rule:
        # Repeated decoy hits rejected by the honeypot Redis bucket are not
        # persisted again; otherwise a blocked flood could still fill the DB.
        if status_code == 429:
            return None
        return {
            "event_type": "security.honeypot_probe",
            "severity": "high",
            "rule_id": honeypot_rule,
        }
    if path.startswith("/api/v1/") and status_code == 401:
        return {
            "event_type": "security.api_auth_failure",
            "severity": "medium",
            "rule_id": "API_AUTH_FAILURE",
        }
    if path.startswith("/api/v1/") and status_code == 429:
        return {
            "event_type": "security.rate_limit_exceeded",
            "severity": "medium",
            "rule_id": "API_RATE_LIMIT",
        }
    return None


def sign_alert_payload(payload: dict, secret: str) -> tuple[bytes, str]:
    """Serialize a stable alert body and return its HMAC-SHA256 signature."""
    body = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )
    signature = hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
    return body, "sha256=" + signature



def persist_security_evidence(
    db: Session,
    *,
    signal: dict[str, str],
    source_ip: str,
    path: str,
    method: str,
    user_agent: str,
    request_id: str,
    auth_failure_threshold: int = 5,
    auth_failure_window_seconds: int = 300,
) -> list[dict[str, str | int]]:
    """Append sanitized security signals to the existing hash-linked audit chain.

    Only the URL path (never its query string), a validated source IP, a bounded
    user-agent label and a request correlation ID are stored. Request bodies,
    cookies and credential values are deliberately excluded.
    """
    now = datetime.now(UTC)
    safe = {
        "rule_id": signal["rule_id"][:80],
        "severity": signal["severity"][:16],
        "source_ip": source_ip[:64],
        "path": path.split("?", 1)[0][:253],
        "method": method[:12].upper(),
        "user_agent": sanitize_user_agent(user_agent),
        "request_id": request_id[:64],
        "observed_at": now.isoformat(),
    }
    db.add(
        record_audit_event(
            db,
            event_type=signal["event_type"],
            subject=source_ip,
            result=signal["severity"],
            details=json.dumps(safe, sort_keys=True, separators=(",", ":")),
        )
    )
    # SessionLocal intentionally disables autoflush. Flush the first audit
    # record before appending a second event in the same transaction so that
    # sequence allocation observes the newly assigned chain tail.
    db.flush()
    alerts: list[dict[str, str | int]] = []
    if signal["event_type"] == "security.api_auth_failure" and source_ip != "unknown":
        cutoff = now - timedelta(seconds=auth_failure_window_seconds)
        previous_failures = db.scalar(
            select(func.count())
            .select_from(AuditEvent)
            .where(
                AuditEvent.event_type == "security.api_auth_failure",
                AuditEvent.subject == source_ip,
                AuditEvent.created_at >= cutoff,
            )
        ) or 0
        failure_count = int(previous_failures) + 1
        already_alerted = db.scalar(
            select(AuditEvent.id)
            .where(
                AuditEvent.event_type == "security.brute_force_detected",
                AuditEvent.subject == source_ip,
                AuditEvent.created_at >= cutoff,
            )
            .limit(1)
        )
        if failure_count >= auth_failure_threshold and not already_alerted:
            brute_force = {
                **safe,
                "rule_id": "AUTH_BRUTE_FORCE",
                "severity": "critical",
                "failure_count": failure_count,
                "window_seconds": auth_failure_window_seconds,
            }
            db.add(
                record_audit_event(
                    db,
                    event_type="security.brute_force_detected",
                    subject=source_ip,
                    result="critical",
                    details=json.dumps(brute_force, sort_keys=True, separators=(",", ":")),
                )
            )
            alerts.append(brute_force)
    if signal["severity"] in {"high", "critical"}:
        alerts.append(safe)
    return alerts
