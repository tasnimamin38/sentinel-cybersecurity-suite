import hashlib
import re
from pathlib import Path

_PATTERNS = [
    ("GITHUB_TOKEN", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b")),
    ("AWS_ACCESS_KEY", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("SLACK_TOKEN", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{20,}\b")),
    ("PRIVATE_KEY", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
]


def _redacted_evidence(value: str) -> str:
    digest = hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()[:12]
    return f"[REDACTED] sha256:{digest}"


def scan_text(text: str) -> list[dict]:
    findings: list[dict] = []
    for kind, pattern in _PATTERNS:
        for match in pattern.finditer(text):
            raw = match.group(0)
            findings.append(
                {
                    "code": f"EXPOSED_{kind}",
                    "title": f"Potential {kind.replace('_', ' ').lower()} detected",
                    "severity": "high",
                    "category": "secret-hygiene",
                    "evidence": _redacted_evidence(raw),
                    "description": "A credential-like pattern was detected. The matched value is never returned.",
                    "recommendation": "Revoke or rotate the credential, inspect its usage, and move secrets to a managed secret store.",
                }
            )
    return findings


def scan_directory(root: str, max_file_bytes: int = 1_000_000) -> list[dict]:
    base = Path(root).resolve(strict=True)
    findings: list[dict] = []
    skipped_dirs = {".git", "node_modules", ".venv", "venv", "__pycache__", "dist", "build"}
    for path in base.rglob("*"):
        if not path.is_file() or any(part in skipped_dirs for part in path.parts):
            continue
        try:
            resolved = path.resolve(strict=True)
            resolved.relative_to(base)
            if resolved.stat().st_size > max_file_bytes:
                continue
            content = resolved.read_bytes()
            if b"\x00" in content:
                continue
            text = content.decode("utf-8")
        except (OSError, UnicodeDecodeError, ValueError):
            continue
        for item in scan_text(text):
            findings.append({**item, "path": str(resolved.relative_to(base))})
    return findings