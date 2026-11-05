import ipaddress
import re

_DOMAIN_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


class ScopeViolation(ValueError):
    """Raised when an assessment target is outside the configured authorization scope."""


def normalize_domain(value: str) -> str:
    if not isinstance(value, str):
        raise ScopeViolation("Target must be a DNS hostname.")
    candidate = value.strip().rstrip(".")
    if not candidate or "://" in candidate or any(char in candidate for char in "/?#@"):
        raise ScopeViolation(
            "Provide a hostname only; schemes, paths and userinfo are not accepted."
        )
    try:
        candidate = candidate.encode("idna").decode("ascii").lower()
        ipaddress.ip_address(candidate)
    except ValueError:
        pass
    except UnicodeError as exc:
        raise ScopeViolation("Target hostname is not valid IDNA.") from exc
    try:
        ipaddress.ip_address(candidate)
    except ValueError:
        pass
    else:
        raise ScopeViolation("IP literals are not accepted; authorize a DNS hostname.")
    if len(candidate) > 253 or "." not in candidate:
        raise ScopeViolation("Target must be a fully-qualified DNS hostname.")
    labels = candidate.split(".")
    if any(not _DOMAIN_LABEL.fullmatch(label) for label in labels):
        raise ScopeViolation("Target hostname contains an invalid DNS label.")
    return candidate


def authorize_domain(target: str, allowed_domains: list[str] | tuple[str, ...]) -> str:
    domain = normalize_domain(target)
    allowed: list[str] = []
    for item in allowed_domains:
        try:
            allowed.append(normalize_domain(item))
        except ScopeViolation:
            continue
    if not any(domain == item or domain.endswith("." + item) for item in allowed):
        raise ScopeViolation("Target is not in the explicitly configured authorized domain scope.")
    return domain
