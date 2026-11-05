import hmac

from fastapi import Header, HTTPException, status

from app.config import get_settings


def require_api_key(x_api_key: str | None = Header(default=None, alias="X-API-Key")) -> None:
    configured = get_settings().configured_api_keys
    if not configured or any(len(key) < 32 for key in configured):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="API authentication is not securely configured. Configure one or more keys of at least 32 characters.",
        )
    supplied = x_api_key or ""
    # Evaluate every candidate to avoid an early-exit comparison oracle.
    matches = [hmac.compare_digest(supplied, candidate) for candidate in configured]
    if not any(matches):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or missing API key."
        )
