"""Deterministic and explainable risk aggregation for posture findings."""

from math import exp

SEVERITY_POINTS = {"critical": 100.0, "high": 70.0, "medium": 35.0, "low": 10.0, "info": 1.0}


def calculate_risk(findings: list[dict], context: dict | None = None) -> dict:
    """Aggregate unique findings with confidence and asset-criticality weighting.

    Formula:
        raw = sum(severity_points * confidence * asset_criticality)
        score = round(100 * (1 - exp(-raw / 50)))

    Any critical finding forces a score of 100. Duplicate finding codes are
    counted once, preventing repeated evidence from inflating risk.
    """
    context = context or {}
    criticality = context.get("asset_criticality", 1.0)
    try:
        criticality = float(criticality)
    except (TypeError, ValueError):
        criticality = 1.0
    criticality = min(1.5, max(0.5, criticality))

    unique: dict[str, dict] = {}
    for index, finding in enumerate(findings):
        code = str(finding.get("code") or f"__finding_{index}")
        category = str(finding.get("category") or "general")
        key = f"{category}:{code}"
        severity = str(finding.get("severity", "info")).lower()
        if severity not in SEVERITY_POINTS:
            severity = "info"
        try:
            confidence = float(finding.get("confidence", 1.0))
        except (TypeError, ValueError):
            confidence = 1.0
        confidence = min(1.0, max(0.25, confidence))
        normalized = {
            **finding,
            "severity": severity,
            "confidence": confidence,
            "_risk_points": SEVERITY_POINTS[severity] * confidence * criticality,
        }
        current = unique.get(key)
        if current is None or normalized["_risk_points"] > current["_risk_points"]:
            unique[key] = normalized

    counts = {severity: 0 for severity in SEVERITY_POINTS}
    for finding in unique.values():
        counts[finding["severity"]] += 1

    raw_points = sum(item["_risk_points"] for item in unique.values())
    has_critical = counts["critical"] > 0
    score = (
        100
        if has_critical
        else (0 if raw_points <= 0 else min(100, round(100 * (1 - exp(-raw_points / 50)))))
    )
    if has_critical or score >= 90:
        level = "critical"
    elif score >= 70:
        level = "high"
    elif score >= 40:
        level = "moderate"
    elif score > 0:
        level = "low"
    else:
        level = "informational"

    drivers = sorted(
        (
            {
                "code": item.get("code", "UNSPECIFIED"),
                "severity": item["severity"],
                "weighted_points": round(item["_risk_points"], 2),
                "confidence": item["confidence"],
            }
            for item in unique.values()
        ),
        key=lambda item: item["weighted_points"],
        reverse=True,
    )[:5]

    return {
        "score": score,
        "level": level,
        "counts": counts,
        "explanation": {
            "model": "sentinel-exponential-v2",
            "formula": "critical => 100; otherwise round(100 * (1 - exp(-weighted_points / 50)))",
            "raw_weighted_points": round(raw_points, 2),
            "asset_criticality_multiplier": criticality,
            "unique_findings": len(unique),
            "drivers": drivers,
        },
    }
