WEIGHTS = {"critical": 100, "high": 70, "medium": 35, "low": 10, "info": 0}


def calculate_risk(findings: list[dict]) -> dict:
    if not findings:
        return {"score": 0, "level": "informational", "counts": {key: 0 for key in WEIGHTS}}
    counts = {key: 0 for key in WEIGHTS}
    for item in findings:
        severity = str(item.get("severity", "info")).lower()
        counts[severity if severity in counts else "info"] += 1
    score = (
        100
        if counts["critical"]
        else min(100, sum(WEIGHTS[key] * count for key, count in counts.items()))
    )
    if counts["critical"] or score >= 90:
        level = "critical"
    elif score >= 70:
        level = "high"
    elif score >= 35:
        level = "moderate"
    elif score > 0:
        level = "low"
    else:
        level = "informational"
    return {"score": score, "level": level, "counts": counts}