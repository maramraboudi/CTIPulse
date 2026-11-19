def priority_for(score: float) -> str:
    if score >= 80:
        return "Critical"
    if score >= 60:
        return "High"
    if score >= 40:
        return "Medium"
    return "Low"


def calculate_risk(cvss: float = 0, epss: float = 0, in_kev: bool = False, poc_count: int = 0) -> float:
    """Return a transparent 0-100 score using the project heuristic."""
    cvss_component = max(0, min(10, cvss)) / 10
    epss_component = max(0, min(1, epss))
    kev_component = 1 if in_kev else 0
    poc_component = 1 if poc_count > 0 else 0
    score = 10 * (
        0.25 * cvss_component
        + 0.35 * epss_component
        + 0.25 * kev_component
        + 0.15 * poc_component
    )
    return round(score * 10, 1)


def explain_risk(cvss: float, epss: float, in_kev: bool, poc_count: int) -> dict:
    score = calculate_risk(cvss, epss, in_kev, poc_count)
    signals = [
        {"name": "CVSS severity", "value": f"{cvss:.1f}/10", "weight": "25%", "included": cvss > 0},
        {"name": "EPSS likelihood", "value": f"{epss:.1%}", "weight": "35%", "included": epss > 0},
        {"name": "CISA KEV", "value": "Known exploited" if in_kev else "Not listed", "weight": "25%", "included": in_kev},
        {"name": "Public PoC", "value": f"{poc_count} repository/repositories" if poc_count else "Not found", "weight": "15%", "included": poc_count > 0},
    ]
    return {"score": score, "priority": priority_for(score), "signals": signals}
