"""Third-party risk — vendor security questionnaire scoring.

A questionnaire is a set of weighted yes/no/partial/na questions (CAIQ/SIG-style).
Scoring is a pure function of the answers: the weighted share of satisfied
controls → a 0-100 score → a risk rating. ``no`` answers on any question are
flagged as gaps. The built-in :data:`DEFAULT_TEMPLATE` is a compact CAIQ-lite
that ships with the platform; organizations can define their own.
"""

from __future__ import annotations

from typing import Any

# answer → compliance credit; ``na`` is excluded from the denominator entirely,
# ``unanswered`` scores nothing but still counts against completeness.
_CREDIT = {"yes": 1.0, "partial": 0.5, "no": 0.0, "unanswered": 0.0}
_SCORED = {"yes", "partial", "no", "unanswered"}  # 'na' excluded

# Built-in CAIQ-lite template: (question_id, domain, text, weight).
DEFAULT_TEMPLATE: dict[str, Any] = {
    "key": "caiq_lite",
    "name": "CAIQ-Lite Vendor Security Assessment",
    "framework": "CAIQ",
    "version": "1.0",
    "questions": [
        {"id": "GOV-01", "domain": "Governance", "weight": 2,
         "text": "Do you maintain a documented security program with executive ownership?"},
        {"id": "GOV-02", "domain": "Governance", "weight": 3,
         "text": "Do you hold a current attestation (SOC 2 Type II, ISO 27001, or FedRAMP)?"},
        {"id": "IAM-01", "domain": "Access Control", "weight": 3,
         "text": "Is MFA enforced for all administrative and remote access?"},
        {"id": "IAM-02", "domain": "Access Control", "weight": 2,
         "text": "Do you review access periodically and revoke it on personnel termination?"},
        {"id": "DAT-01", "domain": "Data Protection", "weight": 3,
         "text": "Is customer data encrypted at rest and in transit with strong ciphers?"},
        {"id": "DAT-02", "domain": "Data Protection", "weight": 2,
         "text": "Do you support data segregation and documented retention/deletion?"},
        {"id": "VUL-01", "domain": "Vulnerability Mgmt", "weight": 2,
         "text": "Do you run regular vulnerability scanning and remediate on a defined SLA?"},
        {"id": "IR-01", "domain": "Incident Response", "weight": 3,
         "text": "Do you have an IR plan with customer breach-notification commitments?"},
        {"id": "BCP-01", "domain": "Resilience", "weight": 2,
         "text": "Do you maintain and test business-continuity and disaster-recovery plans?"},
        {"id": "SUP-01", "domain": "Supply Chain", "weight": 2,
         "text": "Do you assess the security of your own subprocessors / fourth parties?"},
    ],
}

# score band → vendor risk rating (higher score = lower risk).
_BANDS = [(90, "low"), (75, "moderate"), (50, "high")]


def rating_for(score: float) -> str:
    for threshold, rating in _BANDS:
        if score >= threshold:
            return rating
    return "critical"


def score_responses(responses: list[dict[str, Any]]) -> dict[str, Any]:
    """Score a set of answered responses.

    Each response is ``{"answer", "weight"}``. Returns ``score`` (0-100 over the
    scored, non-``na`` weight), ``rating``, ``answered``/``total`` counts, and the
    list of flagged (``no``) question ids.
    """
    total = len(responses)
    earned = 0.0
    possible = 0.0
    answered = 0
    flagged: list[str] = []
    for r in responses:
        ans = str(r.get("answer", "unanswered")).lower()
        weight = float(r.get("weight", 1) or 1)
        if ans not in _SCORED and ans != "na":
            ans = "unanswered"
        if ans == "na":
            continue
        if ans != "unanswered":
            answered += 1
        possible += weight
        earned += weight * _CREDIT.get(ans, 0.0)
        if ans == "no":
            fid = r.get("question_id")
            if fid:
                flagged.append(str(fid))
    score = round(100 * earned / possible, 1) if possible else 0.0
    return {
        "score": score,
        "rating": rating_for(score),
        "answered": answered,
        "total": total,
        "flagged": flagged,
    }
