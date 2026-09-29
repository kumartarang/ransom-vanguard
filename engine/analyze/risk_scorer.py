from enum import Enum
from typing import List, Dict, Optional
from pydantic import BaseModel

class ThreatLevel(str, Enum):
    NORMAL = "NORMAL"
    LOW = "LOW"
    ELEVATED = "ELEVATED"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

class RiskAssessment(BaseModel):
    score: int # 0 - 100
    threat_level: ThreatLevel
    confidence: float # 0.0 - 1.0
    triggers: List[str]
    should_contain: bool
    rationale: str

class RiskScorer:
    """
    Stage 3 Analyzer: Correlates multi-vector detections and computes dynamic risk score (0-100).
    Determines whether automated instant containment is required.
    """

    WEIGHTS = {
        "canary_tripped": 50,
        "shadow_sabotage": 45,
        "ransom_extension": 35,
        "high_entropy_burst": 35,
        "ransom_note_drop": 30,
        "mass_rename_burst": 25,
        "suspicious_process_name": 30
    }

    CONTAINMENT_THRESHOLD = 60 # Trigger instant containment at or above score of 60

    @classmethod
    def evaluate(
        cls,
        has_canary_trip: bool = False,
        has_shadow_sabotage: bool = False,
        has_ransom_extension: bool = False,
        has_entropy_burst: bool = False,
        has_ransom_note: bool = False,
        has_mass_rename: bool = False,
        has_suspicious_proc: bool = False,
        extra_points: int = 0
    ) -> RiskAssessment:
        score = 0
        triggers = []

        if has_canary_trip:
            score += cls.WEIGHTS["canary_tripped"]
            triggers.append("Canary Honeypot Tripped (+50)")

        if has_shadow_sabotage:
            score += cls.WEIGHTS["shadow_sabotage"]
            triggers.append("VSS Shadow Copy / Recovery Sabotage Attempt (+45)")

        if has_ransom_extension:
            score += cls.WEIGHTS["ransom_extension"]
            triggers.append("Known Ransomware Extension Mutation (+35)")

        if has_entropy_burst:
            score += cls.WEIGHTS["high_entropy_burst"]
            triggers.append("Rapid High-Entropy Encryption Burst (+35)")

        if has_ransom_note:
            score += cls.WEIGHTS["ransom_note_drop"]
            triggers.append("Ransom Note File Dropped (+30)")

        if has_mass_rename:
            score += cls.WEIGHTS["mass_rename_burst"]
            triggers.append("Mass File Rename / Extension Mutation (+25)")

        if has_suspicious_proc:
            score += cls.WEIGHTS["suspicious_process_name"]
            triggers.append("Suspicious Ransomware Process Signature (+30)")

        score += extra_points
        score = min(100, max(0, score))

        # Determine Threat Level
        if score >= 80:
            threat_level = ThreatLevel.CRITICAL
            confidence = 0.99
        elif score >= 60:
            threat_level = ThreatLevel.HIGH
            confidence = 0.90
        elif score >= 40:
            threat_level = ThreatLevel.ELEVATED
            confidence = 0.75
        elif score >= 20:
            threat_level = ThreatLevel.LOW
            confidence = 0.50
        else:
            threat_level = ThreatLevel.NORMAL
            confidence = 0.20

        should_contain = score >= cls.CONTAINMENT_THRESHOLD

        rationale = f"Assessed composite risk of {score}/100 based on {len(triggers)} correlated threat factors. "
        if should_contain:
            rationale += "CRITICAL THRESHOLD BREACHED: Automated instant containment recommended."
        else:
            rationale += "Routine telemetry / sub-critical activity."

        return RiskAssessment(
            score=score,
            threat_level=threat_level,
            confidence=confidence,
            triggers=triggers,
            should_contain=should_contain,
            rationale=rationale
        )
