from typing import Optional
from pydantic import BaseModel
from ..monitor.canary_manager import CanaryFile

class CanaryTripwireAlert(BaseModel):
    rule_name: str = "CANARY_HONEYPOT_TRIPPED"
    canary_path: str
    canary_name: str
    file_type: str
    trip_reason: str
    confidence: float = 1.0
    threat_description: str
    mitre_technique: str = "T1486: Data Encrypted for Impact"

class CanaryTripwireDetector:
    """
    Stage 2 Detector: High-fidelity zero-false-positive detection via sacrificial Canary Tripwires.
    """

    @staticmethod
    def evaluate_trip(canary: CanaryFile) -> CanaryTripwireAlert:
        return CanaryTripwireAlert(
            canary_path=canary.path,
            canary_name=canary.filename,
            file_type=canary.file_type,
            trip_reason=canary.trip_reason or "Unauthorized write/modification to decoy honeypot",
            confidence=1.0,
            threat_description=(
                f"HIGH FIDELITY ALERT: Decoy Canary Honeypot '{canary.filename}' was modified/encrypted! "
                f"Reason: {canary.trip_reason}. This is a confirmed, active ransomware attack."
            )
        )
