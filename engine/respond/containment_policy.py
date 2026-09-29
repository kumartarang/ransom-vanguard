from typing import Dict, Any
from pydantic import BaseModel

class ContainmentPolicy(BaseModel):
    mode: str = "AUTONOMOUS" # 'AUTONOMOUS' (<50ms auto-contain) or 'SEMI_AUTONOMOUS' (alert and wait for SOC)
    kill_process_enabled: bool = True
    isolate_network_enabled: bool = True
    quarantine_files_enabled: bool = True
    auto_recover_enabled: bool = True
    critical_threshold_score: int = 60

class ContainmentPolicyEngine:
    """
    Stage 5 Response: Policy evaluator to decide containment strategy.
    """

    def __init__(self, policy: ContainmentPolicy = ContainmentPolicy()):
        self.policy = policy

    def should_auto_contain(self, risk_score: int) -> bool:
        if self.policy.mode == "AUTONOMOUS":
            return risk_score >= self.policy.critical_threshold_score
        return False

    def update_policy(self, **kwargs):
        for k, v in kwargs.items():
            if hasattr(self.policy, k):
                setattr(self.policy, k, v)
