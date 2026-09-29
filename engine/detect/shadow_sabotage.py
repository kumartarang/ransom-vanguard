import re
from typing import Dict, List, Optional
from pydantic import BaseModel
from ..monitor.process_sensor import ProcessInfo

class ShadowTamperAlert(BaseModel):
    rule_name: str
    pid: int
    process_name: str
    command_executed: str
    confidence: float = 1.0
    threat_description: str
    mitre_technique: str = "T1490: Inhibit System Recovery"

class ShadowSabotageDetector:
    """
    Stage 2 Detector: Detects adversarial attempts to disable Windows Recovery,
    delete Volume Shadow Copies (VSS), and clear event logs (T1490 & T1070.001).
    """

    PATTERNS = [
        (r"vssadmin(\.exe)?\s+delete\s+shadows", "VSS Shadow Copy Deletion (T1490)", 1.0),
        (r"bcdedit(\.exe)?\s+.*bootstatuspolicy\s+ignoreallfailures", "Windows Boot Failure Ignore (T1490)", 0.95),
        (r"bcdedit(\.exe)?\s+.*recoveryenabled\s+no", "Windows Recovery Environment Disabled (T1490)", 0.95),
        (r"wbadmin(\.exe)?\s+delete\s+catalog", "Windows Backup Catalog Deletion (T1490)", 1.0),
        (r"wbadmin(\.exe)?\s+delete\s+systemstatebackup", "System State Backup Deletion (T1490)", 1.0),
        (r"wmic(\.exe)?\s+shadowcopy\s+delete", "WMIC Shadow Copy Deletion (T1490)", 1.0),
        (r"wevtutil(\.exe)?\s+cl\s+(security|system|application)", "Windows Event Log Wipe (T1070.001)", 0.95),
    ]

    def check_process(self, proc: ProcessInfo) -> Optional[ShadowTamperAlert]:
        cmdline_str = " ".join(proc.cmdline).lower() if proc.cmdline else proc.name.lower()

        for pattern, desc, conf in self.PATTERNS:
            if re.search(pattern, cmdline_str, re.IGNORECASE):
                return ShadowTamperAlert(
                    rule_name="SYSTEM_RECOVERY_SABOTAGE_ATTEMPT",
                    pid=proc.pid,
                    process_name=proc.name,
                    command_executed=cmdline_str,
                    confidence=conf,
                    threat_description=f"Host sabotage detected: {desc} via process PID {proc.pid} ({proc.name}). Command: '{cmdline_str}'",
                    mitre_technique="T1490: Inhibit System Recovery"
                )
        return None
