import time
from typing import Dict, List, Optional, Any
from pydantic import BaseModel, Field

class AlertEvent(BaseModel):
    alert_id: str
    timestamp: float = Field(default_factory=time.time)
    severity: str # 'INFO', 'WARNING', 'HIGH', 'CRITICAL'
    title: str
    rule_name: str
    threat_level: str
    risk_score: int
    source: str # 'FilesystemSensor', 'ProcessSensor', 'CanarySensor', 'HeuristicDetector'
    description: str
    details: Dict[str, Any] = {}
    mitre_technique: Optional[str] = None
    target_path: Optional[str] = None
    pid: Optional[int] = None
    process_name: Optional[str] = None

class TelemetrySnapshot(BaseModel):
    timestamp: float = Field(default_factory=time.time)
    status: str # 'MONITORING', 'UNDER_ATTACK', 'CONTAINING', 'CONTAINED', 'RECOVERED'
    active_threat_level: str
    active_risk_score: int
    monitored_paths_count: int
    canaries_deployed: int
    canaries_tripped: int
    events_per_second: float
    avg_entropy: float
    recent_alerts_count: int
    total_incidents: int
