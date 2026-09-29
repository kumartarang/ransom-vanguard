import time
from typing import Dict, List, Optional
from pydantic import BaseModel, Field

class AffectedFileRecord(BaseModel):
    original_path: str
    current_path: str
    status: str # 'encrypted', 'renamed', 'deleted', 'quarantined', 'restored'
    entropy: float
    timestamp: float
    has_micro_snapshot: bool = False
    snapshot_path: Optional[str] = None

class AttackIncident(BaseModel):
    incident_id: str
    start_time: float
    updated_time: float
    threat_family: str
    risk_score: int
    threat_level: str
    status: str # 'DETECTING', 'ACTIVE', 'CONTAINING', 'CONTAINED', 'RECOVERED'
    culprit_pid: Optional[int] = None
    culprit_process_name: Optional[str] = None
    culprit_cmdline: Optional[str] = None
    parent_pid: Optional[int] = None
    parent_process_name: Optional[str] = None
    mitre_techniques: List[str] = []
    triggers: List[str] = []
    affected_files: List[AffectedFileRecord] = []
    containment_actions: List[str] = []
    recovery_actions: List[str] = []
    summary: str = ""

class AttackGraphTracker:
    """
    Stage 3 Analyzer: Aggregates attack forensics, process lineage, and affected file ledger.
    """

    def __init__(self):
        self.incidents: Dict[str, AttackIncident] = {}
        self.active_incident_id: Optional[str] = None

    def create_or_update_incident(
        self,
        incident_id: str,
        threat_family: str,
        risk_score: int,
        threat_level: str,
        culprit_pid: Optional[int] = None,
        culprit_name: Optional[str] = None,
        cmdline: Optional[str] = None,
        parent_pid: Optional[int] = None,
        parent_name: Optional[str] = None,
        mitre_techniques: Optional[List[str]] = None,
        trigger: Optional[str] = None,
        summary: str = ""
    ) -> AttackIncident:
        now = time.time()
        if incident_id not in self.incidents:
            incident = AttackIncident(
                incident_id=incident_id,
                start_time=now,
                updated_time=now,
                threat_family=threat_family,
                risk_score=risk_score,
                threat_level=threat_level,
                status="ACTIVE",
                culprit_pid=culprit_pid,
                culprit_process_name=culprit_name,
                culprit_cmdline=cmdline,
                parent_pid=parent_pid,
                parent_process_name=parent_name,
                mitre_techniques=mitre_techniques or [],
                triggers=[trigger] if trigger else [],
                summary=summary
            )
            self.incidents[incident_id] = incident
            self.active_incident_id = incident_id
        else:
            incident = self.incidents[incident_id]
            incident.updated_time = now
            incident.risk_score = max(incident.risk_score, risk_score)
            incident.threat_level = threat_level
            if culprit_pid:
                incident.culprit_pid = culprit_pid
            if culprit_name:
                incident.culprit_process_name = culprit_name
            if cmdline:
                incident.culprit_cmdline = cmdline
            if trigger and trigger not in incident.triggers:
                incident.triggers.append(trigger)
            if mitre_techniques:
                for tech in mitre_techniques:
                    if tech not in incident.mitre_techniques:
                        incident.mitre_techniques.append(tech)
            if summary:
                incident.summary = summary

        return incident

    def record_affected_file(self, incident_id: str, file_record: AffectedFileRecord):
        if incident_id in self.incidents:
            # Check if already present
            existing = [f for f in self.incidents[incident_id].affected_files if f.original_path == file_record.original_path]
            if not existing:
                self.incidents[incident_id].affected_files.append(file_record)
            else:
                existing[0].status = file_record.status
                existing[0].entropy = file_record.entropy
                existing[0].current_path = file_record.current_path
                existing[0].has_micro_snapshot = file_record.has_micro_snapshot
                existing[0].snapshot_path = file_record.snapshot_path

    def record_containment_action(self, incident_id: str, action_desc: str):
        if incident_id in self.incidents:
            self.incidents[incident_id].containment_actions.append(action_desc)
            self.incidents[incident_id].status = "CONTAINED"

    def record_recovery_action(self, incident_id: str, action_desc: str):
        if incident_id in self.incidents:
            self.incidents[incident_id].recovery_actions.append(action_desc)
            self.incidents[incident_id].status = "RECOVERED"

    def get_incident(self, incident_id: str) -> Optional[AttackIncident]:
        return self.incidents.get(incident_id)

    def get_all_incidents(self) -> List[AttackIncident]:
        return list(self.incidents.values())

    def get_active_incident(self) -> Optional[AttackIncident]:
        if self.active_incident_id and self.active_incident_id in self.incidents:
            return self.incidents[self.active_incident_id]
        return None
