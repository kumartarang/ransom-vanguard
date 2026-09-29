import os
import time
import uuid
import queue
import threading
from typing import Dict, List, Optional, Any

from .monitor.entropy_calculator import EntropyCalculator
from .monitor.canary_manager import CanaryManager, CanaryFile
from .monitor.filesystem_sensor import FilesystemSensor, FileEventData
from .monitor.process_sensor import ProcessSensor, ProcessInfo

from .detect.signature_detector import SignatureDetector
from .detect.heuristic_detector import HeuristicDetector
from .detect.shadow_sabotage import ShadowSabotageDetector
from .detect.canary_tripwire import CanaryTripwireDetector

from .analyze.risk_scorer import RiskScorer, RiskAssessment, ThreatLevel
from .analyze.threat_classifier import ThreatClassifier, ThreatClassification
from .analyze.attack_graph import AttackGraphTracker, AttackIncident, AffectedFileRecord

from .alert.event_models import AlertEvent, TelemetrySnapshot
from .alert.dispatcher import AlertDispatcher
from .alert.audit_logger import AuditLogger

from .respond.process_killer import ProcessKiller, TerminationResult
from .respond.network_isolator import NetworkIsolator
from .respond.quarantine_vault import QuarantineVault
from .respond.containment_policy import ContainmentPolicy, ContainmentPolicyEngine

from .recover.micro_snapshot import MicroSnapshotEngine
from .recover.shadow_rollback import ShadowRollbackManager
from .recover.decrypt_advisor import DecryptAdvisor
from .recover.forensic_exporter import ForensicReportExporter

class CoreEngine:
    """
    RansomVanguard Autonomous 6-Stage Core Orchestration Engine:
    Monitor → Detect → Analyze → Alert → Respond → Recover
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        
        # Paths
        monitored_paths = self.config.get("monitoring", {}).get(
            "monitored_paths", ["./simulator/sandbox", "./canary_vault"]
        )
        entropy_threshold = self.config.get("monitoring", {}).get("entropy_threshold", 7.55)
        burst_threshold = self.config.get("monitoring", {}).get("burst_file_count_threshold", 6)
        burst_window = self.config.get("monitoring", {}).get("burst_time_window_seconds", 2.0)

        # 1. STAGE 1: MONITOR
        self.canary_manager = CanaryManager(monitored_paths)
        self.fs_sensor = FilesystemSensor(monitored_paths, entropy_threshold)
        self.process_sensor = ProcessSensor()

        # 2. STAGE 2: DETECT
        self.signature_detector = SignatureDetector(
            self.config.get("detection", {}).get("ransomware_extensions", [])
        )
        self.heuristic_detector = HeuristicDetector(
            burst_threshold=burst_threshold,
            time_window=burst_window,
            entropy_threshold=entropy_threshold
        )
        self.shadow_detector = ShadowSabotageDetector()
        self.canary_tripwire_detector = CanaryTripwireDetector()

        # 3. STAGE 3: ANALYZE
        self.risk_scorer = RiskScorer()
        self.threat_classifier = ThreatClassifier()
        self.attack_graph = AttackGraphTracker()

        # 4. STAGE 4: ALERT
        webhook_url = self.config.get("alerting", {}).get("webhook_url", None)
        enable_win_event = self.config.get("alerting", {}).get("windows_event_log", True)
        self.alert_dispatcher = AlertDispatcher(webhook_url=webhook_url, enable_win_event_log=enable_win_event)
        self.audit_logger = AuditLogger("./forensic_audit.jsonl")

        # 5. STAGE 5: RESPOND
        self.process_killer = ProcessKiller()
        self.network_isolator = NetworkIsolator(management_port=8877)
        self.quarantine_vault = QuarantineVault("./quarantine_vault")
        self.policy_engine = ContainmentPolicyEngine()

        # 6. STAGE 6: RECOVER
        self.snapshot_engine = MicroSnapshotEngine("./recovery_snapshots")
        self.shadow_manager = ShadowRollbackManager()
        self.decrypt_advisor = DecryptAdvisor()

        self.is_running = False
        self._worker_thread: Optional[threading.Thread] = None
        self._process_scan_thread: Optional[threading.Thread] = None
        self.total_alerts_count = 0

    def start(self):
        """Initializes and starts all monitoring threads and baselines."""
        if self.is_running:
            return

        print("[CoreEngine] Starting RansomVanguard 6-Stage Autonomous Engine...")

        # Deploy canary files
        canaries = self.canary_manager.deploy_canaries()
        print(f"[CoreEngine] Stage 1: Deployed {len(canaries)} canary tripwire honeypots.")

        # Baseline snapshot sandbox files for zero-loss recovery
        for p in self.fs_sensor.monitored_paths:
            count = self.snapshot_engine.snapshot_directory(p)
            print(f"[CoreEngine] Stage 6: Captured {count} baseline micro-snapshots for '{p}'.")

        # Start filesystem sensor
        self.fs_sensor.start()

        self.is_running = True

        # Start asynchronous event pipeline worker
        self._worker_thread = threading.Thread(target=self._event_loop_worker, daemon=True)
        self._worker_thread.start()

        # Start periodic background process inspector
        self._process_scan_thread = threading.Thread(target=self._process_inspector_worker, daemon=True)
        self._process_scan_thread.start()

        print("[CoreEngine] RansomVanguard engine is ONLINE and actively protecting the host.")

    def stop(self):
        self.is_running = False
        self.fs_sensor.stop()
        print("[CoreEngine] Engine stopped.")

    def _event_loop_worker(self):
        """
        Continuous pipeline loop processing real-time file I/O events.
        Pipeline: Ingest → Check Canaries → Check Signatures → Heuristics → Correlate Risk → Respond → Recover
        """
        while self.is_running:
            event = self.fs_sensor.get_next_event(block=True, timeout=0.2)
            if not event:
                continue

            try:
                self._process_single_file_event(event)
            except Exception as e:
                print(f"[CoreEngine] Pipeline event processing error: {e}")

    def _process_single_file_event(self, event: FileEventData):
        target_path = event.dest_path or event.src_path

        # If it's a file modification and not yet snapshotted or was clean, snapshot it
        if event.event_type in ('created', 'modified') and not event.is_high_entropy:
            self.snapshot_engine.capture_snapshot(target_path)

        # STAGE 2: CHECK CANARY TRIPWIRES
        canary = self.canary_manager.check_tripwire(target_path)
        has_canary_trip = canary is not None and canary.is_tripped

        # STAGE 2: CHECK SIGNATURES (Extensions / Ransom Notes)
        sig_matches = self.signature_detector.check_file(target_path)
        has_ransom_ext = any(m.match_type == "extension" for m in sig_matches)
        has_ransom_note = any(m.match_type == "ransom_note" for m in sig_matches)

        # STAGE 2: CHECK HEURISTIC BURST
        heuristic_alert = self.heuristic_detector.register_event(event)
        has_entropy_burst = heuristic_alert is not None and heuristic_alert.rule_name == "RAPID_MASS_ENCRYPTION_BURST"
        has_mass_rename = heuristic_alert is not None and heuristic_alert.rule_name == "RAPID_MASS_FILE_RENAME_BURST"

        # If any detector triggered
        if has_canary_trip or has_ransom_ext or has_ransom_note or has_entropy_burst or has_mass_rename:
            self._handle_detection(
                event=event,
                canary=canary if has_canary_trip else None,
                sig_matches=sig_matches,
                heuristic_alert=heuristic_alert,
                has_canary_trip=has_canary_trip,
                has_ransom_ext=has_ransom_ext,
                has_ransom_note=has_ransom_note,
                has_entropy_burst=has_entropy_burst,
                has_mass_rename=has_mass_rename
            )

    def _handle_detection(
        self,
        event: FileEventData,
        canary: Optional[CanaryFile] = None,
        sig_matches: Optional[List] = None,
        heuristic_alert: Optional[Any] = None,
        has_canary_trip: bool = False,
        has_ransom_ext: bool = False,
        has_ransom_note: bool = False,
        has_entropy_burst: bool = False,
        has_mass_rename: bool = False,
        proc_info: Optional[ProcessInfo] = None,
        has_shadow_sabotage: bool = False
    ):
        target_path = event.dest_path or event.src_path

        # STAGE 3: ANALYZE - Compute Risk Score
        risk = self.risk_scorer.evaluate(
            has_canary_trip=has_canary_trip,
            has_shadow_sabotage=has_shadow_sabotage,
            has_ransom_extension=has_ransom_ext,
            has_entropy_burst=has_entropy_burst,
            has_ransom_note=has_ransom_note,
            has_mass_rename=has_mass_rename,
            has_suspicious_proc=proc_info.is_suspicious if proc_info else False
        )

        # Classify Threat
        ext = os.path.splitext(target_path)[1]
        note = os.path.basename(target_path) if has_ransom_note else None
        proc_name = proc_info.name if proc_info else None
        classification = self.threat_classifier.classify(ext, note, proc_name)

        # STAGE 3: ANALYZE - Update Attack Graph Incident
        incident_id = f"INC-{time.strftime('%Y%m%d')}-{int(time.time()) % 10000:04d}"
        incident = self.attack_graph.create_or_update_incident(
            incident_id=incident_id,
            threat_family=classification.family_name,
            risk_score=risk.score,
            threat_level=risk.threat_level.value,
            culprit_pid=proc_info.pid if proc_info else None,
            culprit_name=proc_info.name if proc_info else None,
            cmdline=" ".join(proc_info.cmdline) if proc_info and proc_info.cmdline else None,
            parent_pid=proc_info.parent_pid if proc_info else None,
            parent_name=proc_info.parent_name if proc_info else None,
            mitre_techniques=classification.mitre_attack_techniques,
            trigger=risk.triggers[0] if risk.triggers else "Heuristic Anomaly",
            summary=risk.rationale
        )

        # Record affected file
        file_rec = AffectedFileRecord(
            original_path=event.src_path,
            current_path=target_path,
            status="encrypted" if has_entropy_burst or has_ransom_ext else ("tripped" if has_canary_trip else "modified"),
            entropy=event.entropy,
            timestamp=time.time(),
            has_micro_snapshot=target_path in self.snapshot_engine.snapshots or event.src_path in self.snapshot_engine.snapshots
        )
        self.attack_graph.record_affected_file(incident_id, file_rec)

        # STAGE 4: ALERT - Generate & Dispatch
        severity = "CRITICAL" if risk.score >= 80 else ("HIGH" if risk.score >= 60 else "WARNING")
        alert = AlertEvent(
            alert_id=f"ALT-{uuid.uuid4().hex[:8].upper()}",
            timestamp=time.time(),
            severity=severity,
            title=f"Ransomware Activity Detected: {classification.family_name}",
            rule_name=risk.triggers[0] if risk.triggers else "RANSOMWARE_BEHAVIOR",
            threat_level=risk.threat_level.value,
            risk_score=risk.score,
            source="CorrelationEngine",
            description=f"Correlated {len(risk.triggers)} threat vectors. Score: {risk.score}/100. Target: {target_path}",
            details={
                "incident_id": incident_id,
                "triggers": risk.triggers,
                "classification": classification.model_dump(),
                "entropy": event.entropy,
                "target_file": target_path
            },
            mitre_technique=classification.mitre_attack_techniques[0] if classification.mitre_attack_techniques else "T1486",
            target_path=target_path,
            pid=proc_info.pid if proc_info else None,
            process_name=proc_info.name if proc_info else None
        )

        self.total_alerts_count += 1
        self.alert_dispatcher.dispatch(alert)
        self.audit_logger.log_event("THREAT_DETECTED", alert.model_dump())

        # STAGE 5: RESPOND - Containment
        if risk.should_contain and self.policy_engine.should_auto_contain(risk.score):
            self._execute_containment(incident, proc_info, target_path)

    def _execute_containment(self, incident: AttackIncident, proc_info: Optional[ProcessInfo], file_path: str):
        print(f"[CoreEngine] STAGE 5: Initiating Autonomous Instant Containment for Incident {incident.incident_id}...")

        # 1. Neutralize Process
        if proc_info and proc_info.pid:
            kill_res = self.process_killer.kill_process_tree(proc_info.pid)
            action_str = f"Neutralized culprit process '{proc_info.name}' (PID {proc_info.pid}). Status: {kill_res.message}"
            self.attack_graph.record_containment_action(incident.incident_id, action_str)
            self.audit_logger.log_event("PROCESS_KILLED", kill_res.model_dump())

        # 2. Network Airlock Isolation
        if self.config.get("response", {}).get("isolate_network", False):
            iso_res = self.network_isolator.isolate_host()
            self.attack_graph.record_containment_action(incident.incident_id, iso_res.message)
            self.audit_logger.log_event("NETWORK_ISOLATED", iso_res.model_dump())

        # 3. Quarantine Target/Payload
        if os.path.exists(file_path) and (file_path.endswith(".exe") or file_path.endswith(".dll") or file_path.endswith(".ps1")):
            q_item = self.quarantine_vault.quarantine_file(file_path, reason=f"Incident {incident.incident_id}")
            if q_item:
                self.attack_graph.record_containment_action(incident.incident_id, f"Quarantined payload to {q_item.quarantine_path}")

        # STAGE 6: RECOVER - Instant Rollback
        if self.config.get("response", {}).get("auto_recover_files", True):
            self._execute_recovery(incident)

    def _execute_recovery(self, incident: AttackIncident):
        print(f"[CoreEngine] STAGE 6: Initiating Zero-Loss Self-Healing Rollback for Incident {incident.incident_id}...")
        recovered_count = 0

        # Rollback all affected files recorded in incident
        for rec in incident.affected_files:
            # If destination was renamed (e.g. filename.docx.locked), remove encrypted artifact
            if rec.current_path != rec.original_path and os.path.exists(rec.current_path):
                try:
                    os.remove(rec.current_path)
                except Exception:
                    pass

            # Restore original clean snapshot
            if self.snapshot_engine.restore_file(rec.original_path):
                rec.status = "restored"
                recovered_count += 1

        # Also redeploy tripped canaries
        self.canary_manager.reset_canaries()

        recovery_msg = f"Restored {recovered_count} files to 100% pristine baseline using Micro-Snapshots. Tripwires re-armed."
        self.attack_graph.record_recovery_action(incident.incident_id, recovery_msg)
        self.audit_logger.log_event("FILES_RESTORED", {
            "incident_id": incident.incident_id,
            "recovered_count": recovered_count,
            "message": recovery_msg
        })

        # Generate post-mortem report
        report_html = ForensicReportExporter.generate_html_report(incident)
        report_path = f"./forensics_report_{incident.incident_id}.html"
        try:
            with open(report_path, "w", encoding="utf-8") as f:
                f.write(report_html)
        except Exception:
            pass

        print(f"[CoreEngine] STAGE 6 Complete: {recovery_msg}")

    def _process_inspector_worker(self):
        """
        Background worker scanning running processes for shadow tampering (T1490) and malicious command lines.
        """
        while self.is_running:
            try:
                for proc in self.process_sensor.scan_all_processes():
                    sabotage_alert = self.shadow_detector.check_process(proc)
                    if sabotage_alert:
                        # Direct critical trigger
                        print(f"[CoreEngine] CRITICAL DETECT: Shadow Sabotage attempted by PID {proc.pid} ({proc.name})!")
                        fake_event = FileEventData(
                            event_type="modified",
                            src_path="C:\\Windows\\System32\\vssadmin.exe",
                            timestamp=time.time(),
                            file_extension=".exe"
                        )
                        self._handle_detection(
                            event=fake_event,
                            proc_info=proc,
                            has_shadow_sabotage=True
                        )
            except Exception as e:
                pass
            time.sleep(2.0)

    def get_telemetry(self) -> TelemetrySnapshot:
        """Returns live system telemetry snapshot for SOC dashboard."""
        stats = self.fs_sensor.get_recent_burst_stats(2.0)
        active_inc = self.attack_graph.get_active_incident()

        status = "MONITORING"
        score = 0
        threat = "NORMAL"

        if active_inc:
            status = active_inc.status
            score = active_inc.risk_score
            threat = active_inc.threat_level

        canary_stats = self.canary_manager.get_status()
        tripped = sum(1 for c in canary_stats if c.get("is_tripped"))

        return TelemetrySnapshot(
            timestamp=time.time(),
            status=status,
            active_threat_level=threat,
            active_risk_score=score,
            monitored_paths_count=len(self.fs_sensor.monitored_paths),
            canaries_deployed=len(canary_stats),
            canaries_tripped=tripped,
            events_per_second=stats["events_per_second"],
            avg_entropy=stats["avg_entropy"],
            recent_alerts_count=self.total_alerts_count,
            total_incidents=len(self.attack_graph.get_all_incidents())
        )
