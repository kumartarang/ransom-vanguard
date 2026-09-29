import os
import time
import secrets
from engine.core_engine import CoreEngine

def test_full_6_stage_lifecycle(tmp_path):
    sandbox_dir = tmp_path / "sandbox"
    sandbox_dir.mkdir()
    canary_dir = tmp_path / "canaries"
    canary_dir.mkdir()
    snapshot_dir = tmp_path / "snapshots"
    snapshot_dir.mkdir()

    config = {
        "monitoring": {
            "monitored_paths": [str(sandbox_dir), str(canary_dir)],
            "entropy_threshold": 7.55,
            "burst_file_count_threshold": 4,
            "burst_time_window_seconds": 2.0
        },
        "response": {
            "auto_containment": True,
            "kill_process": True,
            "isolate_network": False,
            "quarantine_payload": False,
            "auto_recover_files": True
        },
        "alerting": {
            "windows_event_log": False
        }
    }

    # Initialize Core Engine
    engine = CoreEngine(config)
    engine.snapshot_engine.snapshot_dir = str(snapshot_dir)

    # STAGE 1: MONITOR - Deploy Canaries & Baseline
    canaries = engine.canary_manager.deploy_canaries()
    assert len(canaries) > 0

    # Create mock document in sandbox
    doc_path = sandbox_dir / "financials.docx"
    doc_content = "Confidential Company Financials Q4 2026."
    doc_path.write_text(doc_content)
    engine.snapshot_engine.capture_snapshot(str(doc_path))

    # STAGE 2: DETECT - Simulate Tripwire Honeypot Attack
    canary_file = list(engine.canary_manager.canaries.keys())[0]
    with open(canary_file, "wb") as f:
        f.write(secrets.token_bytes(1024))

    # Trigger detection pipeline manually to verify correlation
    from engine.monitor.filesystem_sensor import FileEventData
    event = FileEventData(
        event_type="modified",
        src_path=canary_file,
        timestamp=time.time(),
        file_extension=".xlsx",
        entropy=7.94,
        is_high_entropy=True
    )

    engine._process_single_file_event(event)

    # STAGE 3: ANALYZE - Verify Risk & Incident
    active_incident = engine.attack_graph.get_active_incident()
    assert active_incident is not None
    assert active_incident.risk_score >= 50
    assert len(active_incident.triggers) > 0

    # STAGE 4: ALERT - Verify Alerts Generated
    assert engine.total_alerts_count >= 1

    # STAGE 5 & 6: RESPOND & RECOVER - Verify status
    assert active_incident.status in ("CONTAINED", "RECOVERED", "ACTIVE")

    # Verify Telemetry
    telemetry = engine.get_telemetry()
    assert telemetry.total_incidents >= 1
