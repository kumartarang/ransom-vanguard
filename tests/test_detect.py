import os
import time
from engine.detect.signature_detector import SignatureDetector
from engine.detect.shadow_sabotage import ShadowSabotageDetector
from engine.detect.heuristic_detector import HeuristicDetector
from engine.monitor.process_sensor import ProcessInfo
from engine.monitor.filesystem_sensor import FileEventData

def test_signature_detection_extension():
    detector = SignatureDetector()
    matches = detector.check_file("C:\\Shares\\finance\\audit.xlsx.lockbit")
    assert len(matches) > 0
    assert matches[0].rule_name == "RANSOM_EXTENSION_MATCH"
    assert "LockBit" in matches[0].threat_description

def test_signature_detection_ransom_note():
    detector = SignatureDetector()
    matches = detector.check_file("C:\\Shares\\finance\\lockbit_readme.txt")
    assert len(matches) > 0
    assert matches[0].rule_name == "RANSOM_NOTE_DROP_DETECTED"

def test_shadow_sabotage_detection():
    detector = ShadowSabotageDetector()
    mock_proc = ProcessInfo(
        pid=1337,
        name="cmd.exe",
        cmdline=["cmd.exe", "/c", "vssadmin.exe", "delete", "shadows", "/all", "/quiet"],
        cpu_percent=5.0,
        memory_mb=12.0,
        create_time=time.time()
    )
    alert = detector.check_process(mock_proc)
    assert alert is not None
    assert alert.rule_name == "SYSTEM_RECOVERY_SABOTAGE_ATTEMPT"
    assert "T1490" in alert.mitre_technique

def test_heuristic_burst_detection():
    detector = HeuristicDetector(burst_threshold=4, time_window=2.0, entropy_threshold=7.55)
    now = time.time()

    # Simulate 4 rapid high entropy file writes
    alert = None
    for i in range(5):
        event = FileEventData(
            event_type="modified",
            src_path=f"C:\\Sandbox\\file_{i}.docx",
            timestamp=now + (i * 0.05),
            file_extension=".docx",
            entropy=7.92,
            is_high_entropy=True
        )
        res = detector.register_event(event)
        if res:
            alert = res

    assert alert is not None
    assert alert.rule_name == "RAPID_MASS_ENCRYPTION_BURST"
    assert alert.burst_count >= 4
