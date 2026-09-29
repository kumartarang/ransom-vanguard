import os
import secrets
import pytest
from engine.core_engine import CoreEngine
from engine.detonation_lab import ThreatDetonationLab

@pytest.fixture
def engine():
    config = {
        "monitoring": {
            "monitored_paths": ["./simulator/sandbox", "./canary_vault"],
            "entropy_threshold": 7.55
        },
        "response": {
            "isolate_network": False,
            "auto_recover_files": True
        }
    }
    eng = CoreEngine(config)
    eng.start()
    yield eng
    eng.stop()

def test_threat_lab_presets():
    presets = ThreatDetonationLab.get_presets()
    assert len(presets) >= 5
    preset_ids = [p.preset_id for p in presets]
    assert "lockbit3_dropper" in preset_ids
    assert "vss_wiper_sabotage" in preset_ids
    assert "high_entropy_aes_burst" in preset_ids

def test_detonate_vss_sabotage_preset(engine):
    lab = ThreatDetonationLab(core_engine=engine, sandbox_dir="./simulator/sandbox")
    preset = next(p for p in lab.get_presets() if p.preset_id == "vss_wiper_sabotage")
    
    result = lab.process_threat_artifact(
        artifact_bytes=preset.sample_content.encode('utf-8'),
        filename=preset.filename,
        simulate_execution=True,
        custom_threat_family=preset.threat_family
    )

    assert result.risk_score >= 60
    assert result.threat_level in ("HIGH", "CRITICAL")
    assert len(result.stages) == 6
    assert result.stages[0].stage_name == "MONITOR & INGEST"
    assert result.stages[1].stage_name == "DETECT & SENSORS"
    assert result.stages[2].stage_name == "ANALYZE & MITRE ATT&CK"
    assert result.stages[3].stage_name == "ALERT & BROADCAST"
    assert result.stages[4].stage_name == "RESPOND & CONTAINMENT"
    assert result.stages[5].stage_name == "RECOVER & SELF-HEALING"
    assert result.quarantined is True

def test_detonate_custom_high_entropy_payload(engine):
    lab = ThreatDetonationLab(core_engine=engine, sandbox_dir="./simulator/sandbox")
    # Generate high-entropy encrypted ciphertext
    high_entropy_data = secrets.token_bytes(4096)

    result = lab.process_threat_artifact(
        artifact_bytes=high_entropy_data,
        filename="custom_ransomware_payload.lockbit",
        simulate_execution=True
    )

    assert result.entropy >= 7.50
    assert result.risk_score >= 60
    assert result.quarantined is True
    assert result.total_duration_ms > 0
    assert os.path.exists(result.quarantine_path)
