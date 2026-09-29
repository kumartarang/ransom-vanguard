import os
import shutil
import secrets
from engine.recover.micro_snapshot import MicroSnapshotEngine

def test_micro_snapshot_capture_and_rollback(tmp_path):
    # Setup temporary directory
    test_dir = tmp_path / "test_docs"
    test_dir.mkdir()
    snapshot_dir = tmp_path / "snapshots"

    file1 = test_dir / "confidential_q3.txt"
    original_content = "This is clean, pristine corporate data before ransomware attack."
    file1.write_text(original_content, encoding="utf-8")

    engine = MicroSnapshotEngine(str(snapshot_dir))
    
    # 1. Capture snapshot baseline
    snap = engine.capture_snapshot(str(file1))
    assert snap is not None
    assert engine.get_snapshots_count() == 1

    # 2. Simulate Ransomware Encryption Damage
    encrypted_bytes = secrets.token_bytes(2048)
    with open(str(file1), "wb") as f:
        f.write(encrypted_bytes)

    # Verify damaged
    with open(str(file1), "rb") as f:
        assert f.read() != original_content.encode("utf-8")

    # 3. Autonomous Rollback
    restored = engine.restore_file(str(file1))
    assert restored is True

    # 4. Verify 100% loss-free restoration
    restored_text = file1.read_text(encoding="utf-8")
    assert restored_text == original_content
