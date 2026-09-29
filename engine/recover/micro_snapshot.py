import os
import shutil
import time
import hashlib
from typing import Dict, List, Optional
from pydantic import BaseModel

class SnapshotEntry(BaseModel):
    original_path: str
    snapshot_path: str
    sha256: str
    size: int
    timestamp: float

class MicroSnapshotEngine:
    """
    Stage 6 Recovery: Micro-Snapshot & Instant Rollback Engine.
    Maintains clean pre-incident copies of files. When ransomware is detected and killed,
    this engine automatically rolls back all tampered/encrypted/renamed files to 100% pristine state.
    """

    def __init__(self, snapshot_dir: str = "./recovery_snapshots"):
        self.snapshot_dir = os.path.abspath(snapshot_dir)
        self.snapshots: Dict[str, SnapshotEntry] = {}
        os.makedirs(self.snapshot_dir, exist_ok=True)

    @staticmethod
    def _compute_hash(path: str) -> str:
        try:
            h = hashlib.sha256()
            with open(path, 'rb') as f:
                while chunk := f.read(65536):
                    h.update(chunk)
            return h.hexdigest()
        except Exception:
            return ""

    def capture_snapshot(self, file_path: str) -> Optional[SnapshotEntry]:
        """
        Creates a clean snapshot of a file before modification.
        """
        if not os.path.exists(file_path) or os.path.isdir(file_path):
            return None

        try:
            abs_path = os.path.abspath(file_path)
            file_hash = self._compute_hash(abs_path)
            size = os.path.getsize(abs_path)
            timestamp = time.time()

            # Hash-based unique snapshot filename
            snapshot_filename = f"{file_hash[:16]}_{os.path.basename(abs_path)}"
            snapshot_path = os.path.join(self.snapshot_dir, snapshot_filename)

            # Copy file to snapshot storage if not already there
            if not os.path.exists(snapshot_path):
                shutil.copy2(abs_path, snapshot_path)

            entry = SnapshotEntry(
                original_path=abs_path,
                snapshot_path=snapshot_path,
                sha256=file_hash,
                size=size,
                timestamp=timestamp
            )

            self.snapshots[abs_path] = entry
            return entry
        except Exception as e:
            print(f"[MicroSnapshotEngine] Error snapshotting {file_path}: {e}")
            return None

    def snapshot_directory(self, dir_path: str) -> int:
        """Takes a clean baseline snapshot of all files in a directory."""
        count = 0
        if not os.path.exists(dir_path):
            return count

        for root, _, files in os.walk(dir_path):
            for file in files:
                filepath = os.path.join(root, file)
                if self.capture_snapshot(filepath):
                    count += 1
        return count

    def restore_file(self, original_path: str) -> bool:
        """
        Restores a single file from its micro-snapshot.
        """
        abs_path = os.path.abspath(original_path)
        if abs_path not in self.snapshots:
            # Check by basename
            base = os.path.basename(abs_path)
            for path, entry in self.snapshots.items():
                if os.path.basename(path) == base:
                    abs_path = path
                    break
            else:
                return False

        entry = self.snapshots[abs_path]
        if not os.path.exists(entry.snapshot_path):
            return False

        try:
            # Ensure destination directory exists
            os.makedirs(os.path.dirname(abs_path), exist_ok=True)
            shutil.copy2(entry.snapshot_path, abs_path)
            return True
        except Exception as e:
            print(f"[MicroSnapshotEngine] Restore failed for {abs_path}: {e}")
            return False

    def restore_all(self) -> Dict[str, bool]:
        """
        Restores all known files from snapshot cache.
        """
        results = {}
        for path in list(self.snapshots.keys()):
            results[path] = self.restore_file(path)
        return results

    def get_snapshots_count(self) -> int:
        return len(self.snapshots)
