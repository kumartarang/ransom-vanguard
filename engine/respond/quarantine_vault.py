import os
import shutil
import hashlib
import time
from typing import Dict, List, Optional
from pydantic import BaseModel

class QuarantinedItem(BaseModel):
    original_path: str
    quarantine_path: str
    filename: str
    sha256: str
    file_size: int
    quarantined_at: float
    reason: str

class QuarantineVault:
    """
    Stage 5 Response: Secure Isolation Vault.
    Quarantines suspicious payloads, disables execution permissions, and records cryptographic hashes.
    """

    def __init__(self, vault_dir: str = "./quarantine_vault"):
        self.vault_dir = os.path.abspath(vault_dir)
        self.items: Dict[str, QuarantinedItem] = {}
        os.makedirs(self.vault_dir, exist_ok=True)

    @staticmethod
    def _hash_file(filepath: str) -> str:
        try:
            h = hashlib.sha256()
            with open(filepath, 'rb') as f:
                while chunk := f.read(65536):
                    h.update(chunk)
            return h.hexdigest()
        except Exception:
            return "UNKNOWN"

    def quarantine_file(self, file_path: str, reason: str = "Ransomware signature detected") -> Optional[QuarantinedItem]:
        if not os.path.exists(file_path):
            return None

        filename = os.path.basename(file_path)
        timestamp = time.time()
        file_hash = "INTERCEPTED_BY_DEFENSE"
        size = 0
        try:
            file_hash = self._hash_file(file_path)
            size = os.path.getsize(file_path)
        except Exception:
            pass

        # Target vault file with safe quarantined extension
        quarantine_filename = f"{int(timestamp)}_{filename}.quarantine"
        vault_target = os.path.join(self.vault_dir, quarantine_filename)

        try:
            # Move file into vault
            shutil.move(file_path, vault_target)
            try:
                os.chmod(vault_target, 0o400)
            except Exception:
                pass
        except Exception as e:
            # If Windows Defender locked it or OS blocked move, neutralize and save vault record
            try:
                if os.path.exists(file_path):
                    os.remove(file_path)
            except Exception:
                pass
            try:
                with open(vault_target, "w", encoding="utf-8") as f:
                    f.write(f"# QUARANTINED THREAT ARTIFACT\nOriginal Path: {file_path}\nReason: {reason}\nStatus: Isolated & Neutralized\n")
            except Exception:
                pass

        item = QuarantinedItem(
            original_path=file_path,
            quarantine_path=vault_target,
            filename=filename,
            sha256=file_hash,
            file_size=size,
            quarantined_at=timestamp,
            reason=reason
        )

        self.items[vault_target] = item
        return item

    def get_all_quarantined(self) -> List[QuarantinedItem]:
        return list(self.items.values())
