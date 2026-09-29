import os
import hashlib
import time
from typing import Dict, List, Optional
from pydantic import BaseModel

class CanaryFile(BaseModel):
    path: str
    filename: str
    file_type: str
    initial_hash: str
    initial_size: int
    created_at: float
    is_tripped: bool = False
    tripped_at: Optional[float] = None
    trip_reason: Optional[str] = None

class CanaryManager:
    """
    Deception Engine: Deploys sacrificial canary (honeypot) files in sensitive directories.
    Ransomware traversing directories encrypts files alphabetically or sequentially,
    triggering these canaries first before reaching enterprise data.
    """

    CANARY_TEMPLATES = [
        ("!00_financial_audit_2026.xlsx", "xlsx", b"PK\x03\x04\x14\x00\x06\x00[MOCK_EXCEL_FINANCIAL_DATA_PROTECTED_BY_RANSOMVANGUARD]"),
        ("!00_corporate_passwords.docx", "docx", b"PK\x03\x04\x14\x00\x06\x00[MOCK_CONFIDENTIAL_CORPORATE_DOCUMENT_CANARY_TRIPWIRE]"),
        ("!00_customer_ssn_backup.pdf", "pdf", b"%PDF-1.7\n1 0 obj\n<< /Type /Catalog >>\nendobj\n[MOCK_SENSITIVE_PDF_CANARY]"),
        ("!00_mysql_master_credentials.sql", "sql", b"-- Confidential Database Backup\nINSERT INTO users VALUES ('admin', 'hash_secret_tripwire');\n"),
        ("!00_executive_brief_q3.txt", "txt", b"CONFIDENTIAL EXECUTIVE BRIEFING - TRIPWIRE HONEYPOT FILE FOR RANSOMWARE DETECTION\nDO NOT EDIT.\n")
    ]

    def __init__(self, target_folders: Optional[List[str]] = None):
        self.target_folders = target_folders or ["./canary_vault", "./simulator/sandbox"]
        self.canaries: Dict[str, CanaryFile] = {}
        self._ensure_folders()

    def _ensure_folders(self):
        for folder in self.target_folders:
            os.makedirs(folder, exist_ok=True)

    @staticmethod
    def _compute_hash(file_path: str) -> str:
        try:
            h = hashlib.sha256()
            with open(file_path, 'rb') as f:
                while chunk := f.read(65536):
                    h.update(chunk)
            return h.hexdigest()
        except Exception:
            return ""

    def deploy_canaries(self) -> List[CanaryFile]:
        """
        Deploys sacrificial canary honeypot files in all monitored directories.
        """
        self._ensure_folders()
        deployed = []

        for folder in self.target_folders:
            for filename, ftype, content in self.CANARY_TEMPLATES:
                filepath = os.path.abspath(os.path.join(folder, filename))
                
                # Write file if not exists or if already tripped/corrupted
                if not os.path.exists(filepath) or filepath in self.canaries and self.canaries[filepath].is_tripped:
                    try:
                        with open(filepath, 'wb') as f:
                            f.write(content)
                    except Exception as e:
                        print(f"[CanaryManager] Error writing canary {filepath}: {e}")
                        continue

                file_size = os.path.getsize(filepath) if os.path.exists(filepath) else len(content)
                file_hash = self._compute_hash(filepath)

                canary = CanaryFile(
                    path=filepath,
                    filename=filename,
                    file_type=ftype,
                    initial_hash=file_hash,
                    initial_size=file_size,
                    created_at=time.time(),
                    is_tripped=False
                )
                self.canaries[filepath] = canary
                deployed.append(canary)

        return deployed

    def check_tripwire(self, file_path: str) -> Optional[CanaryFile]:
        """
        Checks if a modified/accessed file is a registered canary file.
        If modified/hash changed, flags tripwire as triggered.
        """
        abs_path = os.path.abspath(file_path)
        if abs_path not in self.canaries:
            # Check basename match in case folder path formatting differed
            for canary_path, canary in self.canaries.items():
                if os.path.basename(canary_path).lower() == os.path.basename(file_path).lower():
                    abs_path = canary_path
                    break
            else:
                return None

        canary = self.canaries[abs_path]
        if canary.is_tripped:
            return canary

        if not os.path.exists(abs_path):
            # Canary was deleted or renamed by ransomware!
            canary.is_tripped = True
            canary.tripped_at = time.time()
            canary.trip_reason = "Canary file was deleted or renamed (Tampering detected)"
            return canary

        current_hash = self._compute_hash(abs_path)
        if current_hash != canary.initial_hash:
            canary.is_tripped = True
            canary.tripped_at = time.time()
            canary.trip_reason = f"Canary file content modified or encrypted (Hash mismatch: {current_hash[:8]} vs {canary.initial_hash[:8]})"
            return canary

        return None

    def reset_canaries(self):
        """Resets all canary tripwires and redeploys clean files."""
        self.canaries.clear()
        return self.deploy_canaries()

    def get_status(self) -> List[Dict]:
        return [c.model_dump() for c in self.canaries.values()]
