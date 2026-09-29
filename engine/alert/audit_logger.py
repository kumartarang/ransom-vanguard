import os
import json
import time
import hashlib
from typing import Dict, Any, List

class AuditLogger:
    """
    Stage 4 / Forensics: Cryptographically verifiable append-only forensic event log.
    Maintains a hash chain to guarantee tamper-resistance.
    """

    def __init__(self, log_path: str = "./forensic_audit.jsonl"):
        self.log_path = os.path.abspath(log_path)
        self.last_hash = "0000000000000000000000000000000000000000000000000000000000000000"
        self._init_log()

    def _init_log(self):
        os.makedirs(os.path.dirname(self.log_path), exist_ok=True)
        if os.path.exists(self.log_path):
            try:
                with open(self.log_path, 'r', encoding='utf-8') as f:
                    for line in f:
                        line = line.strip()
                        if line:
                            entry = json.loads(line)
                            if "entry_hash" in entry:
                                self.last_hash = entry["entry_hash"]
            except Exception:
                pass

    def log_event(self, event_type: str, data: Dict[str, Any]) -> Dict[str, Any]:
        timestamp = time.time()
        raw_payload = {
            "timestamp": timestamp,
            "datetime": time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(timestamp)),
            "event_type": event_type,
            "data": data,
            "previous_hash": self.last_hash
        }

        # Calculate SHA256 chain hash
        serialized = json.dumps(raw_payload, sort_keys=True)
        entry_hash = hashlib.sha256(serialized.encode('utf-8')).hexdigest()
        raw_payload["entry_hash"] = entry_hash
        self.last_hash = entry_hash

        # Append to log file
        try:
            with open(self.log_path, 'a', encoding='utf-8') as f:
                f.write(json.dumps(raw_payload) + "\n")
        except Exception as e:
            print(f"[AuditLogger] Log append error: {e}")

        return raw_payload

    def read_recent_entries(self, limit: int = 50) -> List[Dict[str, Any]]:
        if not os.path.exists(self.log_path):
            return []
        entries = []
        try:
            with open(self.log_path, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line:
                        entries.append(json.loads(line))
        except Exception:
            pass
        return entries[-limit:]
