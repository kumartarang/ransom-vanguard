import os
import time
import secrets
import threading
from typing import Dict, List, Optional
from pydantic import BaseModel

class SimulationResult(BaseModel):
    attack_type: str
    target_folder: str
    files_targeted: int
    duration_ms: float
    status: str
    details: List[str]

class SafeAttackSimulator:
    """
    Ransomware Attack Lab & Pipeline Validator:
    Safely executes controlled, non-destructive ransomware attack behaviors in an isolated sandbox folder.
    Validates detection speed, accuracy, containment, and self-healing recovery.
    """

    MOCK_FILES = [
        ("q3_financial_revenue.xlsx", "Company confidential Q3 balance sheet and payroll records. Total: $4,520,000."),
        ("customer_database_export.sql", "INSERT INTO customers (id, name, email) VALUES (1, 'Alice Corp', 'alice@corp.com');"),
        ("hr_employee_contracts.docx", "Employment contract agreement for confidential executive leadership team."),
        ("internal_api_gateway.py", "import os\ndef handle_payment():\n    return {'status': 'processed', 'amount': 990}"),
        ("patient_medical_records.pdf", "%PDF-1.4 Clinical health records and diagnostic patient treatment records."),
        ("legal_settlement_brief.docx", "Privileged and confidential attorney-client work product document."),
        ("product_roadmap_2027.txt", "Top secret AI architecture specifications and hardware acceleration designs."),
        ("azure_ad_infrastructure.tf", "resource 'azuread_user' 'admin' { user_principal_name = 'secops@enterprise.com' }"),
        ("quarterly_tax_filing.pdf", "%PDF-1.7 Internal Revenue Service corporate enterprise tax audit filing."),
        ("vendor_payout_schedules.csv", "VendorID,VendorName,Amount,RoutingNumber\nV001,FastCloud,45000,021000021")
    ]

    def __init__(self, sandbox_dir: str = "./simulator/sandbox", canary_dir: str = "./canary_vault"):
        self.sandbox_dir = os.path.abspath(sandbox_dir)
        self.canary_dir = os.path.abspath(canary_dir)
        self.is_running = False
        self._ensure_sandbox()

    def _ensure_sandbox(self):
        os.makedirs(self.sandbox_dir, exist_ok=True)
        os.makedirs(self.canary_dir, exist_ok=True)

    def populate_sandbox(self) -> int:
        """Populates the sandbox with mock enterprise documents for safe simulation."""
        self._ensure_sandbox()
        count = 0
        for filename, content in self.MOCK_FILES:
            path = os.path.join(self.sandbox_dir, filename)
            with open(path, "w", encoding="utf-8") as f:
                f.write(content)
            count += 1
        return count

    def run_canary_trip_simulation(self) -> SimulationResult:
        """
        Simulates ransomware traversing filesystem and encrypting the sacrificial Canary Honeypot.
        """
        start = time.perf_counter()
        details = []
        tripped_count = 0

        # Find canaries in canary vault or sandbox
        for folder in [self.canary_dir, self.sandbox_dir]:
            if os.path.exists(folder):
                for f in os.listdir(folder):
                    if f.startswith("!00_"):
                        target = os.path.join(folder, f)
                        # Simulate encryption overwrite with high-entropy bytes
                        try:
                            with open(target, "wb") as canary_file:
                                canary_file.write(secrets.token_bytes(2048))
                            details.append(f"Simulated encryption of canary tripwire: {f}")
                            tripped_count += 1
                            break
                        except Exception as e:
                            details.append(f"Failed to touch {f}: {e}")

        duration = (time.perf_counter() - start) * 1000
        return SimulationResult(
            attack_type="CANARY_TRIPWIRE_SIMULATION",
            target_folder=self.canary_dir,
            files_targeted=tripped_count,
            duration_ms=round(duration, 2),
            status="SUCCESS",
            details=details
        )

    def run_entropy_burst_simulation(self) -> SimulationResult:
        """
        Simulates multi-threaded high-entropy encryption burst across all sandbox files.
        """
        self.populate_sandbox()
        start = time.perf_counter()
        details = []
        files = [os.path.join(self.sandbox_dir, f) for f in os.listdir(self.sandbox_dir) if not f.startswith("!00_")]

        for filepath in files[:8]:
            try:
                # Generate high-entropy encrypted payload (Shannon entropy ~ 7.98)
                encrypted_data = secrets.token_bytes(4096)
                with open(filepath, "wb") as f:
                    f.write(encrypted_data)
                details.append(f"Encrypted {os.path.basename(filepath)} with 4KB high-entropy AES ciphertext")
                # Rapid bursts (<10ms between files)
                time.sleep(0.02)
            except Exception as e:
                details.append(f"Error encrypting {filepath}: {e}")

        duration = (time.perf_counter() - start) * 1000
        return SimulationResult(
            attack_type="HIGH_ENTROPY_ENCRYPTION_BURST",
            target_folder=self.sandbox_dir,
            files_targeted=len(details),
            duration_ms=round(duration, 2),
            status="SUCCESS",
            details=details
        )

    def run_extension_mutation_simulation(self, target_ext: str = ".lockbit") -> SimulationResult:
        """
        Simulates mass file renaming and extension appending (e.g. file.docx -> file.docx.lockbit).
        """
        self.populate_sandbox()
        start = time.perf_counter()
        details = []
        files = [os.path.join(self.sandbox_dir, f) for f in os.listdir(self.sandbox_dir) if not f.endswith(target_ext) and not f.startswith("!00_")]

        for filepath in files[:6]:
            try:
                new_path = f"{filepath}{target_ext}"
                # Overwrite with high entropy and rename
                with open(filepath, "wb") as f:
                    f.write(secrets.token_bytes(2048))
                os.rename(filepath, new_path)
                details.append(f"Renamed {os.path.basename(filepath)} -> {os.path.basename(new_path)}")
                time.sleep(0.02)
            except Exception as e:
                details.append(f"Error mutating {filepath}: {e}")

        duration = (time.perf_counter() - start) * 1000
        return SimulationResult(
            attack_type="MASS_EXTENSION_MUTATION",
            target_folder=self.sandbox_dir,
            files_targeted=len(details),
            duration_ms=round(duration, 2),
            status="SUCCESS",
            details=details
        )

    def run_ransom_note_drop_simulation(self) -> SimulationResult:
        """
        Simulates dropping ransom notes across target directories.
        """
        start = time.perf_counter()
        details = []
        notes = ["lockbit_readme.txt", "how_to_decrypt.html"]

        for note in notes:
            path = os.path.join(self.sandbox_dir, note)
            try:
                with open(path, "w", encoding="utf-8") as f:
                    f.write("=== YOUR NETWORK IS ENCRYPTED BY LOCKBIT 3.0 ===\nTo recover your private key visit our Tor portal.")
                details.append(f"Dropped ransom note: {note}")
            except Exception as e:
                details.append(f"Error dropping note: {e}")

        duration = (time.perf_counter() - start) * 1000
        return SimulationResult(
            attack_type="RANSOM_NOTE_DROP",
            target_folder=self.sandbox_dir,
            files_targeted=len(details),
            duration_ms=round(duration, 2),
            status="SUCCESS",
            details=details
        )

    def run_full_kill_chain_simulation(self) -> SimulationResult:
        """
        Simulates a complete real-world ransomware attack sequence:
        1. Canary honeypot trip
        2. Rapid high-entropy encryption burst
        3. Extension mutation to .locked
        4. Ransom note drop
        """
        start = time.perf_counter()
        details = []

        # 1. Canary trip
        res1 = self.run_canary_trip_simulation()
        details.extend(res1.details)

        # 2. Entropy burst
        res2 = self.run_entropy_burst_simulation()
        details.extend(res2.details)

        # 3. Extension mutation
        res3 = self.run_extension_mutation_simulation(".locked")
        details.extend(res3.details)

        # 4. Note drop
        res4 = self.run_ransom_note_drop_simulation()
        details.extend(res4.details)

        duration = (time.perf_counter() - start) * 1000
        return SimulationResult(
            attack_type="FULL_KILL_CHAIN_SIMULATION",
            target_folder=self.sandbox_dir,
            files_targeted=len(details),
            duration_ms=round(duration, 2),
            status="SUCCESS",
            details=details
        )
