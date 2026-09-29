from typing import List, Dict, Optional
from pydantic import BaseModel

class ThreatClassification(BaseModel):
    family_name: str
    encryption_algorithm: str
    ransom_note: Optional[str]
    mitre_attack_techniques: List[str]
    description: str

class ThreatClassifier:
    """
    Stage 3 Analyzer: Classifies ransomware families and correlates with MITRE ATT&CK Framework.
    """

    FAMILY_KNOWLEDGE_BASE = {
        "lockbit": ThreatClassification(
            family_name="LockBit 3.0 (Black)",
            encryption_algorithm="AES-256 + RSA-4096 / ChaCha20",
            ransom_note="lockbit_readme.txt / readme_to_recover.txt",
            mitre_attack_techniques=[
                "T1486: Data Encrypted for Impact",
                "T1490: Inhibit System Recovery",
                "T1070.001: Clear Windows Event Logs",
                "T1059.001: PowerShell",
                "T1562.001: Disable Windows Defender"
            ],
            description="High-speed multi-threaded ransomware known for fast partial/full encryption and shadow copy deletion."
        ),
        "blackcat": ThreatClassification(
            family_name="ALPHV / BlackCat",
            encryption_algorithm="ChaCha20 + RSA",
            ransom_note="how_to_decrypt.html",
            mitre_attack_techniques=[
                "T1486: Data Encrypted for Impact",
                "T1490: Inhibit System Recovery",
                "T1027: Obfuscated Files",
                "T1059: Command and Scripting Interpreter"
            ],
            description="Rust-based enterprise ransomware highly capable of targeting Windows Server domains."
        ),
        "conti": ThreatClassification(
            family_name="Conti / Wizard Spider",
            encryption_algorithm="AES-256 CBC + RSA-4096",
            ransom_note="restore-my-files.txt",
            mitre_attack_techniques=[
                "T1486: Data Encrypted for Impact",
                "T1490: Inhibit System Recovery",
                "T1047: Windows Management Instrumentation (WMI)"
            ],
            description="Multi-threaded ransomware utilizing Windows Restart Manager to unlock files."
        ),
        "phobos": ThreatClassification(
            family_name="Phobos / CrySIS",
            encryption_algorithm="AES-CBC + RSA-1024",
            ransom_note="decrypt_instructions.html / info.hta",
            mitre_attack_techniques=[
                "T1486: Data Encrypted for Impact",
                "T1490: Inhibit System Recovery"
            ],
            description="Targets RDP exposed Windows servers and appends target-specific IDs to file extensions."
        ),
        "wannacry": ThreatClassification(
            family_name="WannaCry (WanaCrypt0r 2.0)",
            encryption_algorithm="AES-128-CBC + RSA-2048",
            ransom_note="@wannadecryptor@.exe",
            mitre_attack_techniques=[
                "T1486: Data Encrypted for Impact",
                "T1210: Exploitation of Remote Services (EternalBlue/SMBv1)",
                "T1490: Inhibit System Recovery"
            ],
            description="Self-propagating ransomware worm spreading via SMBv1 vulnerabilities."
        )
    }

    GENERIC_CLASSIFICATION = ThreatClassification(
        family_name="Generic Ransomware / High-Entropy Cryptor",
        encryption_algorithm="Symmetric Cipher (AES / ChaCha20 / RC4)",
        ransom_note="Varies / Generic Dropper",
        mitre_attack_techniques=[
            "T1486: Data Encrypted for Impact",
            "T1490: Inhibit System Recovery"
        ],
        description="Behavioral signature matching autonomous mass-encryption and file mutation."
    )

    @classmethod
    def classify(cls, extension: Optional[str] = None, note_name: Optional[str] = None, process_name: Optional[str] = None) -> ThreatClassification:
        search_terms = []
        if extension:
            search_terms.append(extension.replace(".", "").lower())
        if note_name:
            search_terms.append(note_name.lower())
        if process_name:
            search_terms.append(process_name.lower())

        for key, info in cls.FAMILY_KNOWLEDGE_BASE.items():
            if any(key in term for term in search_terms):
                return info

        return cls.GENERIC_CLASSIFICATION
