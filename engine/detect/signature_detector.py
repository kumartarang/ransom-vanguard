import os
from typing import Dict, List, Optional
from pydantic import BaseModel

class SignatureMatch(BaseModel):
    rule_name: str
    match_type: str # 'extension', 'ransom_note', 'header'
    file_path: str
    indicator: str
    confidence: float # 0.0 - 1.0
    threat_description: str

class SignatureDetector:
    """
    Stage 2 Detector: Matches known ransomware extension signatures, ransom note templates, and file headers.
    """

    KNOWN_EXTENSIONS = {
        ".locked": ("Generic Ransomware", 0.95),
        ".crypted": ("Generic Crypto Ransomware", 0.95),
        ".crypto": ("Generic Crypto Ransomware", 0.95),
        ".enc": ("Generic Ransomware", 0.90),
        ".lockbit": ("LockBit 3.0 / Black", 1.0),
        ".blackcat": ("ALPHV / BlackCat", 1.0),
        ".alphv": ("ALPHV / BlackCat", 1.0),
        ".conti": ("Conti Ransomware", 1.0),
        ".phobos": ("Phobos Ransomware", 1.0),
        ".ryuk": ("Ryuk Enterprise Ransomware", 1.0),
        ".wannacry": ("WannaCry 2.0 Ransomware", 1.0),
        ".mallox": ("Mallox / TargetCompany", 1.0),
        ".makop": ("Makop Ransomware", 1.0),
        ".rhysida": ("Rhysida Group", 1.0),
        ".akira": ("Akira Ransomware", 1.0),
        ".play": ("Play (Balloonfly) Ransomware", 1.0),
        ".royal": ("Royal Ransomware", 1.0),
        ".stop": ("STOP/DJVU Ransomware", 1.0),
        ".djvu": ("STOP/DJVU Ransomware", 1.0),
        ".wnry": ("WannaCry Payload", 1.0),
    }

    KNOWN_RANSOM_NOTES = {
        "readme_to_recover.txt": ("LockBit / Generic Ransom Note", 0.95),
        "how_to_decrypt.html": ("BlackCat / ALPHV Note", 0.95),
        "restore-my-files.txt": ("Conti / Ryuk Note", 0.95),
        "lockbit_readme.txt": ("LockBit 3.0 Ransom Note", 1.0),
        "decrypt_instructions.html": ("Phobos / CrySIS Note", 0.95),
        "readme.txt": ("Generic Ransom Note Dropper", 0.60),
        "_readme.txt": ("STOP/DJVU Ransom Note", 0.95),
        "help_recover.txt": ("Generic Ransomware Dropper", 0.85),
        "@wannadecryptor@.exe": ("WannaCry Decryptor Dropper", 1.0),
        "decrypt_my_files.txt": ("Generic Ransom Note", 0.90)
    }

    def __init__(self, custom_extensions: Optional[List[str]] = None):
        self.extensions = dict(self.KNOWN_EXTENSIONS)
        if custom_extensions:
            for ext in custom_extensions:
                if not ext.startswith("."):
                    ext = f".{ext}"
                self.extensions[ext.lower()] = ("Custom Configured Ransomware Extension", 0.90)

    def check_file(self, file_path: str) -> List[SignatureMatch]:
        matches = []
        filename = os.path.basename(file_path).lower()
        ext = os.path.splitext(filename)[1].lower()

        # Check extension match
        if ext in self.extensions:
            family, conf = self.extensions[ext]
            matches.append(SignatureMatch(
                rule_name="RANSOM_EXTENSION_MATCH",
                match_type="extension",
                file_path=file_path,
                indicator=ext,
                confidence=conf,
                threat_description=f"File extension '{ext}' matches known ransomware signature: {family}"
            ))

        # Check ransom note pattern match
        for note_pattern, (family, conf) in self.KNOWN_RANSOM_NOTES.items():
            if filename == note_pattern or (len(note_pattern) > 8 and note_pattern in filename):
                matches.append(SignatureMatch(
                    rule_name="RANSOM_NOTE_DROP_DETECTED",
                    match_type="ransom_note",
                    file_path=file_path,
                    indicator=filename,
                    confidence=conf,
                    threat_description=f"Suspected ransom note creation detected: '{filename}' ({family})"
                ))

        return matches
