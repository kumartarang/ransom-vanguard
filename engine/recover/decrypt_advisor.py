from typing import Dict, List, Optional
from pydantic import BaseModel

class DecryptorToolInfo(BaseModel):
    family_name: str
    extension: str
    tool_name: str
    provider: str
    availability: str # 'FREE_AVAILABLE', 'MASTER_KEY_AVAILABLE', 'RESEARCH_IN_PROGRESS', 'UNBREAKABLE'
    url: str
    instructions: str

class DecryptAdvisor:
    """
    Stage 6 Recovery: Provides actionable decryption guidance, free decryptor utilities,
    and cipher diagnostics (No More Ransom project integration).
    """

    DECRYPTOR_CATALOG = [
        DecryptorToolInfo(
            family_name="STOP / DJVU",
            extension=".djvu / .stop / .kroput",
            tool_name="Emsisoft Decryptor for STOP/Djvu",
            provider="Emsisoft / NoMoreRansom",
            availability="FREE_AVAILABLE",
            url="https://www.emsisoft.com/en/ransomware-decryption/stop-djvu/",
            instructions="Supports all victims with offline encryption keys. Run tool as Administrator."
        ),
        DecryptorToolInfo(
            family_name="WannaCry",
            extension=".wnry / .wcry",
            tool_name="WanaKiwi / Wanawake Memory Extractor",
            provider="Benjamin Delpy / Adrien Guinet",
            availability="FREE_AVAILABLE",
            url="https://github.com/gentilkiwi/wanakiwi",
            instructions="Recovers prime numbers p and q directly from memory before system reboot."
        ),
        DecryptorToolInfo(
            family_name="GandCrab (v1, v4, v5)",
            extension=".crab / .krab",
            tool_name="Bitdefender GandCrab Decryptor",
            provider="Bitdefender / Europol / FBI",
            availability="FREE_AVAILABLE",
            url="https://www.nomoreransom.org/en/decrypters.html",
            instructions="Full decryption available for all versions 1 through 5.2."
        ),
        DecryptorToolInfo(
            family_name="LockBit 3.0",
            extension=".lockbit",
            tool_name="RansomVanguard Micro-Snapshot Restorer",
            provider="RansomVanguard Autonomous Rollback",
            availability="FREE_AVAILABLE",
            url="internal://recovery/rollback",
            instructions="Instant zero-loss micro-snapshot reversion restored directly from Vanguard pre-breach cache."
        ),
        DecryptorToolInfo(
            family_name="ALPHV / BlackCat",
            extension=".blackcat / .alphv",
            tool_name="FBI Master Decryption Key Tool / Vanguard Rollback",
            provider="US DOJ / FBI / RansomVanguard",
            availability="FREE_AVAILABLE",
            url="https://www.justice.gov/opa/pr/fbi-disrupts-blackcat-alphv-ransomware-group",
            instructions="Keys seized in international operation. Decryptable using official released key."
        )
    ]

    @classmethod
    def find_decryptor(cls, family_or_ext: str) -> Optional[DecryptorToolInfo]:
        query = family_or_ext.lower().replace(".", "")
        for tool in cls.DECRYPTOR_CATALOG:
            if query in tool.family_name.lower() or query in tool.extension.lower():
                return tool
        return None

    @classmethod
    def get_all_tools(cls) -> List[DecryptorToolInfo]:
        return cls.DECRYPTOR_CATALOG
