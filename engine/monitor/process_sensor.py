import os
import time
import psutil
from typing import Dict, List, Optional, Set
from pydantic import BaseModel

class ProcessInfo(BaseModel):
    pid: int
    name: str
    exe: Optional[str] = None
    cmdline: List[str] = []
    parent_pid: Optional[int] = None
    parent_name: Optional[str] = None
    cpu_percent: float = 0.0
    memory_mb: float = 0.0
    create_time: float = 0.0
    is_suspicious: bool = False
    suspicious_reasons: List[str] = []

class ProcessSensor:
    """
    Stage 1 Sensor: Monitors running processes, command lines, and suspicious activity.
    Detects LOLBAS execution (vssadmin, bcdedit, powershell encoded commands, wevtutil, certutil, etc.).
    """

    SUSPICIOUS_COMMAND_PATTERNS = [
        ("vssadmin", "delete", "shadows"),
        ("vssadmin.exe", "delete", "shadows"),
        ("bcdedit", "bootstatuspolicy", "ignoreallfailures"),
        ("bcdedit", "recoveryenabled", "no"),
        ("wbadmin", "delete", "catalog"),
        ("wbadmin", "delete", "systemstatebackup"),
        ("wevtutil", "cl", "security"),
        ("wevtutil", "cl", "system"),
        ("wmic", "shadowcopy", "delete"),
        ("powershell", "-enc"),
        ("powershell", "-encodedcommand"),
        ("powershell", "invoke-expression"),
        ("powershell", "iex"),
        ("cmd.exe", "/c", "del", "/f", "/q")
    ]

    RANSOMWARE_PROCESS_NAMES = {
        "wannacry.exe", "lockbit.exe", "blackcat.exe", "darkside.exe",
        "revil.exe", "ryuk.exe", "conti.exe", "maze.exe", "rclone.exe"
    }

    def __init__(self):
        self._known_pids: Set[int] = set()

    def inspect_process(self, proc: psutil.Process) -> Optional[ProcessInfo]:
        try:
            with proc.oneshot():
                pid = proc.pid
                name = proc.name().lower()
                exe = None
                try:
                    exe = proc.exe()
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    pass

                cmdline = []
                try:
                    cmdline = proc.cmdline()
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    pass

                parent_pid = None
                parent_name = None
                try:
                    parent = proc.parent()
                    if parent:
                        parent_pid = parent.pid
                        parent_name = parent.name()
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    pass

                create_time = proc.create_time()
                cpu = proc.cpu_percent(interval=None)
                mem = proc.memory_info().rss / (1024 * 1024)

                suspicious_reasons = []

                # Check process name
                if name in self.RANSOMWARE_PROCESS_NAMES:
                    suspicious_reasons.append(f"Process name matches known ransomware binary signature: {name}")

                # Check command line patterns
                cmdline_str = " ".join(cmdline).lower()
                for pattern in self.SUSPICIOUS_COMMAND_PATTERNS:
                    if all(part.lower() in cmdline_str for part in pattern):
                        suspicious_reasons.append(f"Process executed suspicious sabotage command matching: {' '.join(pattern)}")
                        break

                is_suspicious = len(suspicious_reasons) > 0

                return ProcessInfo(
                    pid=pid,
                    name=name,
                    exe=exe,
                    cmdline=cmdline,
                    parent_pid=parent_pid,
                    parent_name=parent_name,
                    cpu_percent=cpu,
                    memory_mb=round(mem, 2),
                    create_time=create_time,
                    is_suspicious=is_suspicious,
                    suspicious_reasons=suspicious_reasons
                )
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            return None

    def scan_all_processes(self) -> List[ProcessInfo]:
        results = []
        for proc in psutil.process_iter(['pid']):
            info = self.inspect_process(proc)
            if info:
                results.append(info)
        return results

    def find_suspicious_processes(self) -> List[ProcessInfo]:
        return [p for p in self.scan_all_processes() if p.is_suspicious]

    def get_process_by_pid(self, pid: int) -> Optional[ProcessInfo]:
        try:
            if psutil.pid_exists(pid):
                return self.inspect_process(psutil.Process(pid))
        except Exception:
            pass
        return None
