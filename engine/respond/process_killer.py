import os
import sys
import psutil
from typing import Dict, List, Optional
from pydantic import BaseModel

class TerminationResult(BaseModel):
    pid: int
    process_name: str
    success: bool
    killed_children: List[int] = []
    message: str

class ProcessKiller:
    """
    Stage 5 Response: Sub-millisecond process tree suspension and termination.
    Terminates parent and all child processes spawned by the ransomware.
    """

    @classmethod
    def kill_process_tree(cls, pid: int) -> TerminationResult:
        if not psutil.pid_exists(pid):
            return TerminationResult(
                pid=pid,
                process_name="UNKNOWN",
                success=False,
                message=f"PID {pid} does not exist or already terminated."
            )

        try:
            parent = psutil.Process(pid)
            proc_name = parent.name()

            # Prevent killing critical Windows OS system processes
            protected_processes = {"system", "smss.exe", "csrss.exe", "wininit.exe", "services.exe", "lsass.exe", "explorer.exe"}
            if proc_name.lower() in protected_processes:
                return TerminationResult(
                    pid=pid,
                    process_name=proc_name,
                    success=False,
                    message=f"Protection safeguard: Refusing to kill critical Windows system process '{proc_name}'."
                )

            # Collect children recursively
            children = []
            try:
                children = parent.children(recursive=True)
            except Exception:
                pass

            killed_pids = []

            # 1. Suspend parent and children first to stop encryption immediately
            try:
                parent.suspend()
            except Exception:
                pass

            for child in children:
                try:
                    child.suspend()
                except Exception:
                    pass

            # 2. Terminate all children
            for child in children:
                try:
                    c_pid = child.pid
                    child.kill()
                    killed_pids.append(c_pid)
                except Exception:
                    pass

            # 3. Terminate parent
            parent.kill()
            killed_pids.append(pid)

            # Wait briefly for termination
            psutil.wait_procs(children + [parent], timeout=0.2)

            return TerminationResult(
                pid=pid,
                process_name=proc_name,
                success=True,
                killed_children=killed_pids,
                message=f"Successfully neutralized process '{proc_name}' (PID {pid}) and {len(killed_pids)-1} child processes."
            )

        except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
            # Try Windows taskkill fallback
            if sys.platform == "win32":
                import subprocess
                try:
                    res = subprocess.run(["taskkill", "/F", "/T", "/PID", str(pid)], capture_output=True, text=True)
                    if res.returncode == 0:
                        return TerminationResult(
                            pid=pid,
                            process_name="ProcessTree",
                            success=True,
                            killed_children=[pid],
                            message=f"Killed process PID {pid} via taskkill fallback."
                        )
                except Exception:
                    pass

            return TerminationResult(
                pid=pid,
                process_name="UNKNOWN",
                success=False,
                message=f"Failed to kill PID {pid}: {str(e)}"
            )
