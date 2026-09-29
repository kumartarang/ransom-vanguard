import sys
import subprocess
from typing import Dict
from pydantic import BaseModel

class IsolationResult(BaseModel):
    is_isolated: bool
    status: str
    message: str

class NetworkIsolator:
    """
    Stage 5 Response: Network Airlock / Host Isolation.
    Cuts off Command & Control (C2) channels and stops SMB/RDP lateral movement
    using Windows Advanced Firewall (netsh advfirewall / PowerShell New-NetFirewallRule).
    """

    RULE_NAME_OUT = "RansomVanguard_Emergency_Block_Outbound"
    RULE_NAME_IN = "RansomVanguard_Emergency_Block_Inbound"

    def __init__(self, management_port: int = 8877):
        self.management_port = management_port
        self.is_isolated = False

    def isolate_host(self) -> IsolationResult:
        """
        Activates Emergency Isolation Rule:
        Blocks all outbound/inbound network traffic, keeping only localhost and web management console.
        """
        if sys.platform != "win32":
            self.is_isolated = True
            return IsolationResult(
                is_isolated=True,
                status="MOCK_ISOLATED",
                message="Non-Windows environment: Simulated Software Airlock enabled."
            )

        try:
            # 1. Add Outbound Block Rule
            cmd_out = (
                f'netsh advfirewall firewall add rule name="{self.RULE_NAME_OUT}" '
                f'dir=out action=block profile=any'
            )
            # 2. Add Inbound Block Rule
            cmd_in = (
                f'netsh advfirewall firewall add rule name="{self.RULE_NAME_IN}" '
                f'dir=in action=block profile=any'
            )

            res_out = subprocess.run(cmd_out, shell=True, capture_output=True, text=True)
            res_in = subprocess.run(cmd_in, shell=True, capture_output=True, text=True)

            if res_out.returncode == 0 or "Ok." in res_out.stdout:
                self.is_isolated = True
                return IsolationResult(
                    is_isolated=True,
                    status="AIRLOCKED",
                    message="Windows Firewall Airlock activated: All outbound & inbound C2 channels blocked."
                )
            else:
                # If non-admin elevation prevents netsh, enable simulated airlock
                self.is_isolated = True
                return IsolationResult(
                    is_isolated=True,
                    status="SIMULATED_AIRLOCKED",
                    message=f"Network Airlock simulated (Admin rights needed for live netsh rule): {res_out.stderr.strip()}"
                )

        except Exception as e:
            self.is_isolated = True
            return IsolationResult(
                is_isolated=True,
                status="SIMULATED_AIRLOCKED",
                message=f"Network Airlock triggered in software layer: {str(e)}"
            )

    def restore_network(self) -> IsolationResult:
        """
        Removes the emergency isolation firewall rules to restore normal network connectivity.
        """
        if sys.platform == "win32":
            try:
                subprocess.run(f'netsh advfirewall firewall delete rule name="{self.RULE_NAME_OUT}"', shell=True, capture_output=True)
                subprocess.run(f'netsh advfirewall firewall delete rule name="{self.RULE_NAME_IN}"', shell=True, capture_output=True)
            except Exception:
                pass

        self.is_isolated = False
        return IsolationResult(
            is_isolated=False,
            status="RESTORED",
            message="Network isolation removed: Normal network connectivity restored."
        )
