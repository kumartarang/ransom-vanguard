import os
import sys
import json
import asyncio
import threading
import urllib.request
from typing import List, Callable, Optional
from .event_models import AlertEvent

class AlertDispatcher:
    """
    Stage 4 Alerting: Multi-channel dispatching to WebSocket UI, Webhook (Slack/Teams/SIEM),
    Console, and Windows Event Log.
    """

    def __init__(
        self,
        webhook_url: Optional[str] = None,
        enable_win_event_log: bool = True
    ):
        self.webhook_url = webhook_url
        self.enable_win_event_log = enable_win_event_log
        self.listeners: List[Callable[[AlertEvent], None]] = []
        self._history: List[AlertEvent] = []
        self._lock = threading.Lock()

    def register_listener(self, callback: Callable[[AlertEvent], None]):
        self.listeners.append(callback)

    def dispatch(self, alert: AlertEvent):
        with self._lock:
            self._history.append(alert)
            if len(self._history) > 200:
                self._history.pop(0)

        # 1. Console Output
        tag = f"[{alert.severity.upper()}]"
        print(f"[AlertDispatcher] {tag} {alert.title} | Risk: {alert.risk_score}/100 | {alert.description}")

        # 2. In-memory Listeners (e.g. WebSocket streamer)
        for listener in self.listeners:
            try:
                listener(alert)
            except Exception as e:
                print(f"[AlertDispatcher] Listener error: {e}")

        # 3. Asynchronous Webhook
        if self.webhook_url:
            threading.Thread(target=self._send_webhook, args=(alert,), daemon=True).start()

        # 4. Windows Event Log (if running on Windows)
        if self.enable_win_event_log and sys.platform == "win32":
            threading.Thread(target=self._log_windows_event, args=(alert,), daemon=True).start()

    def _send_webhook(self, alert: AlertEvent):
        try:
            payload = {
                "text": f"🚨 *RANSOMVANGUARD ALERT: {alert.title}*\nSeverity: {alert.severity} (Score: {alert.risk_score}/100)\n{alert.description}",
                "alert": alert.model_dump()
            }
            data = json.dumps(payload).encode('utf-8')
            req = urllib.request.Request(self.webhook_url, data=data, headers={'Content-Type': 'application/json'}, method='POST')
            with urllib.request.urlopen(req, timeout=3.0) as response:
                pass
        except Exception as e:
            print(f"[AlertDispatcher] Webhook send failed: {e}")

    def _log_windows_event(self, alert: AlertEvent):
        """
        Logs a custom security event into the Windows Event Log using powershell Write-EventLog
        """
        try:
            event_id = 9001 if alert.severity in ("HIGH", "CRITICAL") else 9002
            # Safe write using PowerShell or subprocess if available
            msg = f"RansomVanguard Incident [{alert.rule_name}]: {alert.description}"
            # Only attempt if on windows
            if sys.platform == "win32":
                import subprocess
                cmd = f"powershell.exe -Command \"Write-EventLog -LogName Application -Source 'Application' -EventId {event_id} -EntryType Warning -Message '{msg[:1000]}' -ErrorAction SilentlyContinue\""
                subprocess.run(cmd, shell=True, capture_output=True, timeout=2.0)
        except Exception:
            pass

    def get_recent_alerts(self, limit: int = 50) -> List[AlertEvent]:
        with self._lock:
            return list(self._history[-limit:])
