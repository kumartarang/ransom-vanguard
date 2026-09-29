import time
from typing import Dict, List, Optional
from pydantic import BaseModel
from ..monitor.filesystem_sensor import FileEventData

class HeuristicAlert(BaseModel):
    rule_name: str
    burst_count: int
    time_window: float
    avg_entropy: float
    rate_per_sec: float
    confidence: float
    affected_files: List[str]
    threat_description: str

class HeuristicDetector:
    """
    Stage 2 Detector: Detects behavioral anomalies such as rapid mass file encryption,
    entropy spikes, and bulk file mutation patterns.
    """

    def __init__(
        self,
        burst_threshold: int = 6,
        time_window: float = 2.0,
        entropy_threshold: float = 7.55
    ):
        self.burst_threshold = burst_threshold
        self.time_window = time_window
        self.entropy_threshold = entropy_threshold
        self.recent_events: List[FileEventData] = []

    def register_event(self, event: FileEventData) -> Optional[HeuristicAlert]:
        """
        Ingests a file event and checks if burst thresholds are breached.
        """
        now = time.time()
        self.recent_events.append(event)

        # Retain only events within sliding time window
        self.recent_events = [e for e in self.recent_events if (now - e.timestamp) <= self.time_window]

        # Calculate metrics
        total_events = len(self.recent_events)
        if total_events < self.burst_threshold:
            return None

        # Check high-entropy events
        high_entropy_events = [e for e in self.recent_events if e.entropy >= self.entropy_threshold or e.is_high_entropy]
        
        # If the majority of rapid file events are high entropy, it is active encryption!
        if len(high_entropy_events) >= (self.burst_threshold * 0.6):
            avg_entropy = sum(e.entropy for e in high_entropy_events) / len(high_entropy_events)
            affected_paths = [e.dest_path or e.src_path for e in high_entropy_events]
            rate = len(high_entropy_events) / max(self.time_window, 0.1)

            confidence = min(0.98, 0.70 + (len(high_entropy_events) / 20.0) * 0.28)

            return HeuristicAlert(
                rule_name="RAPID_MASS_ENCRYPTION_BURST",
                burst_count=len(high_entropy_events),
                time_window=self.time_window,
                avg_entropy=round(avg_entropy, 3),
                rate_per_sec=round(rate, 2),
                confidence=round(confidence, 2),
                affected_files=affected_paths[:10],
                threat_description=(
                    f"Heuristic Anomaly: Detected {len(high_entropy_events)} rapid high-entropy file writes "
                    f"in {self.time_window}s (Avg Entropy: {avg_entropy:.2f}/8.0, Rate: {rate:.1f} files/sec). "
                    f"Characteristic of active multi-threaded ransomware encryption."
                )
            )

        # Check for mass file rename burst (e.g. mass extension changer)
        renamed_events = [e for e in self.recent_events if e.event_type == 'moved']
        if len(renamed_events) >= self.burst_threshold:
            affected_paths = [e.dest_path or e.src_path for e in renamed_events]
            rate = len(renamed_events) / max(self.time_window, 0.1)

            return HeuristicAlert(
                rule_name="RAPID_MASS_FILE_RENAME_BURST",
                burst_count=len(renamed_events),
                time_window=self.time_window,
                avg_entropy=0.0,
                rate_per_sec=round(rate, 2),
                confidence=0.85,
                affected_files=affected_paths[:10],
                threat_description=(
                    f"Heuristic Anomaly: Rapid mass file rename of {len(renamed_events)} files "
                    f"in {self.time_window}s. Indicative of batch ransomware append/rename."
                )
            )

        return None
