import os
import time
import queue
import threading
from typing import Dict, List, Optional, Callable
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler, FileSystemEvent, FileModifiedEvent, FileCreatedEvent, FileMovedEvent, FileDeletedEvent
from pydantic import BaseModel

from .entropy_calculator import EntropyCalculator

class FileEventData(BaseModel):
    event_type: str # 'created', 'modified', 'moved', 'deleted'
    src_path: str
    dest_path: Optional[str] = None
    timestamp: float
    file_extension: str
    file_size: int = 0
    entropy: float = 0.0
    is_high_entropy: bool = False
    is_canary: bool = False

class RansomwareWatchdogHandler(FileSystemEventHandler):
    """
    High-speed event handler filtering file events and calculating real-time entropy
    """
    def __init__(self, event_queue: queue.Queue, entropy_threshold: float = 7.55):
        super().__init__()
        self.event_queue = event_queue
        self.entropy_threshold = entropy_threshold
        self._recent_events: Dict[str, float] = {}

    def _process_file(self, event_type: str, src_path: str, dest_path: Optional[str] = None):
        try:
            # Ignore directories
            if os.path.isdir(src_path) or (dest_path and os.path.isdir(dest_path)):
                return

            target_path = dest_path if dest_path else src_path
            
            # Simple debounce for duplicate rapid OS notifications (50ms)
            now = time.time()
            if target_path in self._recent_events and (now - self._recent_events[target_path]) < 0.05:
                return
            self._recent_events[target_path] = now

            # Clean up debounce cache if it gets too large
            if len(self._recent_events) > 1000:
                self._recent_events = {k: v for k, v in self._recent_events.items() if (now - v) < 2.0}

            ext = os.path.splitext(target_path)[1].lower()
            size = 0
            entropy = 0.0

            if event_type in ('created', 'modified', 'moved') and os.path.exists(target_path):
                try:
                    size = os.path.getsize(target_path)
                    if size > 0:
                        entropy = EntropyCalculator.calculate_file_entropy(target_path)
                except Exception:
                    pass

            is_high = entropy >= self.entropy_threshold

            event_data = FileEventData(
                event_type=event_type,
                src_path=os.path.abspath(src_path),
                dest_path=os.path.abspath(dest_path) if dest_path else None,
                timestamp=now,
                file_extension=ext,
                file_size=size,
                entropy=entropy,
                is_high_entropy=is_high
            )

            self.event_queue.put(event_data)
        except Exception as e:
            print(f"[FilesystemSensor] Error processing event: {e}")

    def on_modified(self, event: FileModifiedEvent):
        if not event.is_directory:
            self._process_file('modified', event.src_path)

    def on_created(self, event: FileCreatedEvent):
        if not event.is_directory:
            self._process_file('created', event.src_path)

    def on_moved(self, event: FileMovedEvent):
        if not event.is_directory:
            self._process_file('moved', event.src_path, event.dest_path)

    def on_deleted(self, event: FileDeletedEvent):
        if not event.is_directory:
            self._process_file('deleted', event.src_path)

class FilesystemSensor:
    """
    Stage 1 Sensor: Watches designated folders for file I/O bursts and high-entropy encryption in real-time.
    """
    def __init__(self, monitored_paths: List[str], entropy_threshold: float = 7.55):
        self.monitored_paths = [os.path.abspath(p) for p in monitored_paths]
        self.entropy_threshold = entropy_threshold
        self.event_queue = queue.Queue()
        self.observer: Optional[Observer] = None
        self.is_running = False
        self._recent_activity_buffer: List[FileEventData] = []
        self._lock = threading.Lock()

    def start(self):
        if self.is_running:
            return

        self.observer = Observer()
        handler = RansomwareWatchdogHandler(self.event_queue, self.entropy_threshold)

        for path in self.monitored_paths:
            os.makedirs(path, exist_ok=True)
            self.observer.schedule(handler, path, recursive=True)

        self.observer.start()
        self.is_running = True
        print(f"[FilesystemSensor] Monitoring active on {len(self.monitored_paths)} paths.")

    def stop(self):
        if not self.is_running:
            return
        if self.observer:
            self.observer.stop()
            self.observer.join()
        self.is_running = False

    def get_next_event(self, block: bool = False, timeout: float = 0.1) -> Optional[FileEventData]:
        try:
            event = self.event_queue.get(block=block, timeout=timeout)
            with self._lock:
                self._recent_activity_buffer.append(event)
                # Keep last 100 events in memory
                if len(self._recent_activity_buffer) > 100:
                    self._recent_activity_buffer.pop(0)
            return event
        except queue.Empty:
            return None

    def get_recent_burst_stats(self, time_window_seconds: float = 2.0) -> Dict:
        """
        Calculates recent file modification rate and average entropy in the last N seconds
        """
        now = time.time()
        with self._lock:
            recent = [e for e in self._recent_activity_buffer if (now - e.timestamp) <= time_window_seconds]

        total_events = len(recent)
        high_entropy_count = sum(1 for e in recent if e.is_high_entropy)
        avg_entropy = sum(e.entropy for e in recent) / total_events if total_events > 0 else 0.0

        return {
            "window_seconds": time_window_seconds,
            "event_count": total_events,
            "high_entropy_count": high_entropy_count,
            "avg_entropy": round(avg_entropy, 4),
            "events_per_second": round(total_events / max(time_window_seconds, 0.1), 2)
        }

    def get_recent_activity(self, limit: int = 20) -> List[Dict]:
        with self._lock:
            return [e.model_dump() for e in self._recent_activity_buffer[-limit:]]
