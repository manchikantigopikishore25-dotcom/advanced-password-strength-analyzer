"""
Safe History and Audit Service.
Records ONLY non-sensitive evaluation telemetry.

STRICT CYBERSECURITY POLICY:
NEVER accepts, stores, or logs:
- Plaintext passwords
- Reversible ciphertext
- Hashes of passwords
- User-identifying credential artifacts
"""
from datetime import datetime, timezone
from typing import List, Dict, Any
import threading

class SafeHistoryService:
    """Thread-safe in-memory ring buffer for non-sensitive evaluation metrics."""
    
    def __init__(self, max_entries: int = 50):
        self._max_entries = max_entries
        self._history: List[Dict[str, Any]] = []
        self._lock = threading.Lock()
        self._counter = 0

    def add_entry(self, score: int, strength: str, length: int, entropy_bits: float) -> Dict[str, Any]:
        """
        Record safe metadata from a password evaluation event.
        Guarantees that no credential or hash is ever accepted or stored.
        """
        with self._lock:
            self._counter += 1
            entry = {
                "id": self._counter,
                "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
                "score": int(score),
                "strength": str(strength),
                "length": int(length),
                "entropy_bits": round(float(entropy_bits), 1)
            }
            self._history.insert(0, entry)
            # Enforce max buffer size
            if len(self._history) > self._max_entries:
                self._history = self._history[:self._max_entries]
            return entry

    def get_history(self, limit: int = 20) -> List[Dict[str, Any]]:
        """Retrieve recent evaluation telemetry without sensitive data."""
        with self._lock:
            return list(self._history[:limit])

    def clear(self) -> None:
        """Clear all stored audit telemetry."""
        with self._lock:
            self._history.clear()

    def get_summary_stats(self) -> Dict[str, Any]:
        """Compute aggregate statistics over recorded evaluations."""
        with self._lock:
            if not self._history:
                return {
                    "total_evaluations": 0,
                    "average_score": 0,
                    "strength_breakdown": {
                        "Very Weak": 0,
                        "Weak": 0,
                        "Moderate": 0,
                        "Strong": 0,
                        "Very Strong": 0
                    }
                }

            total = len(self._history)
            avg_score = round(sum(item["score"] for item in self._history) / total, 1)
            breakdown = {
                "Very Weak": 0,
                "Weak": 0,
                "Moderate": 0,
                "Strong": 0,
                "Very Strong": 0
            }
            for item in self._history:
                label = item.get("strength", "Moderate")
                breakdown[label] = breakdown.get(label, 0) + 1

            return {
                "total_evaluations": total,
                "average_score": avg_score,
                "strength_breakdown": breakdown
            }


# Singleton service instance
history_service = SafeHistoryService(max_entries=50)
