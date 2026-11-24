"""Tamper-evident hash-chained JSONL audit logger for MCP security events."""

from __future__ import annotations

import hashlib
import json
import os
import time
from typing import Any


class HashChainedAuditLogger:
    """Appends SHA-256 hash-chained audit records to a JSONL file.

    Every entry stores ``prev_hash`` and ``entry_hash`` so post-incident
    forensics can verify that no tool call or policy denial was altered or removed.
    """

    GENESIS_HASH = "0" * 64

    def __init__(self, path: str) -> None:
        self.path = path
        parent = os.path.dirname(os.path.abspath(path))
        if parent:
            os.makedirs(parent, exist_ok=True)
        self._last_hash = self._recover_last_hash()

    def _recover_last_hash(self) -> str:
        if not os.path.exists(self.path):
            return self.GENESIS_HASH
        last_line = ""
        with open(self.path, "r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    last_line = line.strip()
        if not last_line:
            return self.GENESIS_HASH
        try:
            return str(json.loads(last_line).get("entry_hash", self.GENESIS_HASH))
        except json.JSONDecodeError:
            return self.GENESIS_HASH

    def log(
        self,
        *,
        request_id: Any,
        event: str,
        tool: str,
        decision: str,
        reason: str,
        args: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        payload_hash = hashlib.sha256(
            json.dumps(args or {}, sort_keys=True, ensure_ascii=False).encode("utf-8")
        ).hexdigest()
        body = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "request_id": request_id,
            "event": event,
            "tool": tool,
            "decision": decision,
            "reason": reason,
            "payload_sha256": payload_hash[:16],
            "prev_hash": self._last_hash,
        }
        canonical = json.dumps(body, sort_keys=True, ensure_ascii=False).encode("utf-8")
        entry_hash = hashlib.sha256(canonical).hexdigest()
        entry = {**body, "entry_hash": entry_hash}
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
        self._last_hash = entry_hash
        return entry

    @classmethod
    def verify_chain(cls, path: str) -> tuple[bool, int, str]:
        """Verify integrity of an entire JSONL audit log."""
        if not os.path.exists(path):
            return True, 0, "empty"
        prev = cls.GENESIS_HASH
        count = 0
        with open(path, "r", encoding="utf-8") as f:
            for idx, raw in enumerate(f, 1):
                line = raw.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError as exc:
                    return False, count, f"line {idx}: invalid JSON ({exc})"
                if entry.get("prev_hash") != prev:
                    return False, count, f"line {idx}: prev_hash mismatch"
                claimed = entry.get("entry_hash")
                body = {k: v for k, v in entry.items() if k != "entry_hash"}
                expected = hashlib.sha256(
                    json.dumps(body, sort_keys=True, ensure_ascii=False).encode("utf-8")
                ).hexdigest()
                if claimed != expected:
                    return False, count, f"line {idx}: entry_hash tampered"
                prev = claimed
                count += 1
        return True, count, "ok"

