"""Structured audit logger for LLM I/O.

Required by the capstone's ethics/auditability rubric. Every Claude call
writes a JSONL record with prompt hash, model, token usage, and response
text. `jq` can slice and dice it afterwards.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


class AuditLogger:
    def __init__(self, log_path: Path | str) -> None:
        self.log_path = Path(log_path)
        self.log_path.parent.mkdir(parents=True, exist_ok=True)

    def log_llm_call(
        self,
        *,
        model: str,
        system_prompt: str,
        user_prompt: str,
        response_text: str,
        usage: dict[str, Any] | None,
        extra: dict[str, Any] | None = None,
    ) -> None:
        record: dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "model": model,
            "system_prompt_sha256": _sha256(system_prompt),
            "user_prompt_sha256": _sha256(user_prompt),
            "response_text": response_text,
            "usage": usage or {},
        }
        if extra:
            record["extra"] = extra
        with self.log_path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(record) + "\n")


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()
