"""Runtime configuration loaded from environment / .env."""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv


@dataclass(frozen=True)
class Settings:
    anthropic_api_key: str | None
    nvd_api_key: str | None
    db_path: Path
    audit_log_path: Path
    triage_model: str

    @property
    def has_anthropic_key(self) -> bool:
        return bool(self.anthropic_api_key)


def load_settings(env_file: str | os.PathLike[str] | None = ".env") -> Settings:
    if env_file and Path(env_file).exists():
        load_dotenv(env_file)
    return Settings(
        anthropic_api_key=os.getenv("ANTHROPIC_API_KEY"),
        nvd_api_key=os.getenv("NVD_API_KEY"),
        db_path=Path(os.getenv("VULN_PLATFORM_DB", "findings.db")),
        audit_log_path=Path(os.getenv("VULN_PLATFORM_AUDIT_LOG", "audit.jsonl")),
        triage_model=os.getenv("VULN_PLATFORM_MODEL", "claude-opus-4-7"),
    )
