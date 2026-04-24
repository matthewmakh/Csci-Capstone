"""Interactive .env configurator. Prompts for missing API keys.

Idempotent: if ANTHROPIC_API_KEY is already set to a real value, this is a no-op.
Safe to run from `make setup` on every invocation.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

ENV_PATH = Path(".env")
EXAMPLE_PATH = Path(".env.example")
PLACEHOLDER = "sk-ant-..."


def main() -> int:
    if not ENV_PATH.exists():
        if EXAMPLE_PATH.exists():
            ENV_PATH.write_text(EXAMPLE_PATH.read_text())
        else:
            ENV_PATH.write_text("")

    lines = ENV_PATH.read_text().splitlines()

    current = _get(lines, "ANTHROPIC_API_KEY")
    if current and current != PLACEHOLDER and current.startswith("sk-ant-"):
        print(f"[setup] ANTHROPIC_API_KEY already configured ({current[:12]}...).")
        return 0

    print()
    print("Anthropic API key is needed for the Triage Agent (Claude Opus 4.7).")
    print("Get one at https://console.anthropic.com/settings/keys")
    print("Press Enter to skip — demo will still run without LLM triage.")
    try:
        key = input("ANTHROPIC_API_KEY> ").strip()
    except (EOFError, KeyboardInterrupt):
        print("\n[setup] Skipped.")
        return 0

    if not key:
        print("[setup] No key entered. Triage will be disabled.")
        _set(lines, "ANTHROPIC_API_KEY", "")
    else:
        if not key.startswith("sk-ant-"):
            print("[setup] Warning: key does not start with 'sk-ant-'. Saving anyway.")
        _set(lines, "ANTHROPIC_API_KEY", key)
        print("[setup] Saved to .env (gitignored).")

    ENV_PATH.write_text("\n".join(lines) + "\n")
    return 0


def _get(lines: list[str], key: str) -> str | None:
    pattern = re.compile(rf"^{re.escape(key)}=(.*)$")
    for line in lines:
        m = pattern.match(line)
        if m:
            return m.group(1)
    return None


def _set(lines: list[str], key: str, value: str) -> None:
    pattern = re.compile(rf"^{re.escape(key)}=")
    for i, line in enumerate(lines):
        if pattern.match(line):
            lines[i] = f"{key}={value}"
            return
    lines.append(f"{key}={value}")


if __name__ == "__main__":
    sys.exit(main())
