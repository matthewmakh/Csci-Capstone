"""Web dashboard for the vulnerability assessment platform.

Lightweight FastAPI app that wraps the markdown report and SQLite store
behind a browsable UI. Runs locally — no auth — for capstone demos.
"""
from .app import create_app

__all__ = ["create_app"]
