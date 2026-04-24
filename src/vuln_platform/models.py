"""Pydantic models for the pipeline's data shapes.

Every agent reads and writes these. Validation at boundaries keeps garbage
from propagating across the pipeline (NVD JSON -> CVE, Claude tool-use
response -> Finding, etc.).
"""
from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field, IPvAnyAddress


Severity = Literal["critical", "high", "medium", "low", "info"]


class Service(BaseModel):
    """A service detected on an open port, optionally with a version."""

    name: str
    version: str | None = None
    banner: str | None = None


class Port(BaseModel):
    """An open TCP port on a host."""

    number: int = Field(ge=1, le=65535)
    service: Service | None = None


class Host(BaseModel):
    """A live host with its discovered open ports."""

    ip: IPvAnyAddress
    hostname: str | None = None
    open_ports: list[Port] = Field(default_factory=list)


class CVE(BaseModel):
    """A CVE record fetched from the NVD."""

    cve_id: str
    description: str
    cvss_score: float | None = None
    cvss_severity: Severity | None = None
    published: datetime | None = None
    references: list[str] = Field(default_factory=list)


class Finding(BaseModel):
    """A triaged finding — one CVE applied to one host+port.

    The Triage Agent emits one of these per enriched CVE. Severity and
    exploit_likelihood come from the LLM's structured output, grounded in
    the CVE's CVSS score and the service context.
    """

    host_ip: str
    port: int
    service_name: str
    service_version: str | None = None
    cve_id: str
    cve_description: str
    cvss_score: float | None = None
    severity: Severity
    exploit_likelihood: Literal["high", "medium", "low", "unknown"]
    rationale: str
    recommended_action: str
