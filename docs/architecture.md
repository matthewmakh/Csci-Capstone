# Architecture

## Pipeline

The platform is a linear pipeline of four cooperating agents sharing a typed context object (`AgentContext`). Each agent reads specific fields from the context and writes others. An `Orchestrator` wires them together.

```
+------------+     +----------------+     +-------------+     +--------------+
| ReconAgent | --> | EnrichmentAgent| --> | TriageAgent | --> | ReporterAgent|
| (scapy)    |     | (NVD)          |     | (Claude)    |     | (markdown)   |
+------------+     +----------------+     +-------------+     +--------------+
     |                   |                      |                    |
     v                   v                      v                    v
  SQLite (hosts)     SQLite (CVEs)         SQLite (findings)   context.report_markdown
                                           audit.jsonl
```

## Agents

### Recon Agent (`agents/recon.py`)

**Reads:** `context.scope_target`.
**Writes:** `context.hosts`.

Responsibilities:
1. Enforce scope on the target CIDR / address.
2. ICMP sweep (`scanner.ping_scan`) to identify live hosts.
3. Concurrent TCP SYN port scan (`scanner.port_scan`) per host.
4. Banner grab (`scanner.grab_banner`) and service/version parse (`scanner.parse_service`) per open port.
5. Persist `Host` records to SQLite.

The host-discovery step can be skipped with `--skip-host-discovery` for single local targets (useful for the demo and for cases where a firewall drops ICMP but the target is known to be live).

### Enrichment Agent (`agents/enrichment.py`)

**Reads:** `context.hosts`.
**Writes:** `context.cves_by_service` (keyed by `"name version"`).

Responsibilities:
1. For each unique service+version tuple across all hosts, query NVD API v2.0 by keyword.
2. Parse the response into `CVE` objects (CVSS v3.1 preferred, falling back to v3.0 then v2.0).
3. Cache each CVE in SQLite via `Store.upsert_cve`.

Service-level deduplication means scanning a /24 where every host runs the same Apache version costs one NVD request, not 254.

### Triage Agent (`agents/triage.py`)

**Reads:** `context.hosts`, `context.cves_by_service`.
**Writes:** `context.findings`.

Responsibilities:
1. For each (host, port, CVE) triple, build a user prompt with the scan and CVE context.
2. Call `client.messages.parse()` on Claude Opus 4.7 with:
   - `thinking: {type: "adaptive"}` — model decides its own thinking depth
   - `output_config: {effort: "high"}` — nudge toward thorough reasoning
   - Frozen system prompt marked `cache_control: ephemeral` so repeat calls reuse the cache
   - Pydantic `_TriageOutput` schema enforcing the response shape
3. Write a JSONL audit record per call (model, prompt hashes, response, tokens).
4. Fall back gracefully to CVSS-derived severity if the LLM returns no parsed output.

### Reporter Agent (`agents/reporter.py`)

**Reads:** `context.findings`.
**Writes:** `context.report_markdown`.

Generates a markdown document with: executive summary, methodology, scope attestation, findings table, per-finding detail grouped by severity.

## Data Model (`models.py`)

- `Host(ip, hostname, open_ports)`
- `Port(number, service)`
- `Service(name, version, banner)`
- `CVE(cve_id, description, cvss_score, cvss_severity, published, references)`
- `Finding(host_ip, port, service_name, service_version, cve_id, cve_description, cvss_score, severity, exploit_likelihood, rationale, recommended_action)`

All are pydantic v2 models. Validation happens at agent boundaries — NVD JSON gets turned into `CVE`, Claude's parsed output into the core fields of `Finding`.

## Storage (`storage.py`)

SQLite-backed DAO with four tables: `scans`, `hosts`, `cves`, `findings`. Chosen over MySQL for zero-config, file-based portability (the capstone demo has to run on any laptop). The DAO is thin enough that a MySQL backend can drop in for Unit 3 infrastructure work without touching the agents.

## Auditability (`audit.py`)

Every LLM call writes a JSON line to `audit.jsonl` with:
- ISO timestamp
- Model ID
- SHA-256 of system and user prompts
- Full response text
- Token usage (input, output, cache creation, cache read)
- Per-call context (host, port, CVE ID)

This satisfies the capstone rubric's "critically assess ethical implications of design choices" bullet — reviewers can audit every triage decision after the fact.

## Configuration (`config.py`)

Loaded from `.env` at startup via `python-dotenv`. Required: `ANTHROPIC_API_KEY`. Optional: `NVD_API_KEY` (boosts NVD rate limits from 5 req/30s to 50 req/30s), `VULN_PLATFORM_DB`, `VULN_PLATFORM_AUDIT_LOG`, `VULN_PLATFORM_MODEL`.

## CLI (`cli.py`)

Two subcommands:

- `scan --scope-file <path> --ip <target> [--ports <spec>] [--report <path>] [--no-triage]`
- `demo [--port <local>] [--report <path>]` — spins up `examples/demo_target/fake_service.py` on localhost, runs the pipeline against it, prints the report.

Both refuse to run without a valid scope file. `scan` also warns on POSIX if the user is not root (scapy SYN scans need raw sockets).

## Why these technology choices

| Choice | Why |
|---|---|
| Claude Opus 4.7 with adaptive thinking | Top-tier reasoning for nuanced severity calls; `xhigh`/`max` are available if needed. `budget_tokens` was removed on 4.7 — adaptive is the path. |
| `messages.parse()` + pydantic | Structured output with validation at the boundary; cleaner than tool-use for single-shot per-CVE triage. |
| Prompt caching on the system prompt | The rubric is frozen; caching saves ~80% on repeat triage calls in the same scan. |
| SQLite | Zero-config, file-based, CI-friendly. MySQL can swap in later. |
| httpx with MockTransport | Modern async-capable client; `MockTransport` makes offline testing trivial. |
| ThreadPoolExecutor port scan | ~50–100x speedup vs the classmate's sequential `sr1` loop. |
| YAML scope files with explicit attestation | Forces the user to confront authorization every run; machine-enforceable. |
