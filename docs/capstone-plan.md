# Capstone Milestone Plan

Milestones mapped to the CSCI 401 Spring 2026 unit schedule.

## Syllabus reference

- **Unit 1** (Jan 26 – Feb 22): Secure Coding, Fuzzing, Vulnerability Discovery, Ethical Hacking
- **Unit 2** (Feb 23 – Apr 12): Machine Learning and AI applications in cyber security
- **Unit 3** (Apr 13 – May 3): Infrastructure security
- **Unit 4** (May 4 – finals): Forensics

Grading: Discussions 100 / Labs 300 / **Capstone project 600** / Total 1000.

## MVP status (this branch)

The platform currently has:

- [x] Refactored scanner foundation (host discovery, concurrent port scan, banner grab, service parsing)
- [x] SQLite persistence layer with a DAO abstraction
- [x] Enforced ethics/scope gate with YAML attestation
- [x] Enrichment Agent querying NVD v2.0 with local caching
- [x] Triage Agent using Claude Opus 4.7 (adaptive thinking, prompt caching, structured parse)
- [x] Reporter Agent producing a markdown pentest report
- [x] Auditable LLM I/O log (`audit.jsonl`)
- [x] `make demo` end-to-end against a local fake target
- [x] Pytest suite covering parsing, models, storage, ethics, enrichment (mocked), triage (mocked), reporter, orchestrator

## Proposed milestone schedule

### M1 — Unit 1 deliverable (due ~Feb 22)
**Theme: Secure coding + ethical hacking foundation**

- This branch, reviewed and merged. The deliverable is the foundation, the ethics framework, and the scanner.
- Team discussion section write-up covering: CFAA framing, why scope files are mandatory, fabrication risk in LLM triage.
- Demo video showing `make demo` end-to-end with explanation of each agent.

### M2 — Unit 2 deliverables (due ~Mar 15 / ~Apr 12)

**Theme: ML and AI applications in cyber security**

Split across two sub-milestones since this is the longest unit.

**M2a (~Mar 15):**
- Prompt engineering writeup: compare triage accuracy across `effort: low/medium/high/xhigh` on a curated set of 20 CVEs with known expert severity rankings.
- Add a secondary "evidence" agent that reads CVE references and fetches exploit-DB entries to improve exploit_likelihood grounding.

**M2b (~Apr 12):**
- Anomaly detection sub-project: train an Isolation Forest on a captured pcap of normal traffic, flag simulated scanner traffic as anomalous. This becomes an appendix to the main report — defensive ML to complement the offensive scanner.

### M3 — Unit 3 deliverable (due ~May 3)
**Theme: Infrastructure security**

- Migrate the storage layer from SQLite to MySQL; document the migration path in `docs/migration.md`.
- Add dockerfile + docker-compose so the whole platform (plus MySQL, plus fake target) spins up with one command.
- Add a minimal Flask web UI on top of the Store — listing scans, viewing reports, filtering findings by severity. (Optional, depending on remaining runway.)

### M4 — Unit 4 deliverable (due ~May 20 / finals week)
**Theme: Forensics + final presentation**

- Forensics-oriented agent: for a given report, ingest timestamped logs from the scanned target, correlate with findings, and generate an incident-response playbook section.
- Final presentation: architecture walk-through, live demo, ethics discussion, cost and performance analysis.
- Final polish: README, architecture diagram, contribution guide, reproducibility checklist.

## Group decomposition

The multi-agent architecture decomposes cleanly — each teammate owns one agent end-to-end:

| Role | Owns | Primary files |
|---|---|---|
| A: Scanner / Recon | Scanner primitives, Recon Agent, scope enforcement | `scanner/*`, `agents/recon.py`, `ethics.py` |
| B: Enrichment / Data | NVD integration, SQLite schema, CVE caching | `agents/enrichment.py`, `storage.py`, `models.py` |
| C: AI / Triage | Claude integration, prompt engineering, audit logging | `agents/triage.py`, `audit.py`, evaluation scripts |
| D: Reporting / UX | Reporter, CLI, demo target, final presentation materials | `agents/reporter.py`, `cli.py`, `examples/*`, `docs/*` |

Cross-cutting concerns (tests, CI, documentation) are shared.

## Risks and mitigations

| Risk | Mitigation |
|---|---|
| Claude API costs balloon | Prompt caching is enabled; monitor via audit log; fall back to `claude-sonnet-4-6` for development runs |
| NVD rate limiting blocks demos | Request an NVD API key (free); local SQLite cache absorbs repeat queries |
| scapy raw-socket requirement frustrates dev loop | `make demo` runs entirely in userland via the fake target; `--no-triage` and `--skip-host-discovery` flags exist for iteration |
| Scope creep on exploitation / red-teaming | Hard-lined: this tool reports, does not exploit. Documented in `docs/ethics.md`. |
| Teammate blockers | Linear pipeline + shared `AgentContext` means any agent can be stubbed to unblock downstream work |

## Evaluation metrics

For the final writeup, we plan to report:

- **Scan throughput:** hosts × ports / second compared to the classmate's original (~50-100x speedup expected from ThreadPoolExecutor alone)
- **Triage agreement rate:** on a 20-CVE benchmark set, what % of LLM severity calls match a human reviewer's call within one level?
- **Cost per scan:** Anthropic + NVD cost for representative /24 and single-host scans
- **Cache hit rate:** from `audit.jsonl`, ratio of `cache_read_input_tokens` to total input tokens across a multi-host scan (expected > 80% after the first triage call)
