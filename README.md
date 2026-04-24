# Agentic Vulnerability Assessment Platform

CSCI 401 Capstone II — John Jay College of Criminal Justice, Spring 2026.

An agentic platform that takes raw network scan data and turns it into a triaged, LLM-reasoned pentest report. Built around four cooperating agents in a pipeline.

## Architecture

```
  Recon Agent  ->  Enrichment Agent  ->  Triage Agent  ->  Reporter Agent
  (scapy)          (NVD/CVE API)         (Claude Opus)     (markdown)
        \              |                      |                /
         \--------  SQLite findings store  ---/--  audit.jsonl (LLM I/O)
```

- **Recon Agent** — ICMP host discovery, concurrent TCP SYN port scan, banner grabbing. Builds on the original `NetworkScanner.ipynb` logic.
- **Enrichment Agent** — queries the NIST NVD API for CVEs matching detected service+version strings. Responses are cached locally.
- **Triage Agent** — Claude Opus 4.7 with adaptive thinking and prompt caching. Ranks findings by severity, exploit likelihood, and business impact. Every LLM call is logged to `audit.jsonl` for auditability.
- **Reporter Agent** — renders a professional markdown pentest report (executive summary, methodology, findings table, per-finding detail, ethics attestation).

## Ethics and Authorization

**This tool is for authorized security testing only.**

Scanning networks you do not own or have written permission to test is illegal in most jurisdictions (e.g., violates the Computer Fraud and Abuse Act in the United States). The CLI refuses to run without a scope file that includes:

- An explicit list of authorized CIDR ranges
- A signed attestation (`authorized_by`, `date`, `statement`)
- A classification (`lab` or `authorized_engagement`)

Every target IP is cross-checked against the scope before any packet is sent. See `docs/ethics.md` for details.

## Install

Requires Python 3.10+.

```
git clone https://github.com/matthewmakh/csci-capstone
cd csci-capstone
python3 -m venv .venv
source .venv/bin/activate
make install
cp .env.example .env
# Edit .env and add your ANTHROPIC_API_KEY
```

## Usage

```
# Inspect CLI
python -m vuln_platform --help

# End-to-end demo against a local fake target (no external services, no root required)
make demo

# Scan real targets (requires sudo for scapy raw sockets)
sudo python -m vuln_platform scan \
    --scope-file examples/scope.example.yaml \
    --ip 127.0.0.1 \
    --ports 1-1024
```

## Testing

Tests run offline. Scapy integration and NVD/Claude API calls are mocked.

```
make test
```

## Project Layout

```
src/vuln_platform/
    scanner/        host discovery, port scan, banner grab
    agents/         recon, enrichment, triage, reporter
    orchestrator.py pipeline runner
    cli.py          argparse entry point
tests/              pytest suites
docs/               architecture, ethics, capstone milestone plan
examples/           scope file template, local demo target
```

## Capstone Milestones

See `docs/capstone-plan.md` for the milestone plan mapped to the syllabus units.

## Cost

Triage calls against a realistic /24 scan run roughly $0.10–$1 per run with Claude Opus 4.7. Prompt caching cuts repeat-run cost substantially.

## Known Limitations

- `scapy` SYN scans require raw socket privileges (root on Linux, or `CAP_NET_RAW`).
- NVD API is rate-limited. Register at <https://nvd.nist.gov/developers/request-an-api-key> and set `NVD_API_KEY` to boost throughput.
- Service version detection from banners is best-effort. False negatives are expected.
