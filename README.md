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

## Quick Start

Requires Python 3.10+ and `make`.

```
git clone https://github.com/matthewmakh/csci-capstone
cd csci-capstone
git checkout claude/refactor-network-scanner-UqkiF
make setup
make demo      # CLI demo
make web       # Browser dashboard at http://127.0.0.1:8000
```

`make setup` creates a virtualenv, installs the package (including the web
dashboard deps), copies `.env.example` to `.env`, prompts you for your
`ANTHROPIC_API_KEY`, and runs the tests. It is idempotent — safe to re-run
if anything changes.

`make demo` spins up a local fake-vulnerable service and runs the full
recon → enrichment → triage → reporter pipeline against it. Costs roughly
$0.05–$0.20 per run with Claude Opus 4.7.

`make web` launches a FastAPI dashboard for browsing past scans, viewing
the rendered markdown report, inspecting the LLM audit log, and triggering
one-click demos.

## Scanning Your Own Network

For lab/home-network scans, the tool can auto-detect your LAN and
generate a scope file with an interactive attestation step:

```
make discover     # show what network you're attached to
make scan-home    # interactive: detect LAN, prompt for attestation,
                  # write home-scope.yaml, scan it
```

`init-scope` requires you to type your full name and the exact phrase
`yes I authorize` before writing the scope file. The generated
`home-scope.yaml` is gitignored so your attestation never gets
committed by accident.

**Only run `scan-home` against networks you own or have written
permission to test.** Cloud providers, public Wi-Fi, school networks,
and anything else where you don't have explicit authorization is off
limits — the tool can't tell whose network you're on, so the
attestation is on you.

## Usage

```
# Help
.venv/bin/python -m vuln_platform --help

# CLI demo
make demo

# Browser dashboard
make web

# Scan a real target (requires sudo for scapy raw sockets)
make scan ARGS='--ip 127.0.0.1 --ports 1-1024'
# or directly:
sudo .venv/bin/python -m vuln_platform scan \
    --scope-file examples/scope.example.yaml \
    --ip 127.0.0.1 \
    --ports 1-1024
```

## Web Dashboard

`make web` starts a local FastAPI app on `http://127.0.0.1:8000`:

- **/** — scan history with severity badges; one-click "Run demo" button
- **/scans/{id}** — full markdown report rendered as HTML, plus a sortable
  findings table with CVSS scores and CVE links to NVD
- **/audit** — every Claude API call (model, tokens, response, prompt
  hashes) for the rubric's auditability requirement

The dashboard shares the SQLite store and `audit.jsonl` with the CLI, so
anything you scan from either side shows up in the other.

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
