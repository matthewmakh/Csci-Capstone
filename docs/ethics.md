# Ethics & Authorization

The CSCI 401 syllabus lists as a learning outcome:

> Collaborate to design, implement, and evaluate a cybersecurity solution to a realistic problem, **critically assess the ethical and societal implications of design choices**, and synthesize research and results into a professional presentation.

This document captures those choices and why we made them.

## Legal Framing

Unauthorized network scanning is illegal in most jurisdictions. In the United States:

- **Computer Fraud and Abuse Act (18 U.S.C. § 1030)** — makes it a federal offense to access a computer "without authorization" or in excess of authorized access. Courts have ruled that port scanning can constitute unauthorized access when it probes systems the scanner has no right to examine.
- **State laws** — many states (including New York, under NY Penal Law §§ 156.05–156.50) have computer-tampering statutes that parallel or extend the CFAA.

Beyond criminal exposure, unauthorized scanning against an employer, school, or ISP network typically violates acceptable-use policies and can result in account termination, academic discipline, or civil liability.

**Rule of thumb:** if you cannot produce a written, signed authorization for a given target, you do not have permission to scan it.

## Enforcement in Code

The platform encodes this rule at two levels:

### 1. Mandatory scope files

`python -m vuln_platform scan` refuses to start without `--scope-file`. The scope file must be valid YAML with:

- `classification: lab` or `classification: authorized_engagement`
- `authorized_cidrs: [...]` — non-empty list of CIDR ranges
- `attestation: { authorized_by, date, statement }` — all three fields required

Missing or malformed scope files raise `InvalidScopeFile` and the CLI exits with code 2 before any network activity.

### 2. Per-target enforcement

Every target IP or CIDR is checked against the scope *before* a packet is sent. Out-of-scope targets raise `ScopeViolation` and the CLI exits with code 3. The check uses `ipaddress.IPv{4,6}Network.subnet_of()` so passing `10.0.0.0/16` when the scope authorizes `10.0.0.0/24` is correctly rejected.

The Recon Agent re-checks each discovered live host before port-scanning it. This matters because a misconfigured router could reply to ICMP from an IP outside the /24 you meant to scan — the second check catches that.

## LLM-Specific Ethics

The Triage Agent uses Claude Opus 4.7 to rank findings. Two safeguards:

1. **Deterministic grounding.** The system prompt anchors severity to CVSS base scores. The LLM can adjust up or down one level with reasoning, but cannot invent findings or CVE IDs. Fabrication is called out explicitly in rule 4 of the prompt ("Do not fabricate CVE IDs, versions, or references").
2. **Full auditability.** Every Claude call writes a JSONL record to `audit.jsonl` with prompt hashes, full response text, and token usage. A reviewer can reconstruct any severity decision after the fact — which is the difference between an LLM augmenting human judgment and an LLM replacing it.

## Data Handling

- Scan results (hosts, CVEs, findings) are stored in a local SQLite file. No data is transmitted to any server other than: (a) the target being scanned, (b) the NVD API (public), (c) the Anthropic API (for triage).
- Prompt text sent to Anthropic contains host IPs, ports, service banners, and CVE descriptions. If scope targets are sensitive, treat the Anthropic API calls accordingly (review their data-use policy, consider a no-training-data agreement).
- The SQLite DB and `audit.jsonl` are `.gitignore`-d by default. Do not check them into version control.

## What This Tool Does Not Do

By design:

- **No exploitation.** The platform reports findings; it does not attempt to exploit them. Exploitation would turn a reconnaissance tool into a true pentest tool and dramatically expand the legal and ethical surface. That corresponds to Option 3 ("Adversarial AI Red Team Agent") from the early project brainstorm — a separate project, not this one.
- **No password spraying or credential testing.** The scanner observes banners; it does not attempt authentication.
- **No bypasses.** If a firewall filters the scan, the tool reports "filtered" and moves on.

## For the Final Presentation

Topics worth addressing explicitly:

- How scope files can be forged (they can — the attestation is honor-system) and what that means for the tool's threat model (operator malice is out of scope; this tool prevents accidental unauthorized scans, not intentional ones).
- LLM hallucination risk and how the audit log lets reviewers catch it.
- Cost implications of LLM-in-the-loop security tooling and the fairness questions that raises (can small orgs afford agentic pentesting?).
- The choice to never exploit and why that matters for classroom use.
