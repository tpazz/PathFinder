# Parser Improvement Backlog

This backlog converts the parser review into implementation tickets with scope, acceptance criteria, and dependencies.

## Milestone 0 — Test Harness and Baseline Lock

### PF-PARSER-001: Expand fixture coverage for all parsers
**Priority:** P0  
**Estimate:** 2–3 days  
**Depends on:** none

**Scope**
- Add fixtures for each parser covering:
  - valid/happy-path output
  - malformed/partial output
  - version-variant output
  - noisy/non-matching lines
- Parsers:
  - `gobuster`, `nmap`, `nikto`, `whatweb`, `sqlmap`, `snmp`
  - `enum4linux`, `kerberos`, `ldapdomaindump`, `sharphound`
  - `linpeas`, `winpeas`

**Acceptance criteria**
- New tests exist per parser module and run under `python -m unittest discover -s tests -v`.
- At least one malformed-input test per parser confirms graceful behavior (no crash).
- Existing parser tests continue to pass unchanged.

---

### PF-PARSER-002: Add parser contract assertions to every parser test
**Priority:** P0  
**Estimate:** 0.5 day  
**Depends on:** PF-PARSER-001

**Scope**
- For each parser test suite, assert output conforms to normalized finding schema via `validate_findings`.
- Add explicit tests for `attributes` presence and key datatype requirements.

**Acceptance criteria**
- Every parser test validates schema compliance.
- No parser test bypasses schema checks.

---

## Milestone 1 — Hardening and Drift Tolerance

### PF-PARSER-003: Harden unsafe numeric casts and missing keys
**Priority:** P0  
**Estimate:** 1 day  
**Depends on:** PF-PARSER-001

**Scope**
- Add safe parsing/fallback logic for:
  - Nmap `portid` conversion
  - Nikto `port` conversion
  - ldapdomaindump `useraccountcontrol`
  - SharpHound dictionary direct indexing hotspots

**Acceptance criteria**
- Malformed numeric fields do not crash parser.
- Invalid records are skipped with warnings/diagnostics.
- Regression tests include malformed numeric/key-missing cases.

---

### PF-PARSER-004: Nikto dual-format support (NDJSON + JSON array)
**Priority:** P1  
**Estimate:** 1 day  
**Depends on:** PF-PARSER-001

**Scope**
- Detect input shape and parse either newline-delimited JSON objects or a single JSON array payload.
- Keep existing classification behavior initially (no classification model changes in this ticket).

**Acceptance criteria**
- Parser accepts both Nikto formats with consistent output schema.
- Tests cover both formats and malformed lines/entries.

---

### PF-PARSER-005: SNMP parser section extraction robustness
**Priority:** P1  
**Estimate:** 1 day  
**Depends on:** PF-PARSER-001

**Scope**
- Replace strict `\n\n`-based block extraction with tolerant section parser.
- Improve process parsing to preserve process tokens and avoid `split()[-1]` loss.

**Acceptance criteria**
- SNMP parsing works across small formatting variations.
- Process findings are meaningfully preserved (not truncated to last token only).

---

### PF-PARSER-006: Kerberos parser support for verbose line formats
**Priority:** P1  
**Estimate:** 0.5–1 day  
**Depends on:** PF-PARSER-001

**Scope**
- Parse kerbrute outputs with timestamps/status prefixes in addition to plain username list.
- Broaden GetNPUsers hash regex coverage for variant output lines.

**Acceptance criteria**
- Verbose and plain kerbrute outputs are both parsed correctly.
- GetNPUsers variant lines are detected and parsed without false positives.

---

### PF-PARSER-007: SharpHound schema/version adapter layer
**Priority:** P1  
**Estimate:** 1–2 days  
**Depends on:** PF-PARSER-001

**Scope**
- Add minimal schema adapter/helpers to tolerate key naming/presence differences.
- Guard all high-risk direct key access and normalize object fields before analysis.

**Acceptance criteria**
- Known schema variants parse without runtime exceptions.
- Existing attack checks still function on baseline fixtures.

---

## Milestone 2 — Signal Quality Improvements

### PF-PARSER-008: Nmap enrichment extraction improvements
**Priority:** P1  
**Estimate:** 1–2 days  
**Depends on:** PF-PARSER-003

**Scope**
- Extract CPE values (if present) into `attributes`.
- Parse NSE structured table/elem output where available.
- OS matching fallback to best available accuracy if no 100% match exists.

**Acceptance criteria**
- CPE captured when present.
- Structured NSE data captured and test-covered.
- OS finding still produced for non-100% scenarios with confidence metadata.

---

### PF-PARSER-009: Gobuster variant coverage + dedup
**Priority:** P2  
**Estimate:** 1 day  
**Depends on:** PF-PARSER-001

**Scope**
- Expand parser support for additional output variants.
- Deduplicate repeated path/vhost findings from retries/noisy output.

**Acceptance criteria**
- Repeated lines do not produce duplicate findings.
- Existing dir/vhost behavior remains backward compatible.

---

### PF-PARSER-010: WhatWeb version candidate preservation
**Priority:** P2  
**Estimate:** 0.5 day  
**Depends on:** PF-PARSER-001

**Scope**
- Preserve full version list in `attributes.version_candidates`.
- Keep current top-level `version` field for compatibility.

**Acceptance criteria**
- Parser stores all version candidates if provided.
- Existing consumers relying on `version` continue to work.

---

### PF-PARSER-011: SQLMap richer context extraction
**Priority:** P2  
**Estimate:** 1 day  
**Depends on:** PF-PARSER-001

**Scope**
- Handle multi-target logs by associating parameters with nearest target context.
- Extract additional metadata when available (risk/level/payload snippets).

**Acceptance criteria**
- Multi-target fixture yields correctly scoped findings.
- Added metadata appears in attributes without breaking schema.

---

### PF-PARSER-012: Nikto classification rule externalization
**Priority:** P3  
**Estimate:** 1–2 days  
**Depends on:** PF-PARSER-004

**Scope**
- Move keyword/category mapping to config-driven rules (JSON/YAML/module constant).
- Keep backward-compatible defaults.

**Acceptance criteria**
- Classification behavior remains same with default config.
- Rules can be updated without code changes.

---

### PF-PARSER-013: LinPEAS/WinPEAS section-aware parsing pass
**Priority:** P2  
**Estimate:** 1–2 days  
**Depends on:** PF-PARSER-001

**Scope**
- Add context-aware parsing by known sections to reduce keyword false positives.
- Keep color signature detection as a high-confidence signal but add plain-text fallback confidence tiers.

**Acceptance criteria**
- False positives reduced in noisy fixture.
- Findings include signal source (`color_signature` vs `keyword_section_match`).

---

## Milestone 3 — AD Attack Surface Depth

### PF-PARSER-014: Expand SharpHound ACL abuse detections
**Priority:** P2  
**Estimate:** 2–3 days  
**Depends on:** PF-PARSER-007

**Scope**
- Add detections for additional exploitable rights/abuse primitives (e.g., WriteDacl-like escalation opportunities).
- Add high-value target set extensibility.

**Acceptance criteria**
- New detections are test-covered with synthetic fixtures.
- Existing detections (DCSync/GenericWrite/delegation/session) remain stable.

---

### PF-PARSER-015: LDAPDomainDump security signal extraction
**Priority:** P2  
**Estimate:** 1–2 days  
**Depends on:** PF-PARSER-003

**Scope**
- Promote key risky account/config flags to explicit findings.
- Reduce attributes noise by selecting key fields instead of raw row dump where useful.

**Acceptance criteria**
- New explicit findings appear for targeted risky states.
- Attributes payload size reduced for user/group/computer baseline findings.

---

## Milestone 4 — Consistency, Explainability, Observability

### PF-PARSER-016: Standardize parser confidence and evidence metadata
**Priority:** P2  
**Estimate:** 1 day  
**Depends on:** PF-PARSER-008..015 (partial)

**Scope**
- Add standardized metadata keys in parser output attributes:
  - `confidence` (high/medium/low)
  - `evidence_type` (`direct` / `heuristic`)
  - `evidence_source`/`raw_line`/`raw_section` where relevant

**Acceptance criteria**
- All parser outputs include confidence/evidence metadata (or explicit null/default).
- Schema remains valid and downstream mapping unaffected.

---

### PF-PARSER-017: Parser execution telemetry summaries
**Priority:** P3  
**Estimate:** 0.5 day  
**Depends on:** PF-PARSER-001

**Scope**
- Emit parser summary counts through logging:
  - input records/lines processed
  - findings emitted
  - records skipped and reason buckets

**Acceptance criteria**
- Verbose mode surfaces parser quality diagnostics.
- No change to default user-facing output unless verbose enabled.

---

## Suggested Sprint Sequence

### Sprint 1 (stability-first)
- PF-PARSER-001, 002, 003

### Sprint 2 (drift tolerance)
- PF-PARSER-004, 005, 006, 007

### Sprint 3 (signal quality)
- PF-PARSER-008, 009, 010, 011, 013

### Sprint 4 (AD depth)
- PF-PARSER-014, 015

### Sprint 5 (consistency + observability)
- PF-PARSER-016, 017, 012

---

## Definition of Done (Backlog-wide)

- Full parser test suite passes.
- All new outputs validate against normalized finding schema.
- No parser crashes on malformed fixtures.
- Trusted parser behavior (Nmap/Gobuster) remains backward-compatible unless explicitly approved.
- Changelog/release notes include parser behavior changes and migration notes.
