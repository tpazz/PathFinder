# PathFinder

PathFinder turns recon loot into prioritised attack paths. Drop tool output into
a folder, run `scan`, and it parses the files, maps versions to public exploit
signals, correlates findings across hosts, and prints the most useful next steps
first.

It is built for authorised labs, CTFs, and pentest workflows where you want fast
triage without losing the underlying evidence.

## Quick Start

```bash
python3 -m main.pathfinder scan loot/ -o findings.json
python3 -m main.pathfinder scan loot/ --top 10
python3 -m main.pathfinder scan loot/ --min-likelihood medium
python3 -m main.pathfinder scan loot/ --show-all
python3 -m main.pathfinder scan loot/ --report engagement.html
```

For one-shot-enum users:

```bash
python one-shot-enum.py 10.10.10.10 --pathfinder
```

PathFinder understands per-host loot folders automatically:

```text
loot/
  10.10.10.10/
    nmap.xml
    webpage_http_80.html
    ffuf_80.json
    dns_corp.htb_axfr.txt
    nikto_80.json
  10.10.10.20/
    nmap.xml
    enum4linux_10.10.10.20.json
```

## Inputs and behavior

`scan` auto-detects common network, web, Active Directory, credential,
privilege-escalation, AI, and one-shot-enum loot. This includes SharpHound
directories/ZIPs, pypykatz/lsassy JSON, dig output, and textual ffuf response
captures, plus raw or one-shot-enum OpenAPI inventories.

PathFinder:

- normalizes findings while retaining source files, evidence, and producer commands;
- groups repeated leads into actionable attack paths;
- correlates credentials, services, shares, web content, AD data, and AI surfaces;
- extracts bounded response evidence and classifies high-signal web parameters
  for traversal/LFI, SSRF, command injection, XXE, SQLi, IDOR, and SSTI triage;
- routes confirmed passwords to read-only MySQL, PostgreSQL, and MSSQL capability
  inventory, and gives unmatched services a generic protocol-triage fallback;
- routes passwords and valid NT hashes to authentication actions while keeping
  NetNTLMv2, AS-REP, TGS, DCC2, and DPAPI material crack-first;
- loads direct GPO/ACL and trust inventory, while limiting BloodHound reasoning
  to owned-principal zero-hop wins and one direct high-value target hint—no
  transitive or cross-domain graph traversal;
- maps versions to optional Searchsploit/GitHub enrichment; and
- saves/reloads JSON findings and generates offline HTML reports.

Potential usernames inferred from webpages remain manual-review candidates;
they are never silently promoted to confirmed accounts.

## Useful Flags

- `--top N`: show the top grouped leads (`20` by default, `0` for all).
- `--min-likelihood low|medium|high`: hide lower-confidence leads.
- `--show-all`: print every generated attack path instead of grouped triage.
- `--hide-discovery` / `--hide-findings`: simplify terminal output.
- `--validate-credentials`: actively test resolved login actions sequentially.
- `--max-vulns N`: cap exploit enrichment per source and host.
- `--offline`: disable GitHub and Searchsploit enrichment.
- `--skip-github` / `--skip-searchsploit`: disable one enrichment source.
- `--target-host HOST`: provide host context for flat loot folders.
- `--oscp`: strip restricted-tool commands from suggestions and flag exam caveats.
- `--no-color`: disable ANSI colour output.
- `--report [HTML]`: write a self-contained report (`pathfinder-report.html` by default).
- `--report-redact-secrets`: redact secrets and credential-bearing commands.

### HTML engagement reports

```bash
python3 -m main.pathfinder scan loot/ --report engagement.html
python3 -m main.pathfinder scan loot/ --min-likelihood medium --report
```

Reports contain no JavaScript or network assets and HTML-escape imported data.
They preserve evidence and commands by default, so treat an unredacted report as
sensitive engagement loot.

SharpHound and LSASS exports may be supplied directly with `--sharphound-dir`
and `--lsass-json`, or placed beneath a scan loot tree for auto-detection.

## Collectors

Both collectors are standard-library-only and read-only apart from writing
their JSON report. Reports preserve sensitive evidence by default.

### AI-PEAS

Collect AI/RAG/model-host configuration, local listeners, workload identities,
RAG stores, MCP tools, ingestion paths, guardrails and artifact consumers:

```bash
python3 tools/ai-peas.py . -o ai-peas-loot.json
python3 -m main.pathfinder --ai-peas-json ai-peas-loot.json -o findings.json
```

```powershell
.\tools\ai-peas.exe . -o ai-peas-loot.json
```

Use `--redact-secret-values` for a sanitized collector report.

### Mini-PEAS

Collect bounded Linux or Windows privilege-escalation evidence:

```bash
python3 tools/mini-peas.py -o mini-peas-loot.json
python3 tools/mini-peas.py /opt/app /var/www -o mini-peas-loot.json
python3 -m main.pathfinder --mini-peas-json mini-peas-loot.json \
  --target-host TARGET_IP -o findings-post.json
```

```powershell
.\tools\mini-peas.exe -o mini-peas-loot.json
```

Place either report beneath `loot/<IP>/` for normal `scan` auto-detection. Use
`--quiet` for JSON-only collection and `--help` for search-budget controls.
Mini-PEAS interface, route, and listener checks are also promoted into
`network_interface`, `reachable_subnet`, and `internal_service` findings tied to
the originating foothold. PathFinder suggests only manual, scope-checked
one-hop forwarding; it does not create tunnels or launch pivot scans.

### Frozen Linux collectors

Release CI produces StaticX-wrapped x86_64 and ARM64 binaries for both
collectors, plus `SHA256SUMS` and `artifact-manifest.json`. CI verifies
architecture, static loading, CLI startup, bounded collection, and output schema.

```bash
bash tools/build-linux-collectors.sh --output-dir dist
sha256sum -c dist/SHA256SUMS
```

Build on a native host matching the target architecture; PyInstaller is not a
cross-compiler.

## Output Example

```text
__________         __  .__    ___________.__            .___
\______   \_____ _/  |_|  |__ \_   _____/|__| ____    __| _/___________
 |     ___/\__  \\   __\  |  \ |    __)  |  |/    \  / __ |/ __ \_  __ \
 |    |     / __ \|  | |   Y  \|     \   |  |   |  \/ /_/ \  ___/|  | \/
 |____|    (____  /__| |___|  /\___  /   |__|___|  /\____ |\___  >__|
                \/          \/     \/            \/      \/    \/

[*] Scanning loot directory: /home/kali/labs/loot

[*] Detected 4 parseable source(s):
    [+] nmap_xml                  -> nmap.xml
    [+] ffuf_json                 -> ffuf_80.json
    [+] nikto_json                -> nikto_80.json
    [+] linpeas_txt               -> linpeas.txt

[*] Target host inferred from Nmap XML: 192.168.56.10

[*] Parsing detected files...
    [+] nmap_xml                  -> 6 findings  (nmap.xml) [192.168.56.10]
    [+] ffuf_json                 -> 9 findings  (ffuf_80.json) [192.168.56.10]
    [+] nikto_json                -> 4 findings  (nikto_80.json) [192.168.56.10]
    [+] linpeas_txt               -> 7 findings  (linpeas.txt) [192.168.56.10]

[*] Running Vulnerability Mapper...
    [+] Mapper prioritized 34 findings.

[*] Running Attack Path Synthesizer...

------------------------------------------------------------
PathFinder identified 6 potential attack path(s)
------------------------------------------------------------
[*] Triage view: showing 6 grouped lead(s) from 6 path(s). Use --show-all for the exhaustive list.

================================================================================
TRIAGE ATTACK PATH #1
[Top Priority: 95]
Name:         Linux SUID Binary - Privilege Escalation
Likelihood:   High-signal next steps
Targets:      192.168.56.10
Grouped hits: 1 underlying path(s)
================================================================================

  [+] Description:
      A SUID binary was found on 192.168.56.10: /usr/bin/find.
      This binary may be abusable to escalate privileges to root.

  [+] Suggested Commands:
      - Check GTFOBins for exploitation technique: https://gtfobins.github.io/
      - find . -exec /bin/sh -p \; -quit

================================================================================

------------------------------------------------------------
Total Findings: 20 (Public Exploits limited to --max-vulns, total discovered: 12)
------------------------------------------------------------

[001] [Score: 95] (privilege_escalation) suid_binary_found
      Host: 192.168.56.10   Port: None

[002] [Score: 85] (web_content) /backup.zip
      Host: 192.168.56.10   Port: 80

[003] [Score: 80] (vulnerability) Apache HTTP Server 2.4.49 Path Traversal and RCE
      Host: 192.168.56.10   Port: 80
      URL: https://www.exploit-db.com/exploits/50383
```

## Install

```bash
git clone https://github.com/tpazz/PathFinder.git
cd PathFinder
python3 -m pip install -r requirements.txt
```

Optional enrichment:

```bash
sudo apt install exploitdb
export GITHUB_TOKEN=...
```

Local files such as `main/credentials.json` and `main/github_cache.json` are
created as needed and are gitignored.

## Ethics

Use PathFinder only on systems you own or have explicit written permission to
test. You are responsible for how you use the output.
