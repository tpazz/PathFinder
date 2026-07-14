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
    nikto_80.json
  10.10.10.20/
    nmap.xml
    enum4linux_10.10.10.20.json
```

## What It Parses

PathFinder supports Nmap, saved webpage HTML, Gobuster, ffuf, Nikto, WhatWeb, nuclei, WPScan,
enum4linux-ng, smbmap, NetExec/CrackMapExec, SNMP, NFS/showmount, Redis, rsync,
SMTP user enum, SQLMap logs, LinPEAS, WinPEAS, SharpHound, ldapdomaindump,
Kerbrute, GetNPUsers, GetUserSPNs, secretsdump, john/hashcat `.pot` files,
certipy, one-shot-enum AI surface JSON, the AI loot collector JSON, and the
PathFinder manual Linux/Windows privilege-escalation collector JSON.

## Core Features

- Auto-detects loot files in `scan` mode.
- Extracts potential usernames from saved webpage text by default. These remain
  `username_candidate` findings requiring manual validation and are never
  promoted to confirmed users automatically. Tool-enumerated and manually
  supplied usernames are labelled `confirmed_username`; candidates receive a
  dedicated `Username Candidates for Manual Review` attack path in both full
  and grouped triage views.
- When one-shot-enum stores ffuf matched responses, recursively ingests those
  discovered pages and maps each response back to its original URL and ffuf
  discovery command.
- Extracts concrete, same-target query URLs and named GET/POST forms from saved
  pages as manual SQLMap triage candidates. It also recognises query URLs in
  JavaScript literals while excluding external targets, static assets, and
  tracking-only parameters.
- Synthesises attack paths from a 99-rule engine.
- Groups repeated paths by rule and actionable target, showing compact resolved
  inputs and commands instead of an arbitrary first match.
- Shows the discovery tool and producer command on findings and attack paths by
  default. Native command metadata (for example Nmap XML/ffuf JSON) and the
  one-shot-enum provenance manifest provide exact commands when available;
  legacy loot is labelled `not recorded`. Commands are preserved verbatim,
  including operator-supplied credentials.
- Correlates credentials, usernames, hashes, shares, web paths, AD findings, and
  AI/LLM surfaces across hosts.
- Compacts grouped credential-reuse and password-spray leads into input lists
  plus one `<USERNAME>`/`<PASSWORD>` core command per login service.
- Maps software/version findings to Searchsploit and GitHub exploit leads.
- Supports an OSCP profile with `--oscp` for manual-safe suggestions around
  restricted tools.
- Saves/reloads findings with `-o findings.json` and `-i findings.json`.

## Useful Flags

- `--top N`: show the top grouped leads (`20` by default, `0` for all).
- `--min-likelihood low|medium|high`: hide lower-confidence leads.
- `--show-all`: print every generated attack path instead of grouped triage.
- `--hide-discovery`: hide discovery tools and producer commands from findings and attack paths.
- `--hide-findings`: hide the prioritized findings list while retaining attack paths.
- `--validate-credentials`: actively execute resolved credential-reuse login checks, one at a time. This is disabled by default and may trigger lockouts or security alerts.
- `--max-vulns N`: cap EDB and GitHub exploit findings and attack-path inputs
  (`5` per source, per IP by default).
- `--offline`: disable GitHub and Searchsploit enrichment.
- `--skip-github` / `--skip-searchsploit`: disable one enrichment source.
- `--target-host HOST`: provide host context for flat loot folders.
- `--oscp`: strip restricted-tool commands from suggestions and flag exam caveats.
- `--no-color`: disable ANSI colour output.

## AI Loot Collector

After an authorised foothold on an AI/RAG/model host, run:

```bash
python3 tools/ai_loot_collector.py . -o ai_loot.json
```

On a 64-bit Windows target without Python, copy and run the standalone collector:

```powershell
.\pathfinder-ai-loot-collector.exe . -o ai_loot.json
```

The executable produces the same `ai_post_exploitation_loot` JSON accepted by
`--ai-loot-json` and `scan`. Maintainers can rebuild it on Windows with
`tools\build_ai_loot_collector.ps1` after installing PyInstaller.

Move `ai_loot.json` into the host loot folder or pass it directly:

```bash
python3 -m main.pathfinder --ai-loot-json ai_loot.json -o findings.json
python3 -m main.pathfinder scan loot/
```

The collector is read-only and preserves discovered values by default for lab
use. Add `--redact-secret-values` only when you explicitly need a sanitized
report. The legacy `--include-secret-values` flag remains accepted.

## Manual Privilege-Escalation Collector

When PEAS is unavailable, the PEN-200-notes-driven collector automates the
manual post-foothold checks while preserving raw command output and sensitive
evidence. On Linux:

```bash
python3 tools/manual_privesc_collector.py -o manual_privesc_loot.json
```

On 64-bit Windows without Python:

```powershell
.\tools\pathfinder-manual-privesc-collector.exe -o manual_privesc_loot.json
```

Additional paths can be supplied to prioritize credential/config searches:

```bash
python3 tools/manual_privesc_collector.py /opt/app /var/www -o manual_privesc_loot.json
```

Feed the report directly into PathFinder or place it beneath `loot/<IP>/`:

```bash
python3 -m main.pathfinder --manual-privesc-json manual_privesc_loot.json \
  --target-host TARGET_IP -o findings-post.json
python3 -m main.pathfinder scan loot/ -o findings-post.json
```

The collector is read-only apart from writing its report. It does not redact
captured environment variables, histories, keys, registry results, configuration
lines, or command output. Maintainers can rebuild the Windows binary with
`tools\build_manual_privesc_collector.ps1` after installing PyInstaller.

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
