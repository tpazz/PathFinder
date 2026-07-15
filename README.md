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
    nikto_80.json
  10.10.10.20/
    nmap.xml
    enum4linux_10.10.10.20.json
```

## What It Parses

PathFinder supports Nmap, saved webpage HTML, Gobuster, ffuf, Nikto, WhatWeb, nuclei, WPScan,
enum4linux-ng, smbmap, NetExec/CrackMapExec, SNMP, NFS/showmount, Redis, rsync,
SMTP user enum, SQLMap logs, LinPEAS, WinPEAS, SharpHound directories/ZIPs,
ldapdomaindump, pypykatz/lsassy JSON, Kerbrute, GetNPUsers, GetUserSPNs,
secretsdump, john/hashcat `.pot` files,
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
- Synthesises attack paths from a rule-driven engine.
- Groups repeated paths by rule and actionable target, showing compact resolved
  inputs and commands instead of an arbitrary first match.
- Shows the discovery tool and producer command on findings and attack paths by
  default. Native command metadata (for example Nmap XML/ffuf JSON) and the
  one-shot-enum provenance manifest provide exact commands when available;
  legacy loot is labelled `not recorded`. Commands are preserved verbatim,
  including operator-supplied credentials.
- Correlates credentials, usernames, hashes, shares, web paths, AD findings, and
  AI/LLM surfaces across hosts.
- Correlates owned credential identities with direct SharpHound ACL and
  delegation edges. DCSync, vulnerable AD CS enrollment, and gMSA-read wins are
  surfaced as zero-hop actions; a direct target may receive one high-value hint
  when it is itself an administrator or local administrator. No transitive graph
  search is performed.
- Routes cleartext passwords to reuse checks and valid NT hashes to pass-the-hash.
  NetNTLMv2, AS-REP, TGS, DCC2, and DPAPI material is crack-first and is never
  offered to pass-the-hash actions.
- Compacts grouped credential-reuse and password-spray leads into input lists
  plus one `<USERNAME>`/`<PASSWORD>` core command per login service.
- Maps software/version findings to Searchsploit and GitHub exploit leads.
- Supports an OSCP profile with `--oscp` for manual-safe suggestions around
  restricted tools.
- Saves/reloads findings with `-o findings.json` and `-i findings.json`.
- Generates a self-contained, offline HTML engagement report with normalized
  findings, prioritized paths, and deduplicated discovery provenance.

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
- `--report [HTML]`: write an offline, self-contained HTML engagement report.
  With no path, the default is `pathfinder-report.html`. The report includes all
  paths passing `--min-likelihood`; terminal `--top` does not truncate it.
- `--report-redact-secrets`: create a sanitized report by redacting passwords,
  hashes, tokens, and credential-bearing commands. Reports preserve evidence by
  default, consistent with terminal and JSON output.

### HTML engagement reports

```bash
python3 -m main.pathfinder scan loot/ --report engagement.html
python3 -m main.pathfinder scan loot/ --min-likelihood medium --report
```

The report is a single HTML file with inline styling and no JavaScript or
network-loaded assets. Untrusted finding content is HTML-escaped. Findings,
evidence, actions, and producer commands are preserved by default; use
`--report-redact-secrets` when a sanitized export is required. Treat the default
report as sensitive engagement loot.

SharpHound collection directories may use canonical names (`users.json`) or
timestamp-prefixed names (`*_users.json`). When multiple exports exist,
PathFinder selects the newest collection of each type. Pass a ZIP directly with
`--sharphound-dir collection.zip`, or place it beneath a scan loot tree.
Pypykatz and lsassy JSON can likewise be auto-detected, or supplied with
`--lsass-json` (`--pypykatz-json` and `--lsassy-json` are accepted aliases).

### Bounded BloodHound correlation

PathFinder builds its owned-principal index only from credentials that already
support authentication: recovered passwords, valid NT hashes, or Kerberos key
material. Uncracked NetNTLMv2/Kerberos/DCC2/DPAPI captures do not mark a
principal as owned. Principal matching is domain-aware and ambiguous bare names
fail closed.

Correlation is intentionally bounded to direct edges. PathFinder may annotate
the direct takeover target with one high-value fact from SharpHound—such as
direct Domain Admin membership or local administrator access—but never follows
an outgoing edge from that target. The ownership index is capped at 5,000
principals and derived output at 250 results, with an explicit warning if either
limit is reached.

## AI-PEAS

After an authorised foothold on an AI/RAG/model host, run:

```bash
python3 tools/ai-peas.py . -o ai-peas-loot.json
```

On a 64-bit Windows target without Python, copy and run the standalone collector:

```powershell
.\tools\ai-peas.exe . -o ai-peas-loot.json
```

The executable produces the same `ai_post_exploitation_loot` JSON accepted by
`--ai-peas-json` and `scan`. Maintainers can rebuild it on Windows with
`tools\build_ai-peas.ps1` after installing PyInstaller.

Move `ai-peas-loot.json` into the host loot folder or pass it directly:

```bash
python3 -m main.pathfinder --ai-peas-json ai-peas-loot.json -o findings.json
python3 -m main.pathfinder scan loot/
```

The collector is read-only and preserves discovered values by default for lab
use. Add `--redact-secret-values` only when you explicitly need a sanitized
report. The legacy `--include-secret-values` flag remains accepted.

AI-PEAS prioritizes AI/configuration candidates before applying `--max-files`
and progressively reports significant discoveries. It extracts notebook cells,
deployment configuration (Compose, Kubernetes, systemd and Jupyter), current
AI-related environment variables, readable runtime process context, provider
secrets, vector/RAG and MLflow/object-store relationships, MCP/agent manifests,
prompt templates, model artifacts and unsafe loaders. Same-source signals are
correlated into higher-confidence application control-plane chains. Use
`--quiet` to suppress progress and `--common-roots` for a broader bounded pass.

## Mini-PEAS

When PEAS is unavailable, the built-in PEN-200-oriented collector automates the
manual post-foothold checks while preserving raw command output and sensitive
evidence. On Linux:

```bash
python3 tools/mini-peas.py -o mini-peas-loot.json
```

On 64-bit Windows without Python:

```powershell
.\tools\mini-peas.exe -o mini-peas-loot.json
```

Additional paths can be supplied to prioritize credential/config searches:

```bash
python3 tools/mini-peas.py /opt/app /var/www -o mini-peas-loot.json
```

On both platforms the collector also performs a bounded targeted Git-loot pass:
it reads useful `.git` metadata while skipping object databases, and records
effective configuration, remotes, recent history, up to 20 stash contents, and
secret-bearing configuration diffs. Use
`--max-git-repos` to change the default limit of 100 repositories.

The filesystem budget applies to relevant credential/configuration candidates,
with high-value named files retained first; the selected output file is excluded
from collection. Linux checks correlate unusual/abusable SUID and dangerous
capabilities with groups, writable PATH entries, privileged processes, cron,
systemd, logrotate, loader configuration and mounts. Windows checks cover
dangerous token privileges, service configuration/directories, scheduled-task
scripts and definitions, AutoLogon, unattended/IIS files, readable registry
hives and writable machine PATH entries. Use `--quiet` when only JSON output is
required. Positional paths normally augment common OS locations; add
`--only-specified-roots` for a strictly targeted credential/configuration pass.
Credential promotion recognises concrete assignments in environment, YAML,
quoted JSON, XML element/attribute, Netrc, registry and PowerShell formats, plus
Docker `auth` values only when they decode to a non-empty `username:password`.
Empty values and environment/template placeholders are not promoted.

Feed the report directly into PathFinder or place it beneath `loot/<IP>/`:

```bash
python3 -m main.pathfinder --mini-peas-json mini-peas-loot.json \
  --target-host TARGET_IP -o findings-post.json
python3 -m main.pathfinder scan loot/ -o findings-post.json
```

The collector is read-only apart from writing its report. It does not redact
captured environment variables, histories, keys, registry results, configuration
lines, or command output. Checks, completion status, durations, and promoted
findings are printed progressively while collection runs. When ingested,
PathFinder displays the underlying check command in finding and attack-path
discovery provenance. Distinct local files, Git artifacts, binaries, services,
and tasks remain separate findings. Credential-material hits are summarized in
one compact grouped triage path with source paths and a reusable review template;
use `--show-all` for every underlying path. Privilege-escalation attack paths
embed the relevant validation and exploitation workflow directly instead of
linking back to private notes. Maintainers can rebuild the Windows binary with
`tools\build_mini-peas.ps1` after installing PyInstaller.

## Frozen Linux collectors

Release CI builds both collectors natively for x86_64 and ARM64, then wraps the
PyInstaller executables with StaticX. The resulting files do not require Python
or target-system shared libraries:

- `mini-peas-linux-x86_64` / `mini-peas-linux-arm64`
- `ai-peas-linux-x86_64` / `ai-peas-linux-arm64`

Each architecture artifact also contains `SHA256SUMS` and
`artifact-manifest.json`. Verification fails unless each file has the expected
ELF machine type, has no `PT_INTERP` dynamic loader, renders `--help`, completes
a bounded real collection, writes the expected PathFinder JSON schema, and the
two collector sources import only the Python standard library.

Build on a native Linux host matching the desired target architecture
(PyInstaller is not a cross-compiler):

```bash
sudo apt-get install binutils musl-tools patchelf scons
BOOTLOADER_CC=musl-gcc python3 -m pip install --no-binary staticx \
  -r tools/linux-build-requirements.txt
bash tools/build-linux-collectors.sh --output-dir dist
sha256sum -c dist/SHA256SUMS
```

The `Linux collector artifacts` workflow performs the same build on
`ubuntu-24.04` and `ubuntu-24.04-arm`. StaticX ignores advanced target NSS
configuration, so directory-backed identity lookup may differ on hosts using
AD/LDAP NSS modules; local files, environment context, and native discovery
commands remain available.

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
