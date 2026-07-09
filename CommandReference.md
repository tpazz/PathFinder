## PathFinder Command Reference Guide

This guide shows the exact commands to run for each supported tool to generate a compatible output file, and the corresponding PathFinder command to ingest it.

**Placeholders:**
- `TARGET_IP` — IP address of the target (e.g., `10.10.10.123`)
- `TARGET_HOST` — IP or hostname (e.g., `example.com`)
- `DOMAIN.COM` — Active Directory domain name (e.g., `megacorp.local`)
- `PORT` — Port number (e.g., `80`, `8080`)
- `WORDLIST` — Path to your wordlist file

---

## Quick Start — Scan Mode (Recommended)

The easiest way to use PathFinder. Dump all your tool output files into one directory and point PathFinder at it. File types are detected automatically by content — no need to remember flag names.

```bash
# 1. Create a loot directory for the engagement
mkdir loot/

# 2. Run your tools, saving output to that directory
nmap -sV -sC -A -oX loot/nmap.xml TARGET_IP
gobuster dir -u http://TARGET_IP -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -o loot/gobuster.txt
nikto -h http://TARGET_IP -o loot/nikto.json -Format json
./linpeas.sh > loot/linpeas.txt    # on the target machine, then transfer back

# 3. Run PathFinder — target host is inferred from nmap XML automatically
python3 -m main.pathfinder scan loot/

# Or specify target host explicitly (required if nmap output is absent)
python3 -m main.pathfinder scan loot/ --target-host TARGET_IP

# Save findings for later or for iterative analysis
python3 -m main.pathfinder scan loot/ --target-host TARGET_IP -o findings.json

# Keep noisy engagements readable: display only the top grouped triage leads
python3 -m main.pathfinder scan loot/ --top 10

# Show every synthesized attack path instead of grouped triage output
python3 -m main.pathfinder scan loot/ --show-all
```

**What scan mode detects automatically:**

| Detected Content | Parser Used |
|---|---|
| XML with `<nmaprun` | Nmap |
| JSON with `"vulnerabilities"` + `"msg"` | Nikto |
| JSON with `"plugins"` | WhatWeb |
| JSON with `"results"` + `"commandline"` | ffuf |
| JSONL with `"template-id"` / `"matched-at"` | nuclei |
| JSON with `"target_url"` + `"plugins"` | wpscan |
| JSON with `"ai_surfaces"` / `"type":"llm_enum"` | one-shot-enum AI/LLM enumeration |
| JSON with `"users"` + `"groups"` | enum4linux-ng |
| JSON with `"Certificate Templates"` | certipy |
| Text with `VALID USERNAME:` | Kerbrute |
| Text with `$krb5asrep$` | impacket-GetNPUsers |
| Text with `$krb5tgs$` | impacket-GetUserSPNs |
| Text with `user:rid:lm:nt:::` | impacket-secretsdump |
| Text with `[+] IP:` + share table | smbmap |
| Text with `SMB <ip> <port> <name> [..]` | NetExec / CrackMapExec |
| Text with `[*] System information` | snmp-check |
| Text with `/path (Status: NNN)` | Gobuster (dir mode) |
| Text with `Found: subdomain` | Gobuster (vhost mode) |
| Text with `WinPEAS` / `SeImpersonatePrivilege` | WinPEAS |
| Text with `linpeas` / `╔══` | LinPEAS |
| Text with `[INFO]` + `sqlmap` + `vulnerable` | SQLMap |
| Directory with `users.json` + `domains.json` | SharpHound |
| Directory with `domain_users.tsv` | ldapdomaindump |

> **Note:** For host-dependent parsers (LinPEAS, WinPEAS, Gobuster, SNMP, Kerbrute, enum4linux) in a *flat* loot dir, the target host is inferred from the nmap XML or Gobuster header — pass `--target-host` if those are absent. In a **per-host** loot layout (below) the host comes from the directory name, so no `--target-host` is needed.

### Multi-host engagements

Scan mode ingests an entire engagement in one pass. Give each host its own
subdirectory named after the host; every file inside is attributed to that host,
and findings are correlated across hosts (so a credential from one box is
sprayed against services on the others). Every file is ingested — multiple web
ports, repeated scans, and multiple hosts no longer overwrite each other.

```
loot/
├── 10.10.10.10/
│   ├── nmap.xml
│   ├── gobuster_80.txt
│   └── nxc.log
└── 10.10.10.20/
    ├── nmap.xml
    └── linpeas.txt
```

```bash
python3 -m main.pathfinder scan loot/     # no --target-host needed; hosts come from the dirs
```

`one-shot-enum --suggest`/`--run` produces exactly this layout automatically
(including each host's `nmap.xml`), so the two tools line up end to end.

---

## Manual Mode — Individual Tool Flags

Use these when you need precise control, or when scan mode can't detect a file.

---

### Initial Foothold Parsers

#### 1. Nmap

Save output as XML with `-oX`. A full service scan is recommended.

```bash
nmap -sV -sC -A -oX nmap.xml TARGET_IP
```

```bash
python3 -m main.pathfinder --nmap-xml nmap.xml
```

#### 2. Gobuster

Save output with `-o`. PathFinder reads the standard text output.

```bash
# Directory bruteforce
gobuster dir -u http://TARGET_HOST:PORT -w WORDLIST -o gobuster.txt

# Virtual host discovery
gobuster vhost -u http://TARGET_HOST -w WORDLIST -o gobuster_vhost.txt --append-domain
```

```bash
# Directory mode (default)
python3 -m main.pathfinder --gobuster-txt gobuster.txt --target-host TARGET_HOST --gobuster-port PORT

# Vhost mode
python3 -m main.pathfinder --gobuster-txt gobuster_vhost.txt --target-host TARGET_HOST --gobuster-mode vhost
```

#### 3. Nikto

**Must use `-Format json`** for machine-readable output.

```bash
nikto -h http://TARGET_HOST:PORT -o nikto.json -Format json
```

```bash
python3 -m main.pathfinder --nikto-json nikto.json
```

#### 4. WhatWeb

Use `--log-json` to produce JSON output.

```bash
whatweb --log-json=whatweb.json http://TARGET_HOST:PORT
```

```bash
python3 -m main.pathfinder --whatweb-json whatweb.json
```

#### 4b. ffuf

Use `-of json` for machine-readable output. Findings are treated like Gobuster web content.

```bash
ffuf -u http://TARGET_HOST:PORT/FUZZ -w WORDLIST -of json -o ffuf.json
```

```bash
python3 -m main.pathfinder --ffuf-json ffuf.json
```

#### 4c. nuclei

Use `-jsonl` for line-delimited JSON. CVE IDs feed the exploit mapper; severity drives prioritisation.

```bash
nuclei -u http://TARGET_HOST:PORT -jsonl -o nuclei.jsonl
```

```bash
python3 -m main.pathfinder --nuclei-jsonl nuclei.jsonl
```

#### 4d. wpscan

Use `--format json`. Core/plugins/themes become software products (exploit-mapped by version); reported issues become vulnerabilities; enumerated users feed spraying rules.

```bash
wpscan --url http://TARGET_HOST:PORT --format json -o wpscan.json
```

```bash
python3 -m main.pathfinder --wpscan-json wpscan.json
```

#### 4e. one-shot-enum AI/LLM enumeration

[one-shot-enum](../one-shot-enum) performs the live AI-surface fingerprinting
(OpenAI-compatible APIs, Ollama, vLLM/TGI, LangServe, agent/MCP, RAG stores,
MLflow, Jupyter, Gradio, workflow builders, image-generation APIs, ...) and
writes a `llm_enum_<port>.json` per host. PathFinder turns each detected surface
into an `ai_service` finding, preserving endpoint/probe evidence, and maps it to
OWASP-LLM/course-note attack paths (prompt injection, tool/agency abuse, RAG
poisoning, artifact-consumer compromise, unauthenticated inference, schema
recovery, and cross-surface RAG/tool chains).

```bash
# produced automatically by:  one-shot-enum <target> --ai-paths --run
python3 -m main.pathfinder --llm-enum-json loot/10.10.10.10/llm_enum_11434.json
# (or just drop the loot dir in front of `scan` - it is auto-detected)
```

#### 5. enum4linux-ng

Use `-oJ` for JSON output. This is the only supported format.

```bash
enum4linux-ng -A -oJ enum4linux TARGET_IP
# Produces enum4linux.json
```

```bash
python3 -m main.pathfinder --enum4linux-json enum4linux.json --target-host TARGET_IP
```

#### 5b. smbmap

Redirect stdout to a file. Writable shares become high-value misconfiguration findings.

```bash
smbmap -H TARGET_IP -u guest -p '' > smbmap.txt
```

```bash
python3 -m main.pathfinder --smbmap-txt smbmap.txt
```

#### 5c. NetExec / CrackMapExec

Use `--log` to save (or redirect the console output). Validated creds, `Pwn3d!` admin access, SMB signing status, null sessions, and shares are all parsed.

```bash
nxc smb TARGET_IP -u USER -p PASS --shares --users --log nxc.log
# CrackMapExec output is also accepted (near-identical format)
```

```bash
python3 -m main.pathfinder --netexec-log nxc.log
```

#### 6. SNMP (`snmp-check`)

Redirect stdout to a file with `>` or use `tee` to see output live.

```bash
snmp-check -t TARGET_IP > snmp.txt
# or
snmp-check -t TARGET_IP | tee snmp.txt
```

```bash
python3 -m main.pathfinder --snmp-txt snmp.txt --target-host TARGET_IP
```

#### 7. SQLMap

Run a standard scan. PathFinder reads the `log` file created inside sqlmap's output directory.

```bash
sqlmap -u "http://TARGET_HOST/page.php?id=1" --batch
```

```bash
# The log file is at: ~/.local/share/sqlmap/output/TARGET_HOST/log
python3 -m main.pathfinder --sqlmap-log ~/.local/share/sqlmap/output/TARGET_HOST/log
```

---

### Privilege Escalation Parsers

#### 8. LinPEAS

Upload `linpeas.sh` to the target, execute it, and save the output. Use `tee` to see it live **and** save it — plain `>` redirection works too, but you lose the live view.

```bash
# On the target — see output live AND save to file (preserves ANSI colour codes)
./linpeas.sh | tee linpeas.txt

# Transfer back to your attack box (scp, python server, etc.)
scp user@TARGET_IP:~/linpeas.txt .
```

```bash
python3 -m main.pathfinder --linpeas-txt linpeas.txt --target-host TARGET_IP
```

> PathFinder handles both ANSI-coloured and plain-text linpeas output.

#### 9. WinPEAS

Upload `winpeas.exe` to the target and redirect output to a file.

```bash
# On the target (PowerShell)
.\winpeas.exe | Out-File -Encoding ASCII winpeas.txt

# Or CMD
winpeas.exe > winpeas.txt
```

```bash
python3 -m main.pathfinder --winpeas-txt winpeas.txt --target-host TARGET_IP
```

---

### Active Directory Parsers

#### 10. SharpHound

Run `SharpHound.exe` on a domain-joined machine, unzip the resulting archive, then point PathFinder at the directory of JSON files.

```bash
# Collect all data
SharpHound.exe -c All

# Transfer the zip back and unzip
unzip *_BloodHound.zip -d sharphound_data/
```

```bash
# Provide the directory path, not a single file
python3 -m main.pathfinder --sharphound-dir sharphound_data/
```

> Supports BloodHound v4 (flat JSON keys) and v5/CE (`Properties` sub-object) formats.

#### 11. ldapdomaindump

Specify an output directory with `-o`.

```bash
ldapdomaindump TARGET_IP -u 'DOMAIN\user' -p 'password' -o ldap_data/
```

```bash
python3 -m main.pathfinder --ldapdomaindump-dir ldap_data/
```

#### 12. Kerbrute + impacket-GetNPUsers

Run kerbrute to enumerate valid users, then feed that list to GetNPUsers to capture AS-REP hashes.

```bash
# Step 1: enumerate valid domain users
kerbrute userenum --dc TARGET_IP -d DOMAIN.COM userlist.txt -o valid_users.txt

# Step 2: find AS-REP roastable accounts
impacket-GetNPUsers DOMAIN.COM/ -usersfile valid_users.txt -no-pass -outputfile asrep_hashes.txt
```

```bash
python3 -m main.pathfinder \
  --kerbrute-txt valid_users.txt \
  --getnpusers-hashes asrep_hashes.txt \
  --target-host DOMAIN.COM
```

#### 13. impacket-GetUserSPNs (Kerberoasting)

Requires valid domain credentials. Each captured TGS-REP hash becomes a Kerberoastable-user finding **and** a reusable credential.

```bash
impacket-GetUserSPNs DOMAIN.COM/USER:PASS -dc-ip TARGET_IP -request -outputfile kerberoast.txt
```

```bash
python3 -m main.pathfinder --getuserspns-hashes kerberoast.txt
```

#### 14. impacket-secretsdump

Recovered NT hashes (and any cleartext) become credentials that spray/PtH against every discovered service.

```bash
impacket-secretsdump DOMAIN.COM/USER:PASS@TARGET_IP | tee secretsdump.txt
```

```bash
python3 -m main.pathfinder --secretsdump-txt secretsdump.txt
```

#### 15. certipy (AD CS)

Use `-json`. Each ESC* finding on a vulnerable template becomes a privilege-escalation path.

```bash
certipy find -u USER@DOMAIN.COM -p PASS -dc-ip TARGET_IP -json -output certipy
# Produces certipy_Certipy.json
```

```bash
python3 -m main.pathfinder --certipy-json certipy_Certipy.json
```

---

## Data Persistence — Saving and Loading Findings

PathFinder supports an iterative workflow. You can save findings after each run and reload them, building up a complete picture across multiple enumeration stages.

```bash
# Save findings to JSON after parsing nmap + gobuster
python3 -m main.pathfinder --nmap-xml nmap.xml --gobuster-txt gobuster.txt \
  --target-host TARGET_IP -o findings.json

# Later: load existing findings and add linpeas output on top
python3 -m main.pathfinder -i findings.json \
  --linpeas-txt linpeas.txt --target-host TARGET_IP -o findings.json

# Load saved findings only (re-run synthesis without re-parsing)
python3 -m main.pathfinder -i findings.json
```

---

## Credential Management

PathFinder maintains a persistent credential store. Credentials you add are automatically tested against all discovered login services by the attack path synthesizer.

```bash
# Add a found credential (interactive wizard)
python3 -m main.pathfinder --add-cred
```

The wizard prompts for username, password or hash, and where you found it. Credentials are saved to `main/credentials.json`.

---

## Utility Options

```bash
# Set GitHub token for higher API rate limits (exploit lookup enrichment)
export GITHUB_TOKEN="ghp_YourTokenHere"

# Run offline — no GitHub or Searchsploit lookups
python3 -m main.pathfinder scan loot/ --offline

# Skip only GitHub (keep Searchsploit)
python3 -m main.pathfinder scan loot/ --skip-github

# Show more detail: rationale, matched evidence per attack path
python3 -m main.pathfinder scan loot/ -v

# Keep the terminal focused on more actionable leads
python3 -m main.pathfinder scan loot/ --min-likelihood medium
python3 -m main.pathfinder scan loot/ --min-likelihood high

# Tune grouped triage output; use 0 to show every group
python3 -m main.pathfinder scan loot/ --top 20
python3 -m main.pathfinder scan loot/ --top 0

# Fall back to the old exhaustive attack-path listing
python3 -m main.pathfinder scan loot/ --show-all

# Teach PathFinder a new attack path rule (interactive)
python3 -m main.pathfinder --learn

# Increase the number of public exploits shown (default: 10 per source)
python3 -m main.pathfinder scan loot/ --max-vulns 25

# Disable ANSI colour (also auto-disabled when output is piped/redirected)
python3 -m main.pathfinder scan loot/ --no-color

# OSCP exam profile: strip prohibited-tool commands (sqlmap, nuclei) from
# suggestions, flag Metasploit's one-target limit, and warn if a prohibited
# tool's output was ingested. Leads are still shown; only the restricted
# commands are removed. (searchsploit/GitHub enrichment stay on - both allowed.)
python3 -m main.pathfinder scan loot/ --oscp
```
