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
```

**What scan mode detects automatically:**

| Detected Content | Parser Used |
|---|---|
| XML with `<nmaprun` | Nmap |
| JSON with `"vulnerabilities"` + `"msg"` | Nikto |
| JSON with `"plugins"` | WhatWeb |
| JSON with `"users"` + `"groups"` | enum4linux-ng |
| Text with `VALID USERNAME:` | Kerbrute |
| Text with `$krb5asrep$` | impacket-GetNPUsers |
| Text with `[*] System information` | snmp-check |
| Text with `/path (Status: NNN)` | Gobuster (dir mode) |
| Text with `Found: subdomain` | Gobuster (vhost mode) |
| Text with `WinPEAS` / `SeImpersonatePrivilege` | WinPEAS |
| Text with `linpeas` / `╔══` | LinPEAS |
| Text with `[INFO]` + `sqlmap` + `vulnerable` | SQLMap |
| Directory with `users.json` + `domains.json` | SharpHound |
| Directory with `domain_users.tsv` | ldapdomaindump |

> **Note:** For host-dependent parsers (LinPEAS, WinPEAS, Gobuster, SNMP, Kerbrute, GetNPUsers, enum4linux), the target host is inferred from the nmap XML or Gobuster header. Pass `--target-host` explicitly if those are absent.

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

#### 5. enum4linux-ng

Use `-oJ` for JSON output. This is the only supported format.

```bash
enum4linux-ng -A -oJ enum4linux TARGET_IP
# Produces enum4linux.json
```

```bash
python3 -m main.pathfinder --enum4linux-json enum4linux.json --target-host TARGET_IP
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

# Teach PathFinder a new attack path rule (interactive)
python3 -m main.pathfinder --learn

# Increase the number of public exploits shown (default: 10 per source)
python3 -m main.pathfinder scan loot/ --max-vulns 25
```
