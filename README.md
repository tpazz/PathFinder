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
*   **Integrate:** Suggest relevant Metasploit modules, `searchsploit` queries and public Github Exploits.

## Key Features

*   **Multi-Input Parsing:** Ingests and standardizes data from a wide array of popular reconnaissance and enumeration tools (Nmap, Gobuster, Nikto, WhatWeb, LinPEAS, WinPEAS, SharpHound, and more).
*   **Vulnerability & Exploit Mapping:** Correlates identified services/versions with known CVEs and public exploits by leveraging offline databases like Exploit-DB (`searchsploit`) and online searches for public GitHub exploits.
*   **Misconfiguration & Weakness Detection:** Automatically identifies common low-hanging fruit such as default credentials, anonymous access, outdated software, and dangerous configurations found by integrated scanners.
*   **Attack Path Synthesis:** Moves beyond simple lists by using a powerful, correlation-focused rule engine to synthesize multi-step attack paths (e.g., "Found a credential, which can be used on an open SSH service on another host.").
*   **User-Trainable Intelligence:** Features an interactive learning mode (`--learn`) that allows users to easily teach Pathfinder new attack patterns. The tool's "brain" grows with the user's experience, making it a personalized knowledge base.
*   **Interactive Credential Management:** Includes a dedicated credential manager (`--add-cred`) that allows users to manually add found passwords or hashes. These credentials are then automatically weaponized by the synthesis engine against all discovered login services.
*   **Heuristic Scoring:** Prioritizes all findings and synthesized attack paths using a scoring system based on exploitability, impact, and reliability, helping testers focus on what matters most.
*   **Configurable Verbosity:** Control the level of detail in the output, from high-level attack path summaries to detailed evidence and rationale.

## Example Workflow
```bash
python3 -m main.pathfinder --nmap-xml data/nmap_results.xml --gobuster-txt data/gobuster_results.txt --target-host 192.168.192.168 --gobuster-port 80 -o data/results.json -v

__________          __   .__      _____ .__             .___              
\______   \_____  _/  |_ |  |__ _/ ____\|__|  ____    __| _/ ____ _______ 
 |     ___/\__  \ \   __\|  |  \\   __\ |  | /    \  / __ |_/ __ \\_  __ \
 |    |     / __ \_|  |  |   Y  \|  |   |  ||   |  \/ /_/ |\  ___/ |  | \/
 |____|    (____  /|__|  |___|  /|__|   |__||___|  /\____ | \___  >|__|   
                \/            \/                 \/      \/     \/        


  >> [Intelligent Reconnaissance Analysis for Pentesters] <<

[*] Attack Path Synthesizer initialized with 2 rules from /home/kali/Github/Pathfinder/main/attack_rules.json

[*] Parsing new data files...

[*] Parsing Nmap: data/nmap_results.xml
    [+] Found 8 raw findings from Nmap.
[*] Parsing Gobuster: data/gobuster_results.txt
    [+] Found 8 raw findings from Gobuster.

[*] Running Vulnerability Mapper on new findings...

    [+] Mapper prioritized 88 of the new findings.

[*] Saving prioritized findings to: data/results.json
    [+] Successfully saved 88 findings.

[*] Running Attack Path Synthesizer...

--- Pathfinder has identified 1 potential attack path(s)! ---

================================================================================
ATTACK PATH #1
Name:       Credential Reuse on Login Service [Priority: 98]
Target:     192.168.228.211
================================================================================

  [+] Description:
      A credential for user 'admin' can be tested against the open 'ssh' service on host 192.168.228.211.

  [+] Rationale:
      Credential reuse is a highly effective attack. Credentials found in one context should be tested against all available login services on all discovered hosts.

  [+] Suggested Commands:
      - Attempt to log in to the 'ssh' service at 192.168.228.211:22 using the username 'admin' and password 'P@$$w0rd@12345'.
      - Example with crackmapexec: crackmapexec ssh 192.168.228.211 -u 'admin' -p 'P@$$w0rd@12345'
      - If the credential is a hash ('None'), attempt Pass-the-Hash attacks for services like SMB and WinRM.

  [+] Matched Evidence:
      - Trigger 1: admin (credential)
      - Trigger 2: ssh (service)

================================================================================

--- Total Findings: 21 (Public Exploits limited to --max-vulns, total discovered: 77):

[1] [Score: 100] admin (credential)
    Host: MANUALLY_ADDED, Port: None

[2] [Score: 70] /logs (web_content)
    Host: 192.168.228.211, Port: 80

[3] [Score: 70] GitHub Exploit: MedKH1684/Log4j-Vulnerability-Exploitation - None (vulnerability)
    Host: 192.168.228.211, Port: 22
    URL: https://github.com/MedKH1684/Log4j-Vulnerability-Exploitation

[4] [Score: 70] GitHub Exploit: flyme2bluemoon/thm-advent - Try Hack Me Advent of Cyber 2020 event (vulnerability)
    Host: 192.168.228.211, Port: 22
    URL: https://github.com/flyme2bluemoon/thm-advent

[5] [Score: 70] GitHub Exploit: Totes5706/TotesHTB - Walkthrough and Writeups for the HackTheBox Penetration Lab Testing Environment (vulnerability)
    Host: 192.168.228.211, Port: 22
    URL: https://github.com/Totes5706/TotesHTB

[6] [Score: 70] GitHub Exploit: kira2040k/The-Marketplace - The Marketplace walkthrough (vulnerability)
    Host: 192.168.228.211, Port: 22
    URL: https://github.com/kira2040k/The-Marketplace

[7] [Score: 70] GitHub Exploit: Yuva-H/nmap-vm-scan-report - Network vulnerablity scan of a Windows virtual machine using Nmap with OS detection and services enumeration.  (vulnerability)
    Host: 192.168.228.211, Port: 22
    URL: https://github.com/Yuva-H/nmap-vm-scan-report

[8] [Score: 70] GitHub Exploit: awesome-selfhosted/awesome-selfhosted - A list of Free Software network services and web applications which can be hosted on your own servers (vulnerability)
    Host: 192.168.228.211, Port: 22
    URL: https://github.com/awesome-selfhosted/awesome-selfhosted

[9] [Score: 70] GitHub Exploit: trimstray/the-book-of-secret-knowledge - A collection of inspiring lists, manuals, cheatsheets, blogs, hacks, one-liners, cli/web tools and more. (vulnerability)
    Host: 192.168.228.211, Port: 22
    URL: https://github.com/trimstray/the-book-of-secret-knowledge

[10] [Score: 70] GitHub Exploit: luong-komorebi/Awesome-Linux-Software - 🐧 A list of awesome Linux softwares  (vulnerability)
    Host: 192.168.228.211, Port: 22
    URL: https://github.com/luong-komorebi/Awesome-Linux-Software

[11] [Score: 70] GitHub Exploit: drduh/macOS-Security-and-Privacy-Guide - Community guide to securing and improving privacy on macOS. (vulnerability)
    Host: 192.168.228.211, Port: 22
    URL: https://github.com/drduh/macOS-Security-and-Privacy-Guide

[12] [Score: 70] GitHub Exploit: blaCCkHatHacEEkr/PENTESTING-BIBLE - articles (vulnerability)
    Host: 192.168.228.211, Port: 22
    URL: https://github.com/blaCCkHatHacEEkr/PENTESTING-BIBLE

[13] [Score: 40] /img (web_content)
    Host: 192.168.228.211, Port: 80

[14] [Score: 40] /plugins (web_content)
    Host: 192.168.228.211, Port: 80

[15] [Score: 40] /css (web_content)
    Host: 192.168.228.211, Port: 80

[16] [Score: 40] /ajax (web_content)
    Host: 192.168.228.211, Port: 80

[17] [Score: 40] /js (web_content)
    Host: 192.168.228.211, Port: 80

[18] [Score: 40] /components (web_content)
    Host: 192.168.228.211, Port: 80

[19] [Score: 40] /inc (web_content)
    Host: 192.168.228.211, Port: 80

[20] [Score: 10] ssh (service)
    Host: 192.168.228.211, Port: 22

[21] [Score: 10] http (service)
    Host: 192.168.228.211, Port: 80
```
### Ethical Discliamer 

This tool is intended for educational purposes and authorized security testing only. Using this tool to attempt unauthorized access to any system or account is illegal and unethical. Always obtain explicit, written permission before using this tool on any system you do not own. The developers assume no liability and are not responsible for any misuse or damage caused by this program.
