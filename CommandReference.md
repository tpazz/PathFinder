### Pathfinder Command Reference Guide

This guide shows the exact commands to run for each supported tool to generate a compatible output file, and the corresponding Pathfinder command to ingest that file.

**Placeholders Used:**
*   `TARGET_IP`: The IP address of the target machine (e.g., `10.10.10.123`).
*   `TARGET_HOST`: The IP address or a hostname (e.g., `example.com`).
*   `DOMAIN.COM`: The target Active Directory domain name (e.g., `megacorp.local`).
*   `PORT`: The specific port number (e.g., `80`, `8080`).
*   `WORDLIST.TXT`: The path to your desired wordlist file.

---

### Initial Foothold Parsers

#### 1. Nmap
*   **Generate Input File:** Use the `-oX` flag to save output as XML. A comprehensive scan is recommended.
    ```bash
    nmap -sV -sC -A -oX nmap_results.xml TARGET_IP
    ```
*   **Run Pathfinder:**
    ```bash
    python3 pathfinder.py --nmap-xml nmap_results.xml
    ```

#### 2. Gobuster
*   **Generate Input File:** Use the `-o` flag to save the output to a text file.
    ```bash
    gobuster dir -u http://TARGET_HOST:PORT -w WORDLIST.TXT -o gobuster_results.txt
    ```
*   **Run Pathfinder:** Requires `--target-host` and `--gobuster-port`.
    ```bash
    python3 pathfinder.py --gobuster-txt gobuster_results.txt --target-host TARGET_HOST --gobuster-port PORT
    ```
    *Note: For `vhost` mode, add `--gobuster-mode vhost`.*

#### 3. Nikto
*   **Generate Input File:** **Crucially**, use `-Format json` to get machine-readable output.
    ```bash
    nikto -h http://TARGET_HOST:PORT -o nikto_results.json -Format json
    ```
*   **Run Pathfinder:**
    ```bash
    python3 pathfinder.py --nikto-json nikto_results.json
    ```

#### 4. WhatWeb
*   **Generate Input File:** Use `--log-json` to create the JSON output file.
    ```bash
    whatweb --log-json=whatweb.json http://TARGET_HOST:PORT
    ```
*   **Run Pathfinder:**
    ```bash
    python3 pathfinder.py --whatweb-json whatweb.json
    ```

#### 5. enum4linux-ng
*   **Generate Input File:** Use the `-oJ` flag for JSON output.
    ```bash
    enum4linux-ng -A -oJ enum4linux_results.json TARGET_IP
    ```
*   **Run Pathfinder:** Requires `--target-host`.
    ```bash
    python3 pathfinder.py --enum4linux-json enum4linux_results.json --target-host TARGET_IP
    ```

#### 6. SNMP (`snmp-check`)
*   **Generate Input File:** Redirect the standard output to a file.
    ```bash
    snmp-check -t TARGET_IP > snmp_results.txt
    ```
*   **Run Pathfinder:** Requires `--target-host`.
    ```bash
    python3 pathfinder.py --snmp-txt snmp_results.txt --target-host TARGET_IP
    ```

#### 7. sqlmap
*   **Generate Input File:** Run a standard `sqlmap` scan. The parser needs the `log` file from the output directory.
    ```bash
    sqlmap -u "http://TARGET_HOST/vuln.php?id=1" --batch
    ```
*   **Run Pathfinder:** You must provide the full path to the `log` file inside the `sqlmap` output directory.
    ```bash
    python3 pathfinder.py --sqlmap-log /home/kali/.local/share/sqlmap/output/TARGET_HOST/log
    ```

---

### Privilege Escalation Parsers

#### 8. LinPEAS
*   **Generate Input File:** Upload `linpeas.sh` to the target, run it, and redirect the output to a file.
    ```bash
    (On Target Machine) ./linpeas.sh > linpeas_results.txt
    ```
*   **Run Pathfinder:** Requires `--target-host`.
    ```bash
    python3 pathfinder.py --linpeas-txt linpeas_results.txt --target-host TARGET_IP
    ```

#### 9. WinPEAS
*   **Generate Input File:** Upload `winpeas.exe` to the target, run it, and redirect the output.
    ```bash
    (On Target Machine) winpeas.exe > winpeas_results.txt
    ```
*   **Run Pathfinder:** Requires `--target-host`.
    ```bash
    python3 pathfinder.py --winpeas-txt winpeas_results.txt --target-host TARGET_IP
    ```

---

### Active Directory Parsers

#### 10. SharpHound
*   **Generate Input Files:**
    1.  Run `SharpHound.exe` on a domain-joined machine. This creates a `.zip` file.
    2.  **Unzip the file** into a new directory.
        ```bash
        unzip 2023*_BloodHound.zip -d sharphound_data
        ```
*   **Run Pathfinder:** Provide the path to the **directory** containing the JSON files.
    ```bash
    python3 pathfinder.py --sharphound-dir sharphound_data
    ```

#### 11. ldapdomaindump
*   **Generate Input Files:** Run the tool and specify an output directory.
    ```bash
    ldapdomaindump TARGET_IP -o ldap_data
    ```
*   **Run Pathfinder:** Provide the path to the **directory** containing the TSV files.
    ```bash
    python3 pathfinder.py --ldapdomaindump-dir ldap_data
    ```

#### 12. Kerbrute & impacket-GetNPUsers
*   **Generate Input Files (2 steps):**
    1.  **Kerbrute:** Validate users against the Domain Controller.
        ```bash
        kerbrute userenum --dc TARGET_IP -d DOMAIN.COM USERS_LIST.TXT -o valid_users.txt
        ```
    2.  **GetNPUsers:** Use the valid user list to find AS-REP roastable hashes.
        ```bash
        impacket-GetNPUsers DOMAIN.COM/ -usersfile valid_users.txt -no-pass -outputfile asrep_hashes.txt
        ```
*   **Run Pathfinder:** Requires `--target-host` (use the domain name).
    ```bash
    python3 pathfinder.py --kerbrute-txt valid_users.txt --getnpusers-hashes asrep_hashes.txt --target-host DOMAIN.COM
    ```

---

### Full Engagement Example (Combining Multiple Inputs)

This is the most common and powerful way to use Pathfinder.

```bash
python3 pathfinder.py \
  --nmap-xml nmap_results.xml \
  --gobuster-txt gobuster_results.txt --target-host TARGET_IP --gobuster-port 80 \
  --nikto-json nikto_results.json \
  --whatweb-json whatweb.json \
  -v
```

### Utility Commands

*   **Teach a new rule:**
    ```bash
    python3 pathfinder.py --learn
    ```
*   **Save analysis results to a file:**
    ```bash
    python3 pathfinder.py --nmap-xml nmap.xml -o saved_findings.json
    ```
*   **Load analysis results from a file (skips parsing):**
    ```bash
    python3 pathfinder.py -i saved_findings.json
    ```
    **Max number of EDB/GitHub exploits to display (default: 10):**
    ```bash
    python3 pathfinder.py --max-vulns 25
    ```
