# DFIR Capstone Investigations

Three digital forensics and incident response (DFIR) investigations covering **memory forensics**, **disk and artifact analysis**, and **malware triage**. Each case has a full written report with evidence screenshots, an attack-chain timeline, IOCs, and conclusions.

**Author:** Dnyaneshwari Kale

> **Spoiler notice:** These reports contain full solutions to CTF-style challenges. Attempt the challenges yourself first if you plan to.

---

## Cases at a Glance

| # | Case | Type | Key Techniques | Report |
|---|------|------|----------------|--------|
| 1 | Compromised XAMPP/DVWA Host (Capstone Challenge 4) | Memory forensics | Volatility 2.6, log recovery from RAM, `malfind` shellcode analysis | [PDF](01-memory-forensics-dvwa/report/Test1_DnyaneshwariKale.pdf) |
| 2 | Silent Breach | Disk, browser, mail and malware analysis | FTK Imager, SQLite history, string analysis, CyberChef, decryption | [PDF](02-silent-breach/report/Test_2_Silent_Breach_DnyaneshwariKale.pdf) |
| 3 | Spotted in the Wild | Disk triage (KAPE) and attack-chain reconstruction | CVE-2023-38831, PowerShell deobfuscation, persistence, anti-forensics | [PDF](03-spotted-in-the-wild/report/Test3_Spotted_in_the_Wild.pdf) |

---

## Case 1: Memory Forensics of a Compromised XAMPP/DVWA Host

**Evidence:** 1 GB Windows memory image (Vista SP1 / Server 2008 SP1 x86), captured 2015-09-03 10:04:05 UTC
**Tools:** Volatility 2.6, PowerShell, YARA

**Summary:** An attacker at 192.168.56.102, on the same host-only network as the victim (192.168.56.101), attacked the DVWA web application using Local File Inclusion, then manual and SQLMap-based SQL injection. A PHP web shell (`c99.php`) was placed in the DVWA web root. The attacker then gained command-line access as Administrator, created two local accounts (`user1`, `hacker`), added `user1` to Remote Desktop Users, and enabled RDP through the Windows Firewall. Obfuscated x86 shellcode was found injected into `svchost.exe` (two processes), `explorer.exe` and `xampp-control.exe`.

**Highlights**
- Recovered Apache access and error logs from memory with `dumpfiles`
- Recovered attacker console history with `cmdscan` and confirmed both accounts with `hashdump`
- Identified injected regions with `malfind` (MOV/JMP jump-table obfuscation stub)
- Kept confirmed findings separate from open items (`ad_driver.sys`, `install.exe`, shellcode framework attribution, access channel used at account creation)

---

## Case 2: Silent Breach

**Evidence:** AD1 logical image, Chrome and Edge history databases, Windows Mail store (`HxStore.hxd`), malware binary
**Tools:** FTK Imager, DB Browser for SQLite, PowerShell, CyberChef
**Challenge:** CyberDefenders Blue Team CTF, "Silent Breach" ([CyberDefenders challenges](https://cyberdefenders.org/blueteam-ctf-challenges/))

**Summary:** User `ethan` on host `ethanPC` downloaded and ran `IMF-Info.pdf.exe`, a Node.js application packaged with `pkg` and disguised as a PDF. It wrote an obfuscated PowerShell script that encrypted two Desktop PDFs with AES-256-CBC (PBKDF2 key derivation) and deleted the originals, which is ransomware-style behavior. The full chain was reconstructed statically, without executing the binary.

**Highlights**
- Download URL recovered from the `Zone.Identifier` alternate data stream
- Delivery application (Microsoft Edge) identified from SQLite download chains
- At-risk IPs recovered from the Windows Mail store with a regex sweep
- Payload deobfuscated in CyberChef (Reverse, then From Base64); the encryption routine was re-implemented in reverse to decrypt the files

| Indicator | Value |
|-----------|-------|
| MD5 (dropper) | `336A7CF476EBC7548C93507339196ABB` |
| Download URL | `http://192.168.16.128:8000/IMF-Info.pdf.exe` |
| Related IPs | `145.67.29.88`, `192.168.16.128`, `212.33.10.112` |

---

## Case 3: Spotted in the Wild (FinTrust Bank Breach)

**Evidence:** `c125-SpottedInTheWild.vhd` (KAPE triage collected 2024-02-03)
**Tools:** FTK Imager, VirusTotal, PowerShell, CyberChef
**Challenge:** [CyberDefenders: Spotted in the Wild](https://cyberdefenders.org/blueteam-ctf-challenges/spottedinthewild)

**Summary:** A malicious RAR archive (`SANS SEC401.rar`) was delivered via Telegram Desktop and exploited **CVE-2023-38831** (a WinRAR spoofed-extension flaw) to run the double-extension script `SANS SEC401.pdf.cmd`. An obfuscated PowerShell dropper fetched a second-stage payload disguised as a JPEG, decoded it with `certutil`, tampered with Windows event logs, created a scheduled task for persistence, and staged internal network scan results locally.

**Attack chain (UTC, 2024-02-03)**

| Time | Event |
|------|-------|
| 07:33:20 | `SANS SEC401.rar` downloaded via Telegram Desktop |
| ~07:35 | Stage-2 payload fetched from `http://172.18.35.10:8000/amanwhogetsnorest.jpg` |
| ~07:36 | `certutil -decode` produced `normal.zip`, dropping `z.ps1` |
| 07:38:01 | `Eventlogs.ps1` run (event log tampering) |
| ~07:38+ | Scheduled task `whoisthebaba` created (every 3 minutes, `/RL HIGHEST`) |
| ~07:38+ | Subnet scan results written to `BL4356.txt` |
| ~07:39+ | Attacker tooling deleted (cleanup incomplete) |

---

## MITRE ATT&CK Coverage

Techniques for Cases 2 and 3 come from the mappings in their reports. Case 1's report does not include a mapping, so the Case 1 rows below are mapped from its findings.

| Case | Tactic | Techniques |
|------|--------|-----------|
| 1 | Initial Access / Persistence / Lateral Movement | T1190 (exploit public-facing app), T1505.003 (web shell), T1136.001 (local account), T1021.001 (RDP) |
| 1 | Defense Evasion | T1055 (process injection), T1562.004 (firewall modification) |
| 2 | Initial Access / Execution | T1189, T1059.001 (PowerShell) |
| 2 | Defense Evasion | T1036.008 (masquerading), T1140 (deobfuscate/decode) |
| 2 | Collection / Impact | T1005, T1486 (data encrypted for impact) |
| 3 | Initial Access / Execution | T1566.001, T1204.002, T1203, T1059.001 |
| 3 | Defense Evasion | T1027, T1070.001 (clear event logs), T1070.004 (file deletion) |
| 3 | Persistence | T1053.005 (scheduled task) |
| 3 | Discovery / Collection | T1046, T1018, T1074.001 |

---

## Tools and Skills Demonstrated

- **Memory forensics:** Volatility 2.6 (`pslist`, `pstree`, `psscan`, `cmdscan`, `filescan`, `malfind`, `hashdump`, `dumpfiles`)
- **Disk forensics:** FTK Imager, NTFS metadata (MAC times), alternate data streams, file slack, KAPE triage data
- **Artifact analysis:** browser history (SQLite), Windows Mail store, scheduled tasks, command history
- **Malware triage:** static string analysis, `pkg`-packed Node.js binary, VirusTotal enrichment
- **Deobfuscation:** CyberChef and PowerShell (reversed, Base64-encoded payloads)
- **Reporting:** timeline reconstruction, IOC extraction, ATT&CK mapping, explicit documentation of evidence gaps

---

## Repository Structure

```
DFIR-Capstone-Investigations/
├── README.md
├── .gitignore
├── 01-memory-forensics-dvwa/
│   └── report/Test1_DnyaneshwariKale.pdf
├── 02-silent-breach/
│   └── report/Test_2_Silent_Breach_DnyaneshwariKale.pdf
└── 03-spotted-in-the-wild/
    └── report/Test3_Spotted_in_the_Wild.pdf
```

## What Is Not Included

Raw evidence images, memory dumps, live malware samples, web shells and challenge-provider files are intentionally not included. They are large, not mine to redistribute, and some are unsafe to host. Hashes and IOCs are given in the reports instead.

## Disclaimer

All investigations were performed on training and CTF datasets in an isolated lab context, for educational purposes only. No malicious binary was executed during analysis.

## Contact

- GitHub: https://github.com/Dnyaneshwari-123
- LinkedIn:https://www.linkedin.com/in/dnyaneshwari-kale-910939290/
