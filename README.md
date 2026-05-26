# Windows Endpoint Monitoring & Threat Detection
### Splunk Enterprise + Sysmon | SOC Detection Lab

> **Built for:** Small businesses and IT teams that need endpoint threat visibility without enterprise EDR costs.

---

## What This Does

Production-style Windows endpoint monitoring using **Splunk Enterprise** and **Sysmon** — collects, parses, and alerts on suspicious activity with MITRE ATT&CK mapping.

**Detects:**
- Malicious PowerShell execution and script-based attacks
- Binary masquerading (renamed executables evading detection)
- Credential dumping via LSASS memory injection
- Unauthorized logins and brute force attempts
- Suspicious file drops in temp/startup directories

---

## Architecture

```
Windows Endpoint
      │
      ├── Sysmon Driver ──→ filters via sysmonconfig.xml
      └── Windows Event Log
            │
            ▼
     Splunk Universal Forwarder
            │  (secure log forwarding)
            ▼
     Splunk Indexer  →  index=endpoint
            │
            ▼
     Splunk Search Head
      ├── Detection Alerts
      └── SOC Dashboard
```

**Log sources collected:**
- `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational` — process, network, file, DNS
- `WinEventLog:Security` — logins, account changes, policy violations
- `WinEventLog:System` — services, drivers, system errors

---

## Detections Demonstrated

| Attack Technique | MITRE ID | Log Source & Event ID | Detection Query | Severity |
|---|---|---|---|---|
| PowerShell bypass execution | T1059.001 | Sysmon: EventCode=1 | `powershell.exe` + `-ExecutionPolicy Bypass` | High |
| Suspicious process spawn | T1055 | Sysmon: EventCode=1 | Unusual parent-child process pairs | High |
| Network connection to unknown host | T1071 | Sysmon: EventCode=3 | Outbound connection from non-browser process | Medium |
| File drop in temp directory | T1105 | Sysmon: EventCode=11 | File creation in `%TEMP%` or `%APPDATA%` | Medium |
| Failed login brute force | T1110 | Security: EventCode=4625 | 5+ failed logins within 60 seconds | High |
| Successful login after failures | T1078 | Security: EventCode=4624 | Login success following failure spike | Critical |

---

## Detection Queries

### 1 — Malicious PowerShell Execution (T1059.001)

Catches execution policy bypass flags including shortened versions attackers use to evade basic filters.

```spl
index=endpoint source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
(Image="*powershell.exe" OR OriginalFileName="PowerShell.EXE")
(CommandLine="*-ep*" OR CommandLine="*-ExecutionPolicy*" OR CommandLine="*-encodedcommand*" OR CommandLine="*-enc*" OR CommandLine="*-nop*")
| table _time host User ParentImage CommandLine
| rename ParentImage as "Parent Process", CommandLine as "Full Command"
```

**Result:** ✅ Detected — captured `-ExecutionPolicy Bypass` with full command line and parent process.

---

### 2 — Binary Masquerading (T1036.003)

Compares the running filename against the PE metadata `OriginalFileName` compiled by Microsoft. A mismatch means a binary was renamed to evade detection.

```spl
index=endpoint source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
| eval image_name=mvindex(split(Image, "\\"), -1)
| eval original_name=OriginalFileName
| where image_name != original_name AND NOT (original_name="-" OR original_name="null")
| table _time host User Image OriginalFileName CommandLine
```

**Result:** ✅ Detected — `cmd.exe` copied and renamed to `svchost.exe` flagged immediately.

---

### 3 — LSASS Memory Injection / Credential Dumping (T1055.001)

Catches tools like Mimikatz that inject threads into `lsass.exe` to extract credentials.

```spl
index=endpoint source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=8
TargetImage="*lsass.exe"
| stats count BY _time host SourceImage SourceProcessId TargetImage StartAddress
| rename SourceImage as "Injecting Process", TargetImage as "Target Process"
```

**Result:** ✅ Detected — remote thread injection into `lsass.exe` captured with source process ID.

---

### 4 — Suspicious File Drop in Temp/Startup (T1105)

```spl
index=endpoint source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=11
| search TargetFilename="*\\AppData\\Local\\Temp\\*"
       OR TargetFilename="*\\Startup\\*"
       OR TargetFilename="*\\Downloads\\*"
| where match(TargetFilename, "\.(exe|ps1|bat|vbs|dll)$")
| table _time host User TargetFilename Image
```
### 5 — Brute Force Login Detection (T1110)

Detects multiple failed login attempts from the same source
within a 60 second window — a clear sign of password attack.

```spl
index=endpoint source="WinEventLog:Security" EventCode=4625
| bucket _time span=60s
| stats count as FailedLogins by _time, Account_Name, IpAddress, ComputerName
| where FailedLogins >= 5
| sort - FailedLogins
| rename Account_Name as "Targeted Account", IpAddress as "Source IP"
```

**Result:** ✅ Alert fired — 8 failed login attempts from single
source detected within 60 second window. Account locked out
after threshold breach.

---

## Threat Simulation Results

Threats were simulated using the included `scripts/emulate_threats.ps1` script and verified in Splunk.

| Simulation | MITRE ID | EventCode Triggered | Detected |
|---|---|---|---|
| PowerShell `-ExecutionPolicy Bypass` | T1059.001 | 1 | ✅ Yes |
| `cmd.exe` renamed to `svchost.exe` | T1036.003 | 1 | ✅ Yes |
| Payload written to `%TEMP%` | T1105 | 11 | ✅ Yes |

---

## Files in This Repo

```
├── README.md
├── config/
│   ├── inputs.conf          ← Splunk log collection config
│   └── sysmonconfig.xml     ← Custom Sysmon noise-filtering rules
├── scripts/
│   └── emulate_threats.ps1  ← Safe threat simulation script
├── dashboards/
│   └── endpoint_visibility_dashboard.xml  ← Splunk dashboard XML
└── reports/
    └── incident-report.html ← Sample client incident report
```

---

## Configuration Files

### Splunk inputs.conf
See `config/inputs.conf` — routes Security and Sysmon logs to `index=endpoint`.

### Sysmon Config
See `config/sysmonconfig.xml` — tuned ruleset that excludes noisy background processes (WMI, Defender, SearchIndexer) while capturing high-risk binaries (PowerShell, cmd, mshta, certutil, bitsadmin).

---

## MITRE ATT&CK Coverage

| Tactic | Technique ID | Technique Name |
|---|---|---|
| Execution | T1059.001 | PowerShell |
| Execution | T1059.003 | Windows Command Shell |
| Defense Evasion | T1036.003 | Binary Masquerading |
| Credential Access | T1003.001 | LSASS Memory Dump |
| Credential Access | T1110 | Brute Force |
| Persistence | T1105 | Ingress Tool Transfer |
| C2 | T1071 | Application Layer Protocol |

---

## Freelance Services Offered

Available for freelance engagements in:

- Splunk + Sysmon deployment and configuration
- Windows endpoint security audit and log review
- Custom detection rule and alert development
- SOC runbook creation for your security team
- Ongoing monthly monitoring and threat reporting


---

## Technologies Used

| Tool | Purpose |
|---|---|
| Splunk Enterprise 9.x | SIEM — ingestion, search, alerting, dashboards |
| Sysmon v15 | Deep Windows endpoint telemetry |
| SPL | Detection query and dashboard logic |
| MITRE ATT&CK | Threat classification framework |
| PowerShell | Threat simulation scripting |

---

## Roadmap

## Roadmap

- [ ] Microsoft Sentinel cloud SIEM integration
- [ ] Active Directory attack detection (Kerberoasting, Pass-the-Hash)
- [ ] Sigma rule conversion for cross-platform SIEM deployment
- [ ] Wazuh agent integration for active endpoint response
- [ ] CI/CD pipeline for detection-as-code rule deployment
- [ ] Email alerting via Splunk notification actions
- [ ] Automated incident response playbooks

---

## Contact

**Swetha Nyamala** — Cybersecurity Freelancer | SOC Analyst | SIEM Engineer

- GitHub: [@swethanyamala](https://github.com/swethanyamala)
- Email: [swethanyamala2003@gmail.com]