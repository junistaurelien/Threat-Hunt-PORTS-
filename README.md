# Threat-Hunt-Lab (PORTS)
<p align="center">
  <img src="Ports1.png" alt="Port of Entry - Threat Hunt" width="700" height="420">
</p>


# Threat Hunt / Incident Report (Lab): Port of Entry (RDP) Compromise 
 By Junist Aurelien 1.19.26

> **Objective:** Investigate and document a suspected intrusion that began with **inbound RDP** and progressed through staging, defense evasion, persistence, C2, credential access, collection/exfiltration, and lateral movement.

---

## Executive Summary 

During a threat hunt for unauthorized remote access, telemetry from **Microsoft Defender for Endpoint (MDE)** identified an inbound **Remote Desktop Protocol (RDP)** connection to **AZUKI-SL** from external source IP **88.97.178.12**. The attacker used the compromised account **kenji.sato** to stage tooling in **`C:\ProgramData\WindowsCache`** (hidden using `attrib`), weakened defenses by adding Windows Defender exclusion extensions (**.bat, .ps1, .exe**) and excluding a Temp path, downloaded payloads using **`certutil.exe`**, and established outbound command-and-control to **78.141.196.6** (primarily **TCP/8080**).  

Credential dumping activity (**mm.exe** with **`sekurlsa::logonpasswords`**) was followed by local archiving (**export-data.zip**) and outbound connectivity to **Discord (discord.com)** consistent with data exfiltration. The attacker created a backdoor local account (**support**), attempted lateral movement to **10.1.0.188** using **`mstsc.exe`** (preceded by `cmdkey` credential staging), and cleared Windows event logs via **`wevtutil`** (first log cleared: **Security**) to hinder investigation.

---

## Environment / Data Sources

- **Platform:** Windows endpoint (Lab)  
- **Endpoint:** `AZUKI-SL`  
- **Primary Telemetry:** Microsoft Defender for Endpoint Advanced Hunting
- **Investigation Window (UTC):** **2025-11-19 → 2025-11-21**

---

## Scope Statement

This report is limited to activity directly associated with the **port-of-entry compromise** on **AZUKI-SL** during the investigation window. Only evidence relevant to:
- Initial Access
- Execution
- Persistence
- Defense Evasion
- Command & Control
- Credential Access
- Collection / Exfiltration
- Lateral Movement  
…is included.

---

## Key Findings

- Initial access occurred via **inbound RDP** from **88.97.178.12** to **AZUKI-SL**
- Tooling staged and hidden in **`C:\ProgramData\WindowsCache`**
- Defender exclusions were modified (extensions + Temp folder path)
- **`certutil.exe`** used to download files (LOLBIN abuse)
- Persistence via scheduled task **Windows Update Check** executing **`C:\ProgramData\WindowsCache\svchost.exe`**
- C2 communications observed to **78.141.196.6** (primarily **TCP/8080**)
- Credential dumping: **mm.exe** + **`sekurlsa::logonpasswords`**
- Archive created: **export-data.zip**
- Exfil indicators: **discord.com**
- Backdoor account created: **support**
- Lateral movement attempt to **10.1.0.188** using **mstsc.exe**
- Log clearing: **wevtutil** (first cleared: **Security**)

---

## Chronological Timeline (UTC)

> Use this section as your story-line when presenting the incident in interviews.

1. **Initial Access:** Inbound **RDP** to `AZUKI-SL` from **88.97.178.12** using **kenji.sato**
2. **Discovery:** Network neighbor enumeration via **`arp -a`**
3. **Staging:** Payloads/tools staged in **`C:\ProgramData\WindowsCache`**, hidden via `attrib`
4. **Defense Evasion:** Defender exclusions added (extensions) and Temp folder excluded
5. **Execution / Download:** **`certutil.exe`** used to retrieve payloads
6. **Persistence:** Scheduled task **Windows Update Check** created to run **`C:\ProgramData\WindowsCache\svchost.exe`**
7. **Command & Control:** Outbound connections to **78.141.196.6** (primarily **TCP/8080**)
8. **Credential Access:** **mm.exe** executed; module **`sekurlsa::logonpasswords`** used
9. **Collection & Packaging:** Data archived as **export-data.zip**
10. **Exfiltration:** Outbound connectivity to **discord.com**
11. **Account Manipulation:** Backdoor account **support** created
12. **Lateral Movement Attempt:** Target **10.1.0.188** via **mstsc.exe** (credential staging observed)
13. **Defense Evasion / Cleanup:** Event logs cleared with **wevtutil** (first: **Security**)

---

## Flag Confirmation (20 Required Answers)

| # | Flag Question | Confirmed Answer |
|---:|---|---|
| 1 | Source IP of RDP connection | **88.97.178.12** |
| 2 | Compromised user account | **kenji.sato** |
| 3 | Command + argument to enumerate neighbors | **arp -a** |
| 4 | Primary staging directory | **C:\ProgramData\WindowsCache** |
| 5 | # of excluded Defender extensions | **3** |
| 6 | Temp folder path excluded | **C:\Users\KENJI~1.SAT\AppData\Local\Temp** |
| 7 | Windows-native binary used to download files | **certutil.exe** |
| 8 | Scheduled task name for persistence | **Windows Update Check** |
| 9 | Executable path configured in task | **C:\ProgramData\WindowsCache\svchost.exe** |
| 10 | C2 server IP | **78.141.196.6** |
| 11 | Destination port for C2 | **8080** *(primary observed)* |
| 12 | Credential dumping tool filename | **mm.exe** |
| 13 | Module used to extract logon passwords | **sekurlsa::logonpasswords** |
| 14 | Archive used for exfiltration | **export-data.zip** |
| 15 | Cloud service used to exfiltrate | **discord.com (Discord)** |
| 16 | First event log cleared | **Security** |
| 17 | Backdoor account username | **support** |
| 18 | PowerShell automation script | **C:\Users\kenji.sato\AppData\Local\Temp\wupdate.ps1** |
| 19 | IP targeted for lateral movement | **10.1.0.188** |
| 20 | Remote access tool used for lateral movement | **mstsc.exe** |

---

## MITRE ATT&CK Mapping (High-Level)

- **Initial Access:** Remote Services (RDP)
- **Discovery:** Network discovery (`arp -a`)
- **Defense Evasion:** Defender exclusions, log clearing (`wevtutil`)
- **Execution:** PowerShell, LOLBIN download (`certutil.exe`)
- **Persistence:** Scheduled task
- **Command & Control:** External IP communications (78.141.196.6:8080)
- **Credential Access:** Credential dumping (Mimikatz-like behavior)
- **Collection/Exfiltration:** Archive + cloud exfil (Discord)
- **Lateral Movement:** Remote Desktop (`mstsc.exe`) toward internal host

---

## Response Actions (Lab)

- Validated inbound RDP and associated user context
- Confirmed staging directory and persistence mechanism
- Documented IOCs: IPs, filenames, task, accounts, script path
- Recommended containment actions (below)

---

## Recommendations (Prevent / Detect)

1. Restrict or disable internet-exposed **RDP**; enforce **VPN + MFA** and Conditional Access  
2. Enable and monitor Defender **Tamper Protection**; alert on Defender exclusion changes  
3. Alert on download-capable LOLBins: `certutil`, `bitsadmin`, `powershell iwr`, etc.  
4. Monitor scheduled task creation, especially tasks executing from `ProgramData` or Temp  
5. Alert on credential dumping patterns (LSASS access, suspicious strings like `sekurlsa`)  
6. Apply egress filtering; alert/block exfil destinations like **discord.com** if non-business use  
7. Alert immediately on **event log clearing** (e.g., `wevtutil cl`)  

---
## *Validation Statement**

**This incident investigation was conducted and validated by me, Junist Aurelien.**  
**Validation Date:** **01-19-2026**

## Appendix — Key Hunting Queries (Condensed)

### 1) RDP Source IP (Inbound /3389)
```kql
DeviceNetworkEvents
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-21))
| where DeviceName =~ "azuki-sl"
| where LocalPort == 3389
| where ActionType == "InboundConnectionAccepted"
| summarize Hits=count(), FirstSeen=min(Timestamp), LastSeen=max(Timestamp) by RemoteIP
| order by Hits desc

2) Defender Exclusion Extensions (Registry)

DeviceRegistryEvents
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-21))
| where DeviceName == "azuki-sl"
| where RegistryKey has @"Windows Defender\Exclusions\Extensions"
| where ActionType in ("RegistryValueSet","RegistryValueCreated","RegistryValueModified")
| project TimeGenerated, RegistryKey, RegistryValueName, InitiatingProcessAccountName, InitiatingProcessCommandLine
| order by TimeGenerated asc

3) Scheduled Task Persistence (schtasks)

DeviceProcessEvents
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-21))
| where DeviceName =~ "azuki-sl"
| where FileName =~ "schtasks.exe" and ProcessCommandLine has "/create"
| project Timestamp, AccountName, ProcessCommandLine
| order by Timestamp asc

4) C2 Connections (from staging directory)
DeviceNetworkEvents
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-21))
| where DeviceName =~ "azuki-sl"
| where ActionType == "ConnectionSuccess"
| where InitiatingProcessFolderPath =~ @"C:\ProgramData\WindowsCache"
| summarize Connections=count(), FirstSeen=min(Timestamp), LastSeen=max(Timestamp) by RemoteIP, RemotePort
| order by Connections desc

---



---

