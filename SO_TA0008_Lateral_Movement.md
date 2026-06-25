# TA0008 — Lateral Movement

> Query dialect: Elastic Kibana Query Language (**Elastic KQL**) using ECS-style fields. These are hunting-grade filters intended for Kibana Discover, Timeline, and Elastic Security rules. Tune fields, data views, and allowlists to your environment.

**Coverage count:** 6 technique sections / 29 KQL queries

## Techniques in this tactic

- [T1021.002 — Remote Services: SMB / Windows Admin Shares](SO_TA0008_Lateral_Movement.md#t1021.002-remote-services-smb-windows-admin-shares) — 5 queries
- [T1021.006 — Remote Services: Windows Remote Management](SO_TA0008_Lateral_Movement.md#t1021.006-remote-services-windows-remote-management) — 3 queries
- [T1021.001 — Remote Services: Remote Desktop Protocol](SO_TA0008_Lateral_Movement.md#t1021.001-remote-services-remote-desktop-protocol) — 5 queries
- [T1021.003 — Remote Services: Distributed Component Object Model](SO_TA0008_Lateral_Movement.md#t1021.003-remote-services-distributed-component-object-model) — 2 queries
- [T1021.004 — Remote Services: SSH](SO_TA0008_Lateral_Movement.md#t1021.004-remote-services-ssh) — 8 queries
- [T1570 — Lateral Tool Transfer](SO_TA0008_Lateral_Movement.md#t1570-lateral-tool-transfer) — 6 queries

---

## T1021.002 — Remote Services: SMB / Windows Admin Shares

**Tactic:** Lateral Movement  
**Detection idea:** Admin share access and remote copy over SMB  
**Elastic implementation notes:** ECS field names vary by integration. Start with the KQL below, then tune for your Elastic Agent, Elastic Defend, Windows, System, Sysmon, cloud, and email data streams.

### Query 1
```kql
event.category:network and destination.port:445 and process.name:("cmd.exe" or "powershell.exe" or "robocopy.exe" or "xcopy.exe" or "net.exe")
```

### Query 2
```kql
event.category:process and process.command_line:(*\\\\\\\\*\\\\ADMIN$* or *\\\\\\\\*\\\\C$* or *\\\\\\\\*\\\\IPC$* or *psexec* or *copy\ \\\\\\\\*)
```

**Tuning ideas:** allowlist known admin scripts, software deployment tools, scanners, EDR activity, patch management, and sanctioned cloud apps before alerting.

---

### Query 3 — Security Onion
**Security Onion specific:** Uses Security Onion Zeek connection metadata for SMB/admin-share lateral movement opportunities.

```kql
event.dataset:conn and destination.port:445 and source.ip:* and destination.ip:*
```

**Security Onion Hunt dashboard (OQL):** Uses Security Onion 3.1 Hunt syntax. The filter uses Lucene/OQL boolean operators and adds Hunt-friendly grouping, sorting, and event-table columns.

```oql
event.dataset:conn AND destination.port:445 AND source.ip:* AND destination.ip:* | groupby event.dataset source.ip destination.ip destination.port rule.name | sortby @timestamp | table @timestamp event.module event.dataset source.ip source.port destination.ip destination.port network.transport network.community_id log.id.uid rule.name host.name user.name event.code event.action
```

### Query 4 — Security Onion
**Security Onion specific:** Uses Security Onion Suricata alert data for SMB exploitation or suspicious SMB activity.

```kql
event.module:"Suricata" and event.dataset:"alert" and rule.name:(*SMB* or *ETERNALBLUE* or *ADMIN$* or *IPC$*) and source.ip:* and destination.ip:*
```

**Security Onion Hunt dashboard (OQL):** Uses Security Onion 3.1 Hunt syntax. The filter uses Lucene/OQL boolean operators and adds Hunt-friendly grouping, sorting, and event-table columns.

```oql
event.module:"Suricata" AND event.dataset:"alert" AND rule.name:(*SMB* OR *ETERNALBLUE* OR *ADMIN$* OR *IPC$*) AND source.ip:* AND destination.ip:* | groupby event.dataset source.ip destination.ip destination.port rule.name | sortby @timestamp | table @timestamp event.module event.dataset source.ip source.port destination.ip destination.port network.transport network.community_id log.id.uid rule.name host.name user.name event.code event.action
```
### Query 5 — Security Onion Windows Elastic Agent
**Security Onion specific:** Uses Elastic Agent telemetry in Security Onion 3.1.0 for Windows hosts. Requires Elastic Agent endpoint, system, Windows, macOS, Linux, or Elastic Defend data streams with ECS host, process, file, registry, authentication, or network fields.

```kql
event.category:process and agent.type:"elastic-agent" and host.os.type:windows and process.name:("cmd.exe" or "powershell.exe" or "xcopy.exe" or "robocopy.exe") and process.command_line:(*\\\\*\\ADMIN$* or *\\\\*\\C$* or *\\\\*\\IPC$* or *psexec*)
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:process AND agent.type:"elastic-agent" AND host.os.type:windows AND process.name:("cmd.exe" OR "powershell.exe" OR "xcopy.exe" OR "robocopy.exe") AND process.command_line:(*\\\\*\\ADMIN$* OR *\\\\*\\C$* OR *\\\\*\\IPC$* OR *psexec*) | groupby host.name host.os.type user.name process.name process.parent.name destination.ip destination.port event.action | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port network.transport network.community_id event.code rule.name
```

## T1021.006 — Remote Services: Windows Remote Management

**Tactic:** Lateral Movement  
**Detection idea:** WinRM and PowerShell remoting activity  
**Elastic implementation notes:** ECS field names vary by integration. Start with the KQL below, then tune for your Elastic Agent, Elastic Defend, Windows, System, Sysmon, cloud, and email data streams.

### Query 1
```kql
event.category:process and process.command_line:(*Enter-PSSession* or *Invoke-Command* or *New-PSSession* or *winrs* or *Enable-PSRemoting*)
```

### Query 2
```kql
event.category:network and destination.port:(5985 or 5986) and process.name:("powershell.exe" or "pwsh.exe" or "wsmprovhost.exe" or "winrs.exe")
```

### Query 3 — Security Onion Windows Elastic Agent
**Security Onion specific:** Uses Elastic Agent telemetry in Security Onion 3.1.0 for Windows hosts. Requires Elastic Agent endpoint, system, Windows, macOS, Linux, or Elastic Defend data streams with ECS host, process, file, registry, authentication, or network fields.

```kql
event.category:process and agent.type:"elastic-agent" and host.os.type:windows and process.name:("powershell.exe" or "pwsh.exe" or "winrs.exe") and process.command_line:(*Enter-PSSession* or *Invoke-Command* or *-ComputerName* or *New-PSSession* or *winrm*)
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:process AND agent.type:"elastic-agent" AND host.os.type:windows AND process.name:("powershell.exe" OR "pwsh.exe" OR "winrs.exe") AND process.command_line:(*Enter\-PSSession* OR *Invoke\-Command* OR *\-ComputerName* OR *New\-PSSession* OR *winrm*) | groupby host.name host.os.type user.name process.name process.parent.name destination.ip destination.port event.action | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port network.transport network.community_id event.code rule.name
```

**Tuning ideas:** allowlist known admin scripts, software deployment tools, scanners, EDR activity, patch management, and sanctioned cloud apps before alerting.

---

## T1021.001 — Remote Services: Remote Desktop Protocol

**Tactic:** Lateral Movement  
**Detection idea:** RDP network connections or successful remote interactive logons  
**Elastic implementation notes:** ECS field names vary by integration. Start with the KQL below, then tune for your Elastic Agent, Elastic Defend, Windows, System, Sysmon, cloud, and email data streams.

### Query 1
```kql
event.category:network and destination.port:3389 and source.ip:* and destination.ip:*
```

### Query 2
```kql
event.dataset:"windows.security" and event.code:4624 and winlog.event_data.LogonType:(10 or 7) and source.ip:*
```

**Tuning ideas:** allowlist known admin scripts, software deployment tools, scanners, EDR activity, patch management, and sanctioned cloud apps before alerting.

---

### Query 3 — Security Onion
**Security Onion specific:** Uses Security Onion Zeek connection metadata for RDP flows between monitored hosts.

```kql
event.dataset:conn and destination.port:3389 and source.ip:* and destination.ip:*
```

**Security Onion Hunt dashboard (OQL):** Uses Security Onion 3.1 Hunt syntax. The filter uses Lucene/OQL boolean operators and adds Hunt-friendly grouping, sorting, and event-table columns.

```oql
event.dataset:conn AND destination.port:3389 AND source.ip:* AND destination.ip:* | groupby event.dataset source.ip destination.ip destination.port rule.name | sortby @timestamp | table @timestamp event.module event.dataset source.ip source.port destination.ip destination.port network.transport network.community_id log.id.uid rule.name host.name user.name event.code event.action
```

### Query 4 — Security Onion
**Security Onion specific:** Uses Security Onion Suricata alert data for RDP brute force, exploit, or policy signatures.

```kql
event.module:"Suricata" and event.dataset:"alert" and rule.name:(*RDP* or *Remote\ Desktop*) and source.ip:* and destination.ip:*
```

**Security Onion Hunt dashboard (OQL):** Uses Security Onion 3.1 Hunt syntax. The filter uses Lucene/OQL boolean operators and adds Hunt-friendly grouping, sorting, and event-table columns.

```oql
event.module:"Suricata" AND event.dataset:"alert" AND rule.name:(*RDP* OR *Remote\ Desktop*) AND source.ip:* AND destination.ip:* | groupby event.dataset source.ip destination.ip destination.port rule.name | sortby @timestamp | table @timestamp event.module event.dataset source.ip source.port destination.ip destination.port network.transport network.community_id log.id.uid rule.name host.name user.name event.code event.action
```
### Query 5 — Security Onion Windows Elastic Agent
**Security Onion specific:** Uses Elastic Agent telemetry in Security Onion 3.1.0 for Windows hosts. Requires Elastic Agent endpoint, system, Windows, macOS, Linux, or Elastic Defend data streams with ECS host, process, file, registry, authentication, or network fields.

```kql
event.category:(process or network) and agent.type:"elastic-agent" and host.os.type:windows and (process.name:"mstsc.exe" or destination.port:3389) and destination.ip:*
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:(process OR network) AND agent.type:"elastic-agent" AND host.os.type:windows AND (process.name:"mstsc.exe" OR destination.port:3389) AND destination.ip:* | groupby host.name host.os.type user.name process.name process.parent.name destination.ip destination.port event.action | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line process.executable file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port destination.domain network.transport event.code rule.name
```

## T1021.003 — Remote Services: Distributed Component Object Model

**Tactic:** Lateral Movement  
**Detection idea:** DCOM lateral movement commands and remote COM execution  
**Elastic implementation notes:** ECS field names vary by integration. Start with the KQL below, then tune for your Elastic Agent, Elastic Defend, Windows, System, Sysmon, cloud, and email data streams.

### Query 1
```kql
event.category:process and process.command_line:(*MMC20.Application* or *ShellWindows* or *ShellBrowserWindow* or *Excel.Application* or *-ComputerName*)
```

### Query 2
```kql
event.category:process and process.name:("powershell.exe" or "pwsh.exe" or "wmic.exe") and process.command_line:(*New-Object\ -ComObject* or *activator*CreateInstance* or *GetTypeFromProgID*)
```

**Tuning ideas:** allowlist known admin scripts, software deployment tools, scanners, EDR activity, patch management, and sanctioned cloud apps before alerting.

---

## T1021.004 — Remote Services: SSH

**Tactic:** Lateral Movement  
**Detection idea:** SSH connections or SSH client use from managed hosts  
**Elastic implementation notes:** ECS field names vary by integration. Start with the KQL below, then tune for your Elastic Agent, Elastic Defend, Windows, System, Sysmon, cloud, and email data streams.

### Query 1
```kql
event.category:network and destination.port:22 and source.ip:* and destination.ip:*
```

### Query 2
```kql
event.category:process and process.name:("ssh.exe" or "scp.exe" or "sftp.exe" or "plink.exe" or "putty.exe") and process.command_line:*
```

**Tuning ideas:** allowlist known admin scripts, software deployment tools, scanners, EDR activity, patch management, and sanctioned cloud apps before alerting.

---

### Query 3 — Security Onion
**Security Onion specific:** Uses Security Onion Zeek connection metadata for SSH lateral movement.

```kql
event.dataset:conn and destination.port:22 and source.ip:* and destination.ip:*
```

**Security Onion Hunt dashboard (OQL):** Uses Security Onion 3.1 Hunt syntax. The filter uses Lucene/OQL boolean operators and adds Hunt-friendly grouping, sorting, and event-table columns.

```oql
event.dataset:conn AND destination.port:22 AND source.ip:* AND destination.ip:* | groupby event.dataset source.ip destination.ip destination.port rule.name | sortby @timestamp | table @timestamp event.module event.dataset source.ip source.port destination.ip destination.port network.transport network.community_id log.id.uid rule.name host.name user.name event.code event.action
```

### Query 4 — Security Onion
**Security Onion specific:** Uses Security Onion Suricata alert data for SSH brute force or anomalous SSH signatures.

```kql
event.module:"Suricata" and event.dataset:"alert" and rule.name:(*SSH* or *OpenSSH* or *Brute\ Force*) and source.ip:* and destination.ip:*
```

**Security Onion Hunt dashboard (OQL):** Uses Security Onion 3.1 Hunt syntax. The filter uses Lucene/OQL boolean operators and adds Hunt-friendly grouping, sorting, and event-table columns.

```oql
event.module:"Suricata" AND event.dataset:"alert" AND rule.name:(*SSH* OR *OpenSSH* OR *Brute\ Force*) AND source.ip:* AND destination.ip:* | groupby event.dataset source.ip destination.ip destination.port rule.name | sortby @timestamp | table @timestamp event.module event.dataset source.ip source.port destination.ip destination.port network.transport network.community_id log.id.uid rule.name host.name user.name event.code event.action
```
### Query 5 — Security Onion Linux/macOS Elastic Agent
**Security Onion specific:** Uses Elastic Agent telemetry in Security Onion 3.1.0 for Linux/macOS hosts. Requires Elastic Agent endpoint, system, or Elastic Defend data streams with ECS host, process, file, or network fields.

```kql
event.category:network and agent.type:"elastic-agent" and host.os.type:(linux or macos) and process.name:(ssh or scp or sftp or rsync) and destination.port:22 and destination.ip:*
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:network AND agent.type:"elastic-agent" AND host.os.type:(linux OR macos) AND process.name:(ssh OR scp OR sftp OR rsync) AND destination.port:22 AND destination.ip:* | groupby host.name host.os.type user.name process.name source.ip destination.ip destination.port | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line file.path file.name file.extension source.ip source.port destination.ip destination.port network.transport network.community_id rule.name
```
### Query 6 — Security Onion Linux Elastic Agent
**Security Onion specific:** Uses Elastic Agent telemetry in Security Onion 3.1.0 for Linux hosts. Requires Elastic Agent endpoint, system, Windows, macOS, Linux, or Elastic Defend data streams with ECS host, process, file, registry, authentication, or network fields.

```kql
event.category:process and agent.type:"elastic-agent" and host.os.type:linux and process.name:ssh and process.command_line:(*\ -i\ * or *\ -L\ * or *\ -R\ * or *\ -D\ * or *ProxyCommand*)
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:process AND agent.type:"elastic-agent" AND host.os.type:linux AND process.name:ssh AND process.command_line:(*\ \-i\ * OR *\ \-L\ * OR *\ \-R\ * OR *\ \-D\ * OR *ProxyCommand*) | groupby host.name host.os.type user.name process.name process.parent.name destination.ip destination.port event.action | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port network.transport network.community_id event.code rule.name
```
### Query 7 — Security Onion macOS Elastic Agent
**Security Onion specific:** Uses Elastic Agent telemetry in Security Onion 3.1.0 for macOS hosts. Requires Elastic Agent endpoint, system, Windows, macOS, Linux, or Elastic Defend data streams with ECS host, process, file, registry, authentication, or network fields.

```kql
event.category:process and agent.type:"elastic-agent" and host.os.type:macos and process.name:(ssh or scp or sftp or rsync) and process.command_line:(*\ -i\ * or *\ -L\ * or *\ -R\ * or *\ -D\ * or */Users/*)
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:process AND agent.type:"elastic-agent" AND host.os.type:macos AND process.name:(ssh OR scp OR sftp OR rsync) AND process.command_line:(*\ \-i\ * OR *\ \-L\ * OR *\ \-R\ * OR *\ \-D\ * OR *\/Users\/*) | groupby host.name host.os.type user.name process.name process.parent.name destination.ip destination.port event.action | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port network.transport network.community_id event.code rule.name
```
### Query 8 — Security Onion Linux Elastic Agent
**Security Onion specific:** Uses Elastic Agent telemetry in Security Onion 3.1.0 for Linux hosts. Requires Elastic Agent endpoint, system, Windows, macOS, Linux, or Elastic Defend data streams with ECS host, process, file, registry, authentication, or network fields.

```kql
event.category:network and agent.type:"elastic-agent" and host.os.type:linux and process.name:ssh and destination.port:22 and destination.ip:*
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:network AND agent.type:"elastic-agent" AND host.os.type:linux AND process.name:ssh AND destination.port:22 AND destination.ip:* | groupby host.name host.os.type user.name process.name process.parent.name destination.ip destination.port event.action | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line process.executable file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port destination.domain network.transport event.code rule.name
```

## T1570 — Lateral Tool Transfer

**Tactic:** Lateral Movement  
**Detection idea:** Copying tools to remote administrative shares or remote hosts  
**Elastic implementation notes:** ECS field names vary by integration. Start with the KQL below, then tune for your Elastic Agent, Elastic Defend, Windows, System, Sysmon, cloud, and email data streams.

### Query 1
```kql
event.category:process and process.name:("xcopy.exe" or "robocopy.exe" or "powershell.exe" or "cmd.exe") and process.command_line:(*\\\\*\\ADMIN$* or *\\\\*\\C$* or *Copy-Item* or *robocopy* or *copy\ \\\\*)
```

### Query 2
```kql
event.category:file and event.action:creation and file.path:(*\\\\ADMIN$\\\\* or *\\\\C$\\\\* or *\\\\Users\\\\Public\\\\*) and file.extension:(exe or dll or ps1 or bat or vbs)
```

**Tuning ideas:** allowlist known admin scripts, software deployment tools, scanners, EDR activity, patch management, and sanctioned cloud apps before alerting.

---

### Query 3 — Security Onion
**Security Onion specific:** Uses Security Onion Zeek file metadata for executable/script transfer over network protocols.

```kql
event.dataset:files and file.extension:(exe or dll or ps1 or bat or vbs or js or jar) and source.ip:* and destination.ip:*
```

**Security Onion Hunt dashboard (OQL):** Uses Security Onion 3.1 Hunt syntax. The filter uses Lucene/OQL boolean operators and adds Hunt-friendly grouping, sorting, and event-table columns.

```oql
event.dataset:files AND file.extension:(exe OR dll OR ps1 OR bat OR vbs OR js OR jar) AND source.ip:* AND destination.ip:* | groupby event.dataset source.ip destination.ip destination.port rule.name | sortby @timestamp | table @timestamp event.module event.dataset source.ip source.port destination.ip destination.port network.transport network.community_id log.id.uid rule.name file.name file.path host.name user.name event.code event.action
```

### Query 4 — Security Onion
**Security Onion specific:** Uses Security Onion Suricata alert data for tool-transfer signatures.

```kql
event.module:"Suricata" and event.dataset:"alert" and rule.name:(*EXE\ Download* or *Executable\ Download* or *MALWARE* or *TOOL* or *PowerShell\ Download*)
```

**Security Onion Hunt dashboard (OQL):** Uses Security Onion 3.1 Hunt syntax. The filter uses Lucene/OQL boolean operators and adds Hunt-friendly grouping, sorting, and event-table columns.

```oql
event.module:"Suricata" AND event.dataset:"alert" AND rule.name:(*EXE\ Download* OR *Executable\ Download* OR *MALWARE* OR *TOOL* OR *PowerShell\ Download*) | groupby event.dataset source.ip destination.ip destination.port rule.name | sortby @timestamp | table @timestamp event.module event.dataset source.ip source.port destination.ip destination.port network.transport network.community_id log.id.uid rule.name host.name user.name event.code event.action
```
### Query 5 — Security Onion Linux Elastic Agent
**Security Onion specific:** Uses Elastic Agent telemetry in Security Onion 3.1.0 for Linux hosts. Requires Elastic Agent endpoint, system, Windows, macOS, Linux, or Elastic Defend data streams with ECS host, process, file, registry, authentication, or network fields.

```kql
event.category:process and agent.type:"elastic-agent" and host.os.type:linux and process.name:(scp or sftp or rsync or curl or wget) and process.command_line:(*.sh* or *.py* or *.elf* or */tmp/* or */dev/shm/*)
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:process AND agent.type:"elastic-agent" AND host.os.type:linux AND process.name:(scp OR sftp OR rsync OR curl OR wget) AND process.command_line:(*.sh* OR *.py* OR *.elf* OR *\/tmp\/* OR *\/dev\/shm\/*) | groupby host.name host.os.type user.name process.name process.parent.name destination.ip destination.port event.action | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line process.executable file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port destination.domain network.transport event.code rule.name
```
### Query 6 — Security Onion macOS Elastic Agent
**Security Onion specific:** Uses Elastic Agent telemetry in Security Onion 3.1.0 for macOS hosts. Requires Elastic Agent endpoint, system, Windows, macOS, Linux, or Elastic Defend data streams with ECS host, process, file, registry, authentication, or network fields.

```kql
event.category:process and agent.type:"elastic-agent" and host.os.type:macos and process.name:(scp or sftp or rsync or curl) and process.command_line:(*.sh* or *.py* or *.zip* or */tmp/* or */Users/Shared/*)
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:process AND agent.type:"elastic-agent" AND host.os.type:macos AND process.name:(scp OR sftp OR rsync OR curl) AND process.command_line:(*.sh* OR *.py* OR *.zip* OR *\/tmp\/* OR *\/Users\/Shared\/*) | groupby host.name host.os.type user.name process.name process.parent.name destination.ip destination.port event.action | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line process.executable file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port destination.domain network.transport event.code rule.name
```
