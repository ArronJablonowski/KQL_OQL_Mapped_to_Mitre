# TA0040 — Impact

> Query dialect: Elastic Kibana Query Language (**Elastic KQL**) using ECS-style fields. These are hunting-grade filters intended for Kibana Discover, Timeline, and Elastic Security rules. Tune fields, data views, and allowlists to your environment.

**Coverage count:** 7 technique sections / 26 KQL queries

## Techniques in this tactic

- [T1486 — Data Encrypted for Impact](SO_TA0040_Impact.md#t1486-data-encrypted-for-impact) — 6 queries
- [T1490 — Inhibit System Recovery](SO_TA0040_Impact.md#t1490-inhibit-system-recovery) — 5 queries
- [T1485 — Data Destruction](SO_TA0040_Impact.md#t1485-data-destruction) — 5 queries
- [T1489 — Service Stop](SO_TA0040_Impact.md#t1489-service-stop) — 3 queries
- [T1491.001 — Defacement: Internal Defacement](SO_TA0040_Impact.md#t1491.001-defacement-internal-defacement) — 2 queries
- [T1498 — Network Denial of Service](SO_TA0040_Impact.md#t1498-network-denial-of-service) — 4 queries
- [T1496 — Resource Hijacking](SO_TA0040_Impact.md#t1496-resource-hijacking) — 1 query

---

## T1486 — Data Encrypted for Impact

**Tactic:** Impact  
**Detection idea:** Ransomware-like encryption and ransom note artifacts  
**Elastic implementation notes:** ECS field names vary by integration. Start with the KQL below, then tune for your Elastic Agent, Elastic Defend, Windows, System, Sysmon, cloud, and email data streams.

### Query 1
```kql
event.category:file and event.action:(creation or modification) and file.name:(*README* or *RECOVER* or *DECRYPT* or *HOW_TO_RESTORE* or *ransom*)
```

### Query 2
```kql
event.category:process and process.command_line:(*cipher\ /w* or *vssadmin\ delete* or *wbadmin\ delete* or *bcdedit* or *wevtutil\ cl*)
```

**Tuning ideas:** allowlist known admin scripts, software deployment tools, scanners, EDR activity, patch management, and sanctioned cloud apps before alerting.

---

### Query 3 — Security Onion
**Security Onion specific:** Uses Security Onion Suricata alert data for ransomware signatures.

```kql
event.module:"Suricata" and event.dataset:"alert" and rule.name:(*Ransomware* or *RANSOMWARE* or *CryptoLocker* or *LockBit* or *Conti* or *BlackCat*)
```

**Security Onion Hunt dashboard (OQL):** Uses Security Onion 3.1 Hunt syntax. The filter uses Lucene/OQL boolean operators and adds Hunt-friendly grouping, sorting, and event-table columns.

```oql
event.module:"Suricata" AND event.dataset:"alert" AND rule.name:(*Ransomware* OR *RANSOMWARE* OR *CryptoLocker* OR *LockBit* OR *Conti* OR *BlackCat*) | groupby event.dataset source.ip destination.ip destination.port rule.name | sortby @timestamp | table event.module event.dataset source.ip source.port destination.ip destination.port network.transport network.community_id log.id.uid rule.name dns.question.name url.domain tls.server.name http.request.method file.name file.path host.name user.name event.code event.action
```

### Query 4 — Security Onion
**Security Onion specific:** Uses Security Onion Zeek SMB/file metadata to hunt ransomware note creation over file shares.

```kql
event.dataset:(smb_files or files) and file.name:(*README* or *RECOVER* or *DECRYPT* or *HOW_TO_RESTORE* or *ransom*)
```

**Security Onion Hunt dashboard (OQL):** Uses Security Onion 3.1 Hunt syntax. The filter uses Lucene/OQL boolean operators and adds Hunt-friendly grouping, sorting, and event-table columns.

```oql
event.dataset:(smb_files OR files) AND file.name:(*README* OR *RECOVER* OR *DECRYPT* OR *HOW_TO_RESTORE* OR *ransom*) | groupby event.dataset source.ip destination.ip destination.port rule.name | sortby @timestamp | table event.module event.dataset source.ip source.port destination.ip destination.port network.transport network.community_id log.id.uid rule.name dns.question.name url.domain tls.server.name http.request.method file.name file.path host.name user.name event.code event.action
```
### Query 5 — Security Onion Windows Elastic Agent
**Security Onion specific:** Uses Elastic Agent telemetry in Security Onion 3.1.0 for Windows hosts. Requires Elastic Agent endpoint, system, Windows, macOS, Linux, or Elastic Defend data streams with ECS host, process, file, registry, authentication, or network fields.

```kql
event.category:file and agent.type:"elastic-agent" and host.os.type:windows and event.action:(creation or modification) and (file.name:(*README* or *RECOVER* or *DECRYPT* or *HOW_TO_RESTORE*) or file.extension:(locked or encrypted or crypt or ransom))
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:file AND agent.type:"elastic-agent" AND host.os.type:windows AND event.action:(creation OR modification) AND (file.name:(*README* OR *RECOVER* OR *DECRYPT* OR *HOW_TO_RESTORE*) OR file.extension:(locked OR encrypted OR crypt OR ransom)) | groupby host.name host.os.type user.name process.name process.parent.name destination.ip destination.port event.action | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port network.transport network.community_id event.code rule.name
```
### Query 6 — Security Onion macOS Elastic Agent
**Security Onion specific:** Uses Elastic Agent telemetry in Security Onion 3.1.0 for macOS hosts. Requires Elastic Agent endpoint, system, Windows, macOS, Linux, or Elastic Defend data streams with ECS host, process, file, registry, authentication, or network fields.

```kql
event.category:file and agent.type:"elastic-agent" and host.os.type:macos and event.action:(creation or modification) and (file.name:(*README* or *RECOVER* or *DECRYPT* or *HOW_TO_RESTORE*) or file.extension:(locked or encrypted or crypt or ransom))
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:file AND agent.type:"elastic-agent" AND host.os.type:macos AND event.action:(creation OR modification) AND (file.name:(*README* OR *RECOVER* OR *DECRYPT* OR *HOW_TO_RESTORE*) OR file.extension:(locked OR encrypted OR crypt OR ransom)) | groupby host.name host.os.type user.name process.name process.parent.name destination.ip destination.port event.action | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line process.executable file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port destination.domain network.transport event.code rule.name
```

## T1490 — Inhibit System Recovery

**Tactic:** Impact  
**Detection idea:** Deletion of backups, shadow copies, or recovery settings  
**Elastic implementation notes:** ECS field names vary by integration. Start with the KQL below, then tune for your Elastic Agent, Elastic Defend, Windows, System, Sysmon, cloud, and email data streams.

### Query 1
```kql
event.category:process and process.name:("vssadmin.exe" or "wmic.exe" or "wbadmin.exe" or "bcdedit.exe" or "powershell.exe") and process.command_line:(*delete\ shadows* or *shadowcopy\ delete* or *delete\ catalog* or *recoveryenabled\ no* or *resize\ shadowstorage*)
```

### Query 2
```kql
event.category:process and process.command_line:(*Disable-ComputerRestore* or *Checkpoint-Computer* or *Remove-Item*) and process.command_line:*System\ Volume\ Information*
```

### Query 3 — Security Onion Linux Elastic Agent
**Security Onion specific:** Uses Elastic Agent telemetry in Security Onion 3.1.0 for Linux hosts. Requires Elastic Agent endpoint, system, Windows, macOS, Linux, or Elastic Defend data streams with ECS host, process, file, registry, authentication, or network fields.

```kql
event.category:process and agent.type:"elastic-agent" and host.os.type:linux and process.name:(rm or find or restic or borg or btrfs or zfs) and process.command_line:(*/backup* or *snapshot*delete* or *prune* or *forget* or *destroy*)
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:process AND agent.type:"elastic-agent" AND host.os.type:linux AND process.name:(rm OR find OR restic OR borg OR btrfs OR zfs) AND process.command_line:(*\/backup* OR *snapshot*delete* OR *prune* OR *forget* OR *destroy*) | groupby host.name host.os.type user.name process.name process.parent.name destination.ip destination.port event.action | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port network.transport network.community_id event.code rule.name
```

### Query 4 — Security Onion Windows Elastic Agent
**Security Onion specific:** Uses Elastic Agent telemetry in Security Onion 3.1.0 for Windows hosts. Requires Elastic Agent endpoint, system, Windows, macOS, Linux, or Elastic Defend data streams with ECS host, process, file, registry, authentication, or network fields.

```kql
event.category:process and agent.type:"elastic-agent" and host.os.type:windows and process.name:("vssadmin.exe" or "wbadmin.exe" or "bcdedit.exe" or "wmic.exe" or "powershell.exe") and process.command_line:(*delete\ shadows* or *delete\ catalog* or *recoveryenabled\ no* or *shadowcopy\ delete* or *Disable-ComputerRestore*)
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:process AND agent.type:"elastic-agent" AND host.os.type:windows AND process.name:("vssadmin.exe" OR "wbadmin.exe" OR "bcdedit.exe" OR "wmic.exe" OR "powershell.exe") AND process.command_line:(*delete\ shadows* OR *delete\ catalog* OR *recoveryenabled\ no* OR *shadowcopy\ delete* OR *Disable\-ComputerRestore*) | groupby host.name host.os.type user.name process.name process.parent.name destination.ip destination.port event.action | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line process.executable file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port destination.domain network.transport event.code rule.name
```

### Query 5 — Security Onion macOS Elastic Agent
**Security Onion specific:** Uses Elastic Agent telemetry in Security Onion 3.1.0 for macOS hosts. Requires Elastic Agent endpoint, system, Windows, macOS, Linux, or Elastic Defend data streams with ECS host, process, file, registry, authentication, or network fields.

```kql
event.category:process and agent.type:"elastic-agent" and host.os.type:macos and process.name:(tmutil or diskutil or rm) and process.command_line:(*delete* or *localsnapshot* or *TimeMachine* or */Volumes/* or */Backups.backupdb/*)
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:process AND agent.type:"elastic-agent" AND host.os.type:macos AND process.name:(tmutil OR diskutil OR rm) AND process.command_line:(*delete* OR *localsnapshot* OR *TimeMachine* OR *\/Volumes\/* OR *\/Backups.backupdb\/*) | groupby host.name host.os.type user.name process.name process.parent.name destination.ip destination.port event.action | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line process.executable file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port destination.domain network.transport event.code rule.name
```

**Tuning ideas:** allowlist known admin scripts, software deployment tools, scanners, EDR activity, patch management, and sanctioned cloud apps before alerting.

---

## T1485 — Data Destruction

**Tactic:** Impact  
**Detection idea:** Destructive file deletion or wipe commands  
**Elastic implementation notes:** ECS field names vary by integration. Start with the KQL below, then tune for your Elastic Agent, Elastic Defend, Windows, System, Sysmon, cloud, and email data streams.

### Query 1
```kql
event.category:process and process.name:("cmd.exe" or "powershell.exe" or "pwsh.exe" or "sdelete.exe" or "cipher.exe") and process.command_line:(*del\ /s* or *Remove-Item*\ -Recurse* or *sdelete* or *cipher\ /w* or *format*)
```

### Query 2
```kql
event.category:file and event.action:deletion and file.path:(*\\\\Users\\\\* or *\\\\Shares\\\\* or *\\\\ProgramData\\\\*) and file.extension:(doc or docx or xls or xlsx or pdf or txt or csv)
```

### Query 3 — Security Onion Linux/macOS Elastic Agent
**Security Onion specific:** Uses Elastic Agent telemetry in Security Onion 3.1.0 for Linux/macOS hosts. Requires Elastic Agent endpoint, system, or Elastic Defend data streams with ECS host, process, file, or network fields.

```kql
event.category:process and agent.type:"elastic-agent" and host.os.type:(linux or macos) and process.name:(rm or shred or srm or dd or diskutil or mkfs) and process.command_line:(*\ -rf\ * or *shred* or *diskutil\ erase* or *dd\ if=/dev/zero* or *mkfs* or */Users/* or */home/*)
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:process AND agent.type:"elastic-agent" AND host.os.type:(linux OR macos) AND process.name:(rm OR shred OR srm OR dd OR diskutil OR mkfs) AND process.command_line:(*\ \-rf\ * OR *shred* OR *diskutil\ erase* OR *dd\ if=\/dev\/zero* OR *mkfs* OR *\/Users\/* OR *\/home\/*) | groupby host.name host.os.type user.name process.name source.ip destination.ip destination.port | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line file.path file.name file.extension source.ip source.port destination.ip destination.port network.transport network.community_id rule.name
```

### Query 4 — Security Onion macOS Elastic Agent
**Security Onion specific:** Uses Elastic Agent telemetry in Security Onion 3.1.0 for macOS hosts. Requires Elastic Agent endpoint, system, Windows, macOS, Linux, or Elastic Defend data streams with ECS host, process, file, registry, authentication, or network fields.

```kql
event.category:process and agent.type:"elastic-agent" and host.os.type:macos and process.name:(rm or srm or diskutil or find) and process.command_line:(*\ -rf\ * or *eraseDisk* or *secureErase* or */Users/* or */Volumes/*)
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:process AND agent.type:"elastic-agent" AND host.os.type:macos AND process.name:(rm OR srm OR diskutil OR find) AND process.command_line:(*\ \-rf\ * OR *eraseDisk* OR *secureErase* OR *\/Users\/* OR *\/Volumes\/*) | groupby host.name host.os.type user.name process.name process.parent.name destination.ip destination.port event.action | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port network.transport network.community_id event.code rule.name
```

### Query 5 — Security Onion Linux Elastic Agent
**Security Onion specific:** Uses Elastic Agent telemetry in Security Onion 3.1.0 for Linux hosts. Requires Elastic Agent endpoint, system, Windows, macOS, Linux, or Elastic Defend data streams with ECS host, process, file, registry, authentication, or network fields.

```kql
event.category:process and agent.type:"elastic-agent" and host.os.type:linux and process.name:(rm or shred or dd or wipe) and process.command_line:(*\ -rf\ /home* or *\ -rf\ /root* or *\ -rf\ /mnt* or *if=/dev/zero* or *shred*)
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:process AND agent.type:"elastic-agent" AND host.os.type:linux AND process.name:(rm OR shred OR dd OR wipe) AND process.command_line:(*\ \-rf\ \/home* OR *\ \-rf\ \/root* OR *\ \-rf\ \/mnt* OR *if=\/dev\/zero* OR *shred*) | groupby host.name host.os.type user.name process.name process.parent.name destination.ip destination.port event.action | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line process.executable file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port destination.domain network.transport event.code rule.name
```

**Tuning ideas:** allowlist known admin scripts, software deployment tools, scanners, EDR activity, patch management, and sanctioned cloud apps before alerting.

---

## T1489 — Service Stop

**Tactic:** Impact  
**Detection idea:** Stopping critical services or security services  
**Elastic implementation notes:** ECS field names vary by integration. Start with the KQL below, then tune for your Elastic Agent, Elastic Defend, Windows, System, Sysmon, cloud, and email data streams.

### Query 1
```kql
event.category:process and process.name:("net.exe" or "net1.exe" or "sc.exe" or "powershell.exe" or "pwsh.exe") and process.command_line:(*\ stop\ * or *Stop-Service* or *Set-Service*Disabled* or *delete*)
```

### Query 2
```kql
event.category:process and process.command_line:(*MSSQLSERVER* or *VSS* or *WinDefend* or *Sense* or *EventLog* or *Backup*) and process.command_line:(*stop* or *disable* or *delete*)
```

### Query 3 — Security Onion Windows Elastic Agent
**Security Onion specific:** Uses Elastic Agent telemetry in Security Onion 3.1.0 for Windows hosts. Requires Elastic Agent endpoint, system, Windows, macOS, Linux, or Elastic Defend data streams with ECS host, process, file, registry, authentication, or network fields.

```kql
event.category:process and agent.type:"elastic-agent" and host.os.type:windows and process.name:("net.exe" or "net1.exe" or "sc.exe" or "powershell.exe") and process.command_line:(*\ stop\ * or *Stop-Service* or *Set-Service*Disabled*) and process.command_line:(*WinDefend* or *Sense* or *EventLog* or *VSS* or *Backup* or *MSSQL*)
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:process AND agent.type:"elastic-agent" AND host.os.type:windows AND process.name:("net.exe" OR "net1.exe" OR "sc.exe" OR "powershell.exe") AND process.command_line:(*\ stop\ * OR *Stop\-Service* OR *Set\-Service*Disabled*) AND process.command_line:(*WinDefend* OR *Sense* OR *EventLog* OR *VSS* OR *Backup* OR *MSSQL*) | groupby host.name host.os.type user.name process.name process.parent.name destination.ip destination.port event.action | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line process.executable file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port destination.domain network.transport event.code rule.name
```

**Tuning ideas:** allowlist known admin scripts, software deployment tools, scanners, EDR activity, patch management, and sanctioned cloud apps before alerting.

---

## T1491.001 — Defacement: Internal Defacement

**Tactic:** Impact  
**Detection idea:** Unauthorized modification of internal web content  
**Elastic implementation notes:** ECS field names vary by integration. Start with the KQL below, then tune for your Elastic Agent, Elastic Defend, Windows, System, Sysmon, cloud, and email data streams.

### Query 1
```kql
event.category:file and event.action:(creation or modification) and file.path:(*\\\\inetpub\\\\wwwroot\\\\* or */var/www/* or */usr/share/nginx/html/*) and file.name:("index.html" or "index.php" or "default.aspx")
```

### Query 2
```kql
event.category:process and process.name:("cmd.exe" or "powershell.exe" or "pwsh.exe" or "bash" or "sh") and process.command_line:(*wwwroot* or */var/www/* or *index.html* or *default.aspx*)
```

**Tuning ideas:** allowlist known admin scripts, software deployment tools, scanners, EDR activity, patch management, and sanctioned cloud apps before alerting.

---

## T1498 — Network Denial of Service

**Tactic:** Impact  
**Detection idea:** High-volume or flood-like network activity from monitored hosts  
**Elastic implementation notes:** ECS field names vary by integration. Start with the KQL below, then tune for your Elastic Agent, Elastic Defend, Windows, System, Sysmon, cloud, and email data streams.

### Query 1
```kql
event.category:network and event.action:(connection_attempted or network_connection) and destination.ip:* and source.ip:* and process.name:("hping3" or "nping.exe" or "nmap.exe" or "powershell.exe" or "python.exe")
```

### Query 2
```kql
event.category:process and process.command_line:(*hping3* or *nping* or *--flood* or *SYN\ flood* or *Start-Job* or *while\($true\)*)
```

**Tuning ideas:** allowlist known admin scripts, software deployment tools, scanners, EDR activity, patch management, and sanctioned cloud apps before alerting.

---

### Query 3 — Security Onion
**Security Onion specific:** Uses Security Onion Suricata alert data for denial-of-service signatures.

```kql
event.module:"Suricata" and event.dataset:"alert" and rule.name:(*DOS* or *DDoS* or *Denial\ of\ Service* or *Flood*) and source.ip:* and destination.ip:*
```

**Security Onion Hunt dashboard (OQL):** Uses Security Onion 3.1 Hunt syntax. The filter uses Lucene/OQL boolean operators and adds Hunt-friendly grouping, sorting, and event-table columns.

```oql
event.module:"Suricata" AND event.dataset:"alert" AND rule.name:(*DOS* OR *DDoS* OR *Denial\ of\ Service* OR *Flood*) AND source.ip:* AND destination.ip:* | groupby event.dataset source.ip destination.ip destination.port rule.name | sortby @timestamp | table event.module event.dataset source.ip source.port destination.ip destination.port network.transport network.community_id log.id.uid rule.name dns.question.name url.domain tls.server.name http.request.method file.name file.path host.name user.name event.code event.action
```

### Query 4 — Security Onion
**Security Onion specific:** Uses Security Onion Zeek connection metadata for high-risk DoS protocol traffic candidates.

```kql
event.dataset:conn and network.transport:(tcp or udp or icmp) and destination.ip:* and source.ip:*
```

**Security Onion Hunt dashboard (OQL):** Uses Security Onion 3.1 Hunt syntax. The filter uses Lucene/OQL boolean operators and adds Hunt-friendly grouping, sorting, and event-table columns.

```oql
event.dataset:conn AND network.transport:(tcp OR udp OR icmp) AND destination.ip:* AND source.ip:* | groupby event.dataset source.ip destination.ip destination.port rule.name | sortby @timestamp | table event.module event.dataset source.ip source.port destination.ip destination.port network.transport network.community_id log.id.uid rule.name dns.question.name url.domain tls.server.name http.request.method file.name file.path host.name user.name event.code event.action
```

## T1496 — Resource Hijacking

**Tactic:** Impact  
**Detection idea:** Linux Elastic Agent cryptomining process or miner pool indicators  
**Elastic implementation notes:** Host telemetry requires Elastic Agent with endpoint, system, Windows, macOS, Linux, or Elastic Defend integrations. Field availability varies by agent policy and event collection settings.

### Query 1 — Security Onion Linux Elastic Agent
**Security Onion specific:** Uses Elastic Agent telemetry in Security Onion 3.1.0 for Linux hosts. Requires Elastic Agent endpoint, system, Windows, macOS, Linux, or Elastic Defend data streams with ECS host, process, file, registry, authentication, or network fields.

```kql
event.category:(process or network) and agent.type:"elastic-agent" and host.os.type:linux and (process.name:(xmrig or minerd or kinsing or crypto) or process.command_line:(*stratum+tcp* or *--coin* or *xmrig*))
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:(process OR network) AND agent.type:"elastic-agent" AND host.os.type:linux AND (process.name:(xmrig OR minerd OR kinsing OR crypto) OR process.command_line:(*stratum\+tcp* OR *\-\-coin* OR *xmrig*)) | groupby host.name host.os.type user.name process.name process.parent.name destination.ip destination.port event.action | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line process.executable file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port destination.domain network.transport event.code rule.name
```


**Tuning ideas:** allowlist approved admin scripts, package managers, MDM/GPO activity, backup tools, EDR activity, deployment systems, developer workflows, and sanctioned remote administration.

---
