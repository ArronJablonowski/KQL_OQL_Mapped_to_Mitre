# TA0010 — Exfiltration

> Query dialect: Elastic Kibana Query Language (**Elastic KQL**) using ECS-style fields. These are hunting-grade filters intended for Kibana Discover, Timeline, and Elastic Security rules. Tune fields, data views, and allowlists to your environment.

**Coverage count:** 6 technique sections / 25 KQL queries

## Techniques in this tactic

- [T1041 — Exfiltration Over C2 Channel](SO_TA0010_Exfiltration.md#t1041-exfiltration-over-c2-channel) — 2 queries
- [T1567.002 — Exfiltration to Cloud Storage](SO_TA0010_Exfiltration.md#t1567.002-exfiltration-to-cloud-storage) — 7 queries
- [T1048 — Exfiltration Over Alternative Protocol](SO_TA0010_Exfiltration.md#t1048-exfiltration-over-alternative-protocol) — 7 queries
- [T1020 — Automated Exfiltration](SO_TA0010_Exfiltration.md#t1020-automated-exfiltration) — 2 queries
- [T1052.001 — Exfiltration Over Physical Medium: Exfiltration over USB](SO_TA0010_Exfiltration.md#t1052.001-exfiltration-over-physical-medium-exfiltration-over-usb) — 4 queries
- [T1567.001 — Exfiltration Over Web Service: Exfiltration to Code Repository](SO_TA0010_Exfiltration.md#t1567.001-exfiltration-over-web-service-exfiltration-to-code-repository) — 3 queries

---

## T1041 — Exfiltration Over C2 Channel

**Tactic:** Exfiltration  
**Detection idea:** Suspicious outbound transfer by scripting or LOLBin processes  
**Elastic implementation notes:** ECS field names vary by integration. Start with the KQL below, then tune for your Elastic Agent, Elastic Defend, Windows, System, Sysmon, cloud, and email data streams.

### Query 1
```kql
event.category:network and process.name:("powershell.exe" or "pwsh.exe" or "curl.exe" or "rclone.exe" or "certutil.exe" or "bitsadmin.exe") and destination.ip:* and not destination.ip:(10.0.0.0/8 or 172.16.0.0/12 or 192.168.0.0/16)
```

### Query 2
```kql
event.category:process and process.command_line:(*Invoke-WebRequest* or *curl* or *rclone* or *mega.nz* or *transfer.sh* or *pastebin*)
```

**Tuning ideas:** allowlist known admin scripts, software deployment tools, scanners, EDR activity, patch management, and sanctioned cloud apps before alerting.

---

## T1567.002 — Exfiltration to Cloud Storage

**Tactic:** Exfiltration  
**Detection idea:** Command-line or process access to cloud storage providers  
**Elastic implementation notes:** ECS field names vary by integration. Start with the KQL below, then tune for your Elastic Agent, Elastic Defend, Windows, System, Sysmon, cloud, and email data streams.

### Query 1
```kql
event.category:network and destination.domain:(*dropbox.com or *drive.google.com or *onedrive.live.com or *box.com or *mega.nz or *blob.core.windows.net or *s3.amazonaws.com)
```

### Query 2
```kql
event.category:process and process.command_line:(*rclone* or *dropbox* or *gdrive* or *onedrive* or *mega.nz* or *s3\://* or *azcopy*)
```

**Tuning ideas:** allowlist known admin scripts, software deployment tools, scanners, EDR activity, patch management, and sanctioned cloud apps before alerting.

---

### Query 3 — Security Onion
**Security Onion specific:** Uses Security Onion Zeek DNS/SSL metadata for cloud-storage exfiltration destinations.

```kql
event.dataset:(dns or ssl) and (dns.question.name:(*dropbox.com or *drive.google.com or *onedrive.live.com or *box.com or *mega.nz or *blob.core.windows.net or *s3.amazonaws.com) or tls.server.name:(*dropbox.com or *drive.google.com or *onedrive.live.com or *box.com or *mega.nz or *blob.core.windows.net or *s3.amazonaws.com))
```

**Security Onion Hunt dashboard (OQL):** Uses Security Onion 3.1 Hunt syntax. The filter uses Lucene/OQL boolean operators and adds Hunt-friendly grouping, sorting, and event-table columns.

```oql
event.dataset:(dns OR ssl) AND (dns.question.name:(*dropbox.com OR *drive.google.com OR *onedrive.live.com OR *box.com OR *mega.nz OR *blob.core.windows.net OR *s3.amazonaws.com) OR tls.server.name:(*dropbox.com OR *drive.google.com OR *onedrive.live.com OR *box.com OR *mega.nz OR *blob.core.windows.net OR *s3.amazonaws.com)) | groupby event.dataset source.ip destination.ip destination.port rule.name | sortby @timestamp | table event.module event.dataset source.ip source.port destination.ip destination.port network.transport network.community_id log.id.uid rule.name dns.question.name url.domain tls.server.name http.request.method file.name file.path host.name user.name event.code event.action
```

### Query 4 — Security Onion
**Security Onion specific:** Uses Security Onion Suricata alert data for cloud upload or exfiltration signatures.

```kql
event.module:"Suricata" and event.dataset:"alert" and rule.name:(*Dropbox* or *Google\ Drive* or *OneDrive* or *MEGA* or *S3* or *EXFIL*)
```

**Security Onion Hunt dashboard (OQL):** Uses Security Onion 3.1 Hunt syntax. The filter uses Lucene/OQL boolean operators and adds Hunt-friendly grouping, sorting, and event-table columns.

```oql
event.module:"Suricata" AND event.dataset:"alert" AND rule.name:(*Dropbox* OR *Google\ Drive* OR *OneDrive* OR *MEGA* OR *S3* OR *EXFIL*) | groupby event.dataset source.ip destination.ip destination.port rule.name | sortby @timestamp | table event.module event.dataset source.ip source.port destination.ip destination.port network.transport network.community_id log.id.uid rule.name dns.question.name url.domain tls.server.name http.request.method file.name file.path host.name user.name event.code event.action
```
### Query 5 — Security Onion Windows Elastic Agent
**Security Onion specific:** Uses Elastic Agent telemetry in Security Onion 3.1.0 for Windows hosts. Requires Elastic Agent endpoint, system, Windows, macOS, Linux, or Elastic Defend data streams with ECS host, process, file, registry, authentication, or network fields.

```kql
event.category:(process or network) and agent.type:"elastic-agent" and host.os.type:windows and (process.command_line:(*rclone* or *azcopy* or *s3\://* or *mega.nz* or *dropbox* or *drive.google*) or destination.domain:(*dropbox.com or *drive.google.com or *onedrive.live.com or *mega.nz or *s3.amazonaws.com))
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:(process OR network) AND agent.type:"elastic-agent" AND host.os.type:windows AND (process.command_line:(*rclone* OR *azcopy* OR *s3\:\/\/* OR *mega.nz* OR *dropbox* OR *drive.google*) OR destination.domain:(*dropbox.com OR *drive.google.com OR *onedrive.live.com OR *mega.nz OR *s3.amazonaws.com)) | groupby host.name host.os.type user.name process.name process.parent.name destination.ip destination.port event.action | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line process.executable file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port destination.domain network.transport event.code rule.name
```
### Query 6 — Security Onion Linux Elastic Agent
**Security Onion specific:** Uses Elastic Agent telemetry in Security Onion 3.1.0 for Linux hosts. Requires Elastic Agent endpoint, system, Windows, macOS, Linux, or Elastic Defend data streams with ECS host, process, file, registry, authentication, or network fields.

```kql
event.category:process and agent.type:"elastic-agent" and host.os.type:linux and process.name:(rclone or aws or gsutil or azcopy or curl) and process.command_line:(*copy* or *sync* or *upload* or *s3\://* or *gs\://* or *blob.core.windows.net*)
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:process AND agent.type:"elastic-agent" AND host.os.type:linux AND process.name:(rclone OR aws OR gsutil OR azcopy OR curl) AND process.command_line:(*copy* OR *sync* OR *upload* OR *s3\:\/\/* OR *gs\:\/\/* OR *blob.core.windows.net*) | groupby host.name host.os.type user.name process.name process.parent.name destination.ip destination.port event.action | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line process.executable file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port destination.domain network.transport event.code rule.name
```
### Query 7 — Security Onion macOS Elastic Agent
**Security Onion specific:** Uses Elastic Agent telemetry in Security Onion 3.1.0 for macOS hosts. Requires Elastic Agent endpoint, system, Windows, macOS, Linux, or Elastic Defend data streams with ECS host, process, file, registry, authentication, or network fields.

```kql
event.category:process and agent.type:"elastic-agent" and host.os.type:macos and process.name:(rclone or aws or gsutil or curl) and process.command_line:(*copy* or *sync* or *upload* or *s3\://* or *gs\://* or *dropbox* or *drive.google*)
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:process AND agent.type:"elastic-agent" AND host.os.type:macos AND process.name:(rclone OR aws OR gsutil OR curl) AND process.command_line:(*copy* OR *sync* OR *upload* OR *s3\:\/\/* OR *gs\:\/\/* OR *dropbox* OR *drive.google*) | groupby host.name host.os.type user.name process.name process.parent.name destination.ip destination.port event.action | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line process.executable file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port destination.domain network.transport event.code rule.name
```

## T1048 — Exfiltration Over Alternative Protocol

**Tactic:** Exfiltration  
**Detection idea:** Outbound transfer tools using FTP, SCP, SFTP, or mail protocols  
**Elastic implementation notes:** ECS field names vary by integration. Start with the KQL below, then tune for your Elastic Agent, Elastic Defend, Windows, System, Sysmon, cloud, and email data streams.

### Query 1
```kql
event.category:network and destination.port:(21 or 22 or 25 or 465 or 587 or 993) and process.name:("curl.exe" or "winscp.exe" or "scp.exe" or "sftp.exe" or "powershell.exe" or "pwsh.exe")
```

### Query 2
```kql
event.category:process and process.command_line:(*ftp\://* or *sftp\://* or *scp\ * or *Send-MailMessage* or *smtp*)
```

**Tuning ideas:** allowlist known admin scripts, software deployment tools, scanners, EDR activity, patch management, and sanctioned cloud apps before alerting.

---

### Query 3 — Security Onion
**Security Onion specific:** Uses Security Onion Zeek connection metadata for alternative protocol exfil paths.

```kql
event.dataset:conn and destination.port:(21 or 22 or 25 or 465 or 587 or 993) and source.ip:* and destination.ip:*
```

**Security Onion Hunt dashboard (OQL):** Uses Security Onion 3.1 Hunt syntax. The filter uses Lucene/OQL boolean operators and adds Hunt-friendly grouping, sorting, and event-table columns.

```oql
event.dataset:conn AND destination.port:(21 OR 22 OR 25 OR 465 OR 587 OR 993) AND source.ip:* AND destination.ip:* | groupby event.dataset source.ip destination.ip destination.port rule.name | sortby @timestamp | table event.module event.dataset source.ip source.port destination.ip destination.port network.transport network.community_id log.id.uid rule.name dns.question.name url.domain tls.server.name http.request.method file.name file.path host.name user.name event.code event.action
```

### Query 4 — Security Onion
**Security Onion specific:** Uses Security Onion Suricata alert data for FTP/SCP/SMTP exfiltration signatures.

```kql
event.module:"Suricata" and event.dataset:"alert" and rule.name:(*EXFIL* or *FTP\ Upload* or *SMTP* or *SCP* or *Data\ Exfiltration*)
```

**Security Onion Hunt dashboard (OQL):** Uses Security Onion 3.1 Hunt syntax. The filter uses Lucene/OQL boolean operators and adds Hunt-friendly grouping, sorting, and event-table columns.

```oql
event.module:"Suricata" AND event.dataset:"alert" AND rule.name:(*EXFIL* OR *FTP\ Upload* OR *SMTP* OR *SCP* OR *Data\ Exfiltration*) | groupby event.dataset source.ip destination.ip destination.port rule.name | sortby @timestamp | table event.module event.dataset source.ip source.port destination.ip destination.port network.transport network.community_id log.id.uid rule.name dns.question.name url.domain tls.server.name http.request.method file.name file.path host.name user.name event.code event.action
```
### Query 5 — Security Onion Linux/macOS Elastic Agent
**Security Onion specific:** Uses Elastic Agent telemetry in Security Onion 3.1.0 for Linux/macOS hosts. Requires Elastic Agent endpoint, system, or Elastic Defend data streams with ECS host, process, file, or network fields.

```kql
event.category:process and agent.type:"elastic-agent" and host.os.type:(linux or macos) and process.name:(scp or sftp or rsync or curl or rclone or aws or gsutil) and process.command_line:(*\://* or *s3\://* or *sync* or *copy* or *upload* or */home/* or */Users/*)
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:process AND agent.type:"elastic-agent" AND host.os.type:(linux OR macos) AND process.name:(scp OR sftp OR rsync OR curl OR rclone OR aws OR gsutil) AND process.command_line:(*\:\/\/* OR *s3\:\/\/* OR *sync* OR *copy* OR *upload* OR *\/home\/* OR *\/Users\/*) | groupby host.name host.os.type user.name process.name source.ip destination.ip destination.port | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line file.path file.name file.extension source.ip source.port destination.ip destination.port network.transport network.community_id rule.name
```
### Query 6 — Security Onion Linux Elastic Agent
**Security Onion specific:** Uses Elastic Agent telemetry in Security Onion 3.1.0 for Linux hosts. Requires Elastic Agent endpoint, system, Windows, macOS, Linux, or Elastic Defend data streams with ECS host, process, file, registry, authentication, or network fields.

```kql
event.category:process and agent.type:"elastic-agent" and host.os.type:linux and process.name:(scp or sftp or rsync or curl or rclone) and process.command_line:(*/home/* or */root/* or */backup* or *sftp\://* or *scp\://* or *rclone\ copy*)
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:process AND agent.type:"elastic-agent" AND host.os.type:linux AND process.name:(scp OR sftp OR rsync OR curl OR rclone) AND process.command_line:(*\/home\/* OR *\/root\/* OR *\/backup* OR *sftp\:\/\/* OR *scp\:\/\/* OR *rclone\ copy*) | groupby host.name host.os.type user.name process.name process.parent.name destination.ip destination.port event.action | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port network.transport network.community_id event.code rule.name
```
### Query 7 — Security Onion macOS Elastic Agent
**Security Onion specific:** Uses Elastic Agent telemetry in Security Onion 3.1.0 for macOS hosts. Requires Elastic Agent endpoint, system, Windows, macOS, Linux, or Elastic Defend data streams with ECS host, process, file, registry, authentication, or network fields.

```kql
event.category:process and agent.type:"elastic-agent" and host.os.type:macos and process.name:(scp or sftp or rsync or curl or rclone) and process.command_line:(*/Users/* or */Volumes/* or *sftp\://* or *scp\://* or *rclone\ copy* or *upload*)
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:process AND agent.type:"elastic-agent" AND host.os.type:macos AND process.name:(scp OR sftp OR rsync OR curl OR rclone) AND process.command_line:(*\/Users\/* OR *\/Volumes\/* OR *sftp\:\/\/* OR *scp\:\/\/* OR *rclone\ copy* OR *upload*) | groupby host.name host.os.type user.name process.name process.parent.name destination.ip destination.port event.action | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line process.executable file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port destination.domain network.transport event.code rule.name
```

## T1020 — Automated Exfiltration

**Tactic:** Exfiltration  
**Detection idea:** Scripted or scheduled outbound file transfer  
**Elastic implementation notes:** ECS field names vary by integration. Start with the KQL below, then tune for your Elastic Agent, Elastic Defend, Windows, System, Sysmon, cloud, and email data streams.

### Query 1
```kql
event.category:process and process.name:("powershell.exe" or "pwsh.exe" or "cmd.exe" or "rclone.exe" or "curl.exe") and process.command_line:(*Compress-Archive* or *.zip* or *Invoke-WebRequest* or *Invoke-RestMethod* or *rclone\ sync*)
```

### Query 2
```kql
event.category:process and process.parent.name:"schtasks.exe" and process.command_line:(*curl* or *rclone* or *powershell* or *ftp* or *s3*)
```

**Tuning ideas:** allowlist known admin scripts, software deployment tools, scanners, EDR activity, patch management, and sanctioned cloud apps before alerting.

---

## T1052.001 — Exfiltration Over Physical Medium: Exfiltration over USB

**Tactic:** Exfiltration  
**Detection idea:** File copy activity to removable media  
**Elastic implementation notes:** ECS field names vary by integration. Start with the KQL below, then tune for your Elastic Agent, Elastic Defend, Windows, System, Sysmon, cloud, and email data streams.

### Query 1
```kql
event.category:file and event.action:(creation or modification) and file.path:(E\:\\* or F\:\\* or G\:\\* or H\:\\*) and file.extension:(zip or 7z or rar or docx or xlsx or pdf or csv)
```

### Query 2
```kql
event.category:process and process.name:("robocopy.exe" or "xcopy.exe" or "powershell.exe" or "cmd.exe") and process.command_line:(*\ E\:\\* or *\ F\:\\* or *\ G\:\\* or *\ H\:\\*)
```

**Tuning ideas:** allowlist known admin scripts, software deployment tools, scanners, EDR activity, patch management, and sanctioned cloud apps before alerting.

---

### Query 3 — Security Onion
**Security Onion specific:** Uses Security Onion endpoint logs collected through Elastic Agent/Windows integrations for removable-media writes.

```kql
event.category:file and event.action:(creation or modification) and file.path:(E\:\\* or F\:\\* or G\:\\* or H\:\\*) and agent.type:elastic-agent
```

**Security Onion Hunt dashboard (OQL):** Uses Security Onion 3.1 Hunt syntax. The filter uses Lucene/OQL boolean operators and adds Hunt-friendly grouping, sorting, and event-table columns.

```oql
event.category:file AND event.action:(creation OR modification) AND file.path:(E\:\\* OR F\:\\* OR G\:\\* OR H\:\\*) AND agent.type:elastic-agent | groupby event.dataset source.ip destination.ip destination.port rule.name | sortby @timestamp | table event.module event.dataset source.ip source.port destination.ip destination.port network.transport network.community_id log.id.uid rule.name dns.question.name url.domain tls.server.name http.request.method file.name file.path host.name user.name event.code event.action
```

### Query 4 — Security Onion
**Security Onion specific:** Uses Security Onion Windows/Sysmon endpoint telemetry for USB storage device insertion context.

```kql
event.dataset:(windows.sysmon_operational or windows.security or windows.system) and (event.code:("6416" or "20001") or winlog.event_data.DeviceDescription:*USB*)
```

**Security Onion Hunt dashboard (OQL):** Uses Security Onion 3.1 Hunt syntax. The filter uses Lucene/OQL boolean operators and adds Hunt-friendly grouping, sorting, and event-table columns.

```oql
event.dataset:(windows.sysmon_operational OR windows.security OR windows.system) AND (event.code:("6416" OR "20001") OR winlog.event_data.DeviceDescription:*USB*) | groupby event.dataset source.ip destination.ip destination.port rule.name | sortby @timestamp | table event.module event.dataset source.ip source.port destination.ip destination.port network.transport network.community_id log.id.uid rule.name dns.question.name url.domain tls.server.name http.request.method file.name file.path host.name user.name event.code event.action
```

## T1567.001 — Exfiltration Over Web Service: Exfiltration to Code Repository

**Tactic:** Exfiltration  
**Detection idea:** Uploads or command-line interaction with code repositories  
**Elastic implementation notes:** ECS field names vary by integration. Start with the KQL below, then tune for your Elastic Agent, Elastic Defend, Windows, System, Sysmon, cloud, and email data streams.

### Query 1
```kql
event.category:process and process.name:("git.exe" or "gh.exe" or "curl.exe" or "powershell.exe" or "pwsh.exe") and process.command_line:(*github.com* or *gitlab.com* or *bitbucket.org* or *git\ push* or *gh\ repo*)
```

### Query 2
```kql
event.category:network and destination.domain:(*github.com or *gitlab.com or *bitbucket.org or *dev.azure.com) and process.name:("git.exe" or "gh.exe" or "curl.exe" or "powershell.exe")
```

### Query 3 — Security Onion Windows Elastic Agent
**Security Onion specific:** Uses Elastic Agent telemetry in Security Onion 3.1.0 for Windows hosts. Requires Elastic Agent endpoint, system, Windows, macOS, Linux, or Elastic Defend data streams with ECS host, process, file, registry, authentication, or network fields.

```kql
event.category:(process or network) and agent.type:"elastic-agent" and host.os.type:windows and process.name:("git.exe" or "gh.exe" or "powershell.exe") and process.command_line:(*git\ push* or *github.com* or *gitlab.com* or *bitbucket.org* or *gh\ repo*)
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:(process OR network) AND agent.type:"elastic-agent" AND host.os.type:windows AND process.name:("git.exe" OR "gh.exe" OR "powershell.exe") AND process.command_line:(*git\ push* OR *github.com* OR *gitlab.com* OR *bitbucket.org* OR *gh\ repo*) | groupby host.name host.os.type user.name process.name process.parent.name destination.ip destination.port event.action | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line process.executable file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port destination.domain network.transport event.code rule.name
```

**Tuning ideas:** allowlist known admin scripts, software deployment tools, scanners, EDR activity, patch management, and sanctioned cloud apps before alerting.

---
