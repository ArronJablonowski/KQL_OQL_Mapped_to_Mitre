# TA0009 — Collection

> Query dialect: Elastic Kibana Query Language (**Elastic KQL**) using ECS-style fields. These are hunting-grade filters intended for Kibana Discover, Timeline, and Elastic Security rules. Tune fields, data views, and allowlists to your environment.

**Coverage count:** 12 technique sections / 34 KQL queries

## Techniques in this tactic

- [T1560.001 — Archive Collected Data: Archive via Utility](SO_TA0009_Collection.md#t1560.001-archive-collected-data-archive-via-utility) — 5 queries
- [T1005 — Data from Local System](SO_TA0009_Collection.md#t1005-data-from-local-system) — 5 queries
- [T1113 — Screen Capture](SO_TA0009_Collection.md#t1113-screen-capture) — 4 queries
- [T1530 — Data from Cloud Storage](SO_TA0009_Collection.md#t1530-data-from-cloud-storage) — 2 queries
- [T1115 — Clipboard Data](SO_TA0009_Collection.md#t1115-clipboard-data) — 3 queries
- [T1039 — Data from Network Shared Drive](SO_TA0009_Collection.md#t1039-data-from-network-shared-drive) — 3 queries
- [T1123 — Audio Capture](SO_TA0009_Collection.md#t1123-audio-capture) — 2 queries
- [T1119 — Automated Collection](SO_TA0009_Collection.md#t1119-automated-collection) — 1 query
- [T1074 — Data Staged](SO_TA0009_Collection.md#t1074-data-staged) — 3 queries
- [T1025 — Data from Removable Media](SO_TA0009_Collection.md#t1025-data-from-removable-media) — 2 queries
- [T1114 — Email Collection](SO_TA0009_Collection.md#t1114-email-collection) — 2 queries
- [T1125 — Video Capture](SO_TA0009_Collection.md#t1125-video-capture) — 2 queries

---

## T1560.001 — Archive Collected Data: Archive via Utility

**Tactic:** Collection  
**Detection idea:** Compression utilities used to stage data  
**Elastic implementation notes:** ECS field names vary by integration. Start with the KQL below, then tune for your Elastic Agent, Elastic Defend, Windows, System, Sysmon, cloud, and email data streams.

### Query 1
```kql
event.category:process and process.name:("7z.exe" or "7za.exe" or "rar.exe" or "winrar.exe" or "tar.exe" or "powershell.exe" or "pwsh.exe") and process.command_line:(*.zip* or *.7z* or *.rar* or *Compress-Archive* or *-mx*)
```

### Query 2
```kql
event.category:file and event.action:creation and file.extension:(zip or 7z or rar or tar or gz) and file.path:(*\\\\Users\\\\Public\\\\* or *\\\\Windows\\\\Temp\\\\* or *\\\\AppData\\\\Local\\\\Temp\\\\*)
```

### Query 3 — Security Onion Windows Elastic Agent
**Security Onion specific:** Uses Elastic Agent telemetry in Security Onion 3.1.0 for Windows hosts. Requires Elastic Agent endpoint, system, Windows, macOS, Linux, or Elastic Defend data streams with ECS host, process, file, registry, authentication, or network fields.

```kql
event.category:process and agent.type:"elastic-agent" and host.os.type:windows and process.name:("powershell.exe" or "7z.exe" or "rar.exe" or "tar.exe" or "makecab.exe") and process.command_line:(*Compress-Archive* or *.zip* or *.7z* or *.rar* or *\\Users\\* or *\\Shares\\*)
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:process AND agent.type:"elastic-agent" AND host.os.type:windows AND process.name:("powershell.exe" OR "7z.exe" OR "rar.exe" OR "tar.exe" OR "makecab.exe") AND process.command_line:(*Compress\-Archive* OR *.zip* OR *.7z* OR *.rar* OR *\\Users\\* OR *\\Shares\\*) | groupby host.name host.os.type user.name process.name process.parent.name destination.ip destination.port event.action | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port network.transport network.community_id event.code rule.name
```

### Query 4 — Security Onion Linux Elastic Agent
**Security Onion specific:** Uses Elastic Agent telemetry in Security Onion 3.1.0 for Linux hosts. Requires Elastic Agent endpoint, system, Windows, macOS, Linux, or Elastic Defend data streams with ECS host, process, file, registry, authentication, or network fields.

```kql
event.category:process and agent.type:"elastic-agent" and host.os.type:linux and process.name:(tar or gzip or zip or 7z) and process.command_line:(*/home/* or */root/* or */etc/* or *.ssh* or *.pem* or *.key*)
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:process AND agent.type:"elastic-agent" AND host.os.type:linux AND process.name:(tar OR gzip OR zip OR 7z) AND process.command_line:(*\/home\/* OR *\/root\/* OR *\/etc\/* OR *.ssh* OR *.pem* OR *.key*) | groupby host.name host.os.type user.name process.name process.parent.name destination.ip destination.port event.action | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line process.executable file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port destination.domain network.transport event.code rule.name
```

### Query 5 — Security Onion macOS Elastic Agent
**Security Onion specific:** Uses Elastic Agent telemetry in Security Onion 3.1.0 for macOS hosts. Requires Elastic Agent endpoint, system, Windows, macOS, Linux, or Elastic Defend data streams with ECS host, process, file, registry, authentication, or network fields.

```kql
event.category:process and agent.type:"elastic-agent" and host.os.type:macos and process.name:(zip or tar or gzip or ditto) and process.command_line:(*/Users/* or */Volumes/* or *.ssh* or *.key* or *.pem* or *.zip*)
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:process AND agent.type:"elastic-agent" AND host.os.type:macos AND process.name:(zip OR tar OR gzip OR ditto) AND process.command_line:(*\/Users\/* OR *\/Volumes\/* OR *.ssh* OR *.key* OR *.pem* OR *.zip*) | groupby host.name host.os.type user.name process.name process.parent.name destination.ip destination.port event.action | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line process.executable file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port destination.domain network.transport event.code rule.name
```

**Tuning ideas:** allowlist known admin scripts, software deployment tools, scanners, EDR activity, patch management, and sanctioned cloud apps before alerting.

---

## T1005 — Data from Local System

**Tactic:** Collection  
**Detection idea:** Bulk local data collection and staging from user/profile directories  
**Elastic implementation notes:** ECS field names vary by integration. Start with the KQL below, then tune for your Elastic Agent, Elastic Defend, Windows, System, Sysmon, cloud, and email data streams.

### Query 1
```kql
event.category:process and process.name:("robocopy.exe" or "xcopy.exe" or "powershell.exe" or "cmd.exe") and process.command_line:(*Documents* or *Desktop* or *Downloads* or *.docx* or *.xlsx* or *.pdf*)
```

### Query 2
```kql
event.category:file and event.action:(creation or modification) and file.path:(*\\\\Users\\\\Public\\\\* or *\\\\Windows\\\\Temp\\\\* or *\\\\ProgramData\\\\*) and file.extension:(zip or 7z or rar or csv or txt)
```

### Query 3 — Security Onion Linux/macOS Elastic Agent
**Security Onion specific:** Uses Elastic Agent telemetry in Security Onion 3.1.0 for Linux/macOS hosts. Requires Elastic Agent endpoint, system, or Elastic Defend data streams with ECS host, process, file, or network fields.

```kql
event.category:process and agent.type:"elastic-agent" and host.os.type:(linux or macos) and process.name:(tar or zip or gzip or ditto or find or rsync or cp or osascript or screencapture) and process.command_line:(*/Users/* or */home/* or */Documents/* or *.ssh* or *.key* or *.pem* or *.zip* or *.tar* or *.gz*)
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:process AND agent.type:"elastic-agent" AND host.os.type:(linux OR macos) AND process.name:(tar OR zip OR gzip OR ditto OR find OR rsync OR cp OR osascript OR screencapture) AND process.command_line:(*\/Users\/* OR *\/home\/* OR *\/Documents\/* OR *.ssh* OR *.key* OR *.pem* OR *.zip* OR *.tar* OR *.gz*) | groupby host.name host.os.type user.name process.name source.ip destination.ip destination.port | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line file.path file.name file.extension source.ip source.port destination.ip destination.port network.transport network.community_id rule.name
```

### Query 4 — Security Onion Linux Elastic Agent
**Security Onion specific:** Uses Elastic Agent telemetry in Security Onion 3.1.0 for Linux hosts. Requires Elastic Agent endpoint, system, Windows, macOS, Linux, or Elastic Defend data streams with ECS host, process, file, registry, authentication, or network fields.

```kql
event.category:process and agent.type:"elastic-agent" and host.os.type:linux and process.name:(cp or rsync or tar or find) and process.command_line:(*.doc* or *.xls* or *.pdf* or *.pem* or *.key* or */home/*)
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:process AND agent.type:"elastic-agent" AND host.os.type:linux AND process.name:(cp OR rsync OR tar OR find) AND process.command_line:(*.doc* OR *.xls* OR *.pdf* OR *.pem* OR *.key* OR *\/home\/*) | groupby host.name host.os.type user.name process.name process.parent.name destination.ip destination.port event.action | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line process.executable file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port destination.domain network.transport event.code rule.name
```

### Query 5 — Security Onion macOS Elastic Agent
**Security Onion specific:** Uses Elastic Agent telemetry in Security Onion 3.1.0 for macOS hosts. Requires Elastic Agent endpoint, system, Windows, macOS, Linux, or Elastic Defend data streams with ECS host, process, file, registry, authentication, or network fields.

```kql
event.category:process and agent.type:"elastic-agent" and host.os.type:macos and process.name:(find or ditto or cp or rsync or zip) and process.command_line:(*/Users/* or */Volumes/* or *.doc* or *.pdf* or *.key* or *.pem*)
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:process AND agent.type:"elastic-agent" AND host.os.type:macos AND process.name:(find OR ditto OR cp OR rsync OR zip) AND process.command_line:(*\/Users\/* OR *\/Volumes\/* OR *.doc* OR *.pdf* OR *.key* OR *.pem*) | groupby host.name host.os.type user.name process.name process.parent.name destination.ip destination.port event.action | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line process.executable file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port destination.domain network.transport event.code rule.name
```

**Tuning ideas:** allowlist known admin scripts, software deployment tools, scanners, EDR activity, patch management, and sanctioned cloud apps before alerting.

---

## T1113 — Screen Capture

**Tactic:** Collection  
**Detection idea:** Screen capture tooling or suspicious screenshot creation  
**Elastic implementation notes:** ECS field names vary by integration. Start with the KQL below, then tune for your Elastic Agent, Elastic Defend, Windows, System, Sysmon, cloud, and email data streams.

### Query 1
```kql
event.category:process and process.command_line:(*screenshot* or *screenclip* or *Graphics.CopyFromScreen* or *BitBlt* or *SnippingTool*)
```

### Query 2
```kql
event.category:file and file.extension:(png or jpg or jpeg or bmp) and file.name:(*screenshot* or *screen* or *capture*)
```

### Query 3 — Security Onion macOS Elastic Agent
**Security Onion specific:** Uses Elastic Agent telemetry in Security Onion 3.1.0 for macOS hosts. Requires Elastic Agent endpoint, system, Windows, macOS, Linux, or Elastic Defend data streams with ECS host, process, file, registry, authentication, or network fields.

```kql
event.category:process and agent.type:"elastic-agent" and host.os.type:macos and process.name:(screencapture or osascript) and process.command_line:(*.png* or *.jpg* or *screencapture* or *System\ Events*)
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:process AND agent.type:"elastic-agent" AND host.os.type:macos AND process.name:(screencapture OR osascript) AND process.command_line:(*.png* OR *.jpg* OR *screencapture* OR *System\ Events*) | groupby host.name host.os.type user.name process.name process.parent.name destination.ip destination.port event.action | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port network.transport network.community_id event.code rule.name
```

### Query 4 — Security Onion Windows Elastic Agent
**Security Onion specific:** Uses Elastic Agent telemetry in Security Onion 3.1.0 for Windows hosts. Requires Elastic Agent endpoint, system, Windows, macOS, Linux, or Elastic Defend data streams with ECS host, process, file, registry, authentication, or network fields.

```kql
event.category:process and agent.type:"elastic-agent" and host.os.type:windows and process.command_line:(*Graphics.CopyFromScreen* or *System.Drawing.Bitmap* or *screenshot* or *nircmd*\ savescreenshot* or *SnippingTool*)
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:process AND agent.type:"elastic-agent" AND host.os.type:windows AND process.command_line:(*Graphics.CopyFromScreen* OR *System.Drawing.Bitmap* OR *screenshot* OR *nircmd*\ savescreenshot* OR *SnippingTool*) | groupby host.name host.os.type user.name process.name process.parent.name destination.ip destination.port event.action | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line process.executable file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port destination.domain network.transport event.code rule.name
```

**Tuning ideas:** allowlist known admin scripts, software deployment tools, scanners, EDR activity, patch management, and sanctioned cloud apps before alerting.

---

## T1530 — Data from Cloud Storage

**Tactic:** Collection  
**Detection idea:** Bulk cloud file reads/downloads or storage enumeration  
**Elastic implementation notes:** ECS field names vary by integration. Start with the KQL below, then tune for your Elastic Agent, Elastic Defend, Windows, System, Sysmon, cloud, and email data streams.

### Query 1
```kql
event.category:file and event.type:access and cloud.provider:* and file.name:*
```

### Query 2
```kql
event.dataset:("o365.audit" or "google_workspace.drive" or "aws.cloudtrail") and event.action:(*FileDownloaded* or *FileAccessed* or *GetObject* or *ListBucket* or *download*)
```

**Tuning ideas:** allowlist known admin scripts, software deployment tools, scanners, EDR activity, patch management, and sanctioned cloud apps before alerting.

## T1115 — Clipboard Data

**Tactic:** Collection  
**Detection idea:** Clipboard access or dumping commands  
**Elastic implementation notes:** ECS field names vary by integration. Start with the KQL below, then tune for your Elastic Agent, Elastic Defend, Windows, System, Sysmon, cloud, and email data streams.

### Query 1
```kql
event.category:process and process.command_line:(*Get-Clipboard* or *Set-Clipboard* or *clip.exe* or *OpenClipboard* or *GetClipboardData*)
```

### Query 2
```kql
event.category:process and process.name:("powershell.exe" or "pwsh.exe" or "cmd.exe") and process.command_line:(*clipboard* or *clip\ \<* or *|\ clip*)
```

### Query 3 — Security Onion macOS Elastic Agent
**Security Onion specific:** Uses Elastic Agent telemetry in Security Onion 3.1.0 for macOS hosts. Requires Elastic Agent endpoint, system, Windows, macOS, Linux, or Elastic Defend data streams with ECS host, process, file, registry, authentication, or network fields.

```kql
event.category:process and agent.type:"elastic-agent" and host.os.type:macos and process.name:(pbpaste or osascript) and process.command_line:(*clipboard* or *the\ clipboard* or *pbpaste*)
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:process AND agent.type:"elastic-agent" AND host.os.type:macos AND process.name:(pbpaste OR osascript) AND process.command_line:(*clipboard* OR *the\ clipboard* OR *pbpaste*) | groupby host.name host.os.type user.name process.name process.parent.name destination.ip destination.port event.action | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line process.executable file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port destination.domain network.transport event.code rule.name
```

**Tuning ideas:** allowlist known admin scripts, software deployment tools, scanners, EDR activity, patch management, and sanctioned cloud apps before alerting.

---

## T1039 — Data from Network Shared Drive

**Tactic:** Collection  
**Detection idea:** Enumeration or copying from network shares  
**Elastic implementation notes:** ECS field names vary by integration. Start with the KQL below, then tune for your Elastic Agent, Elastic Defend, Windows, System, Sysmon, cloud, and email data streams.

### Query 1
```kql
event.category:process and process.name:("robocopy.exe" or "xcopy.exe" or "cmd.exe" or "powershell.exe" or "pwsh.exe") and process.command_line:(*\\\\*\\* or *Copy-Item* or *net\ use* or *dir\ \\\\*)
```

### Query 2
```kql
event.category:file and file.path:*\\\\* and event.action:(access or creation or modification) and file.extension:(doc or docx or xls or xlsx or pdf or txt or csv or zip)
```

### Query 3 — Security Onion Linux Elastic Agent
**Security Onion specific:** Uses Elastic Agent telemetry in Security Onion 3.1.0 for Linux hosts. Requires Elastic Agent endpoint, system, Windows, macOS, Linux, or Elastic Defend data streams with ECS host, process, file, registry, authentication, or network fields.

```kql
event.category:process and agent.type:"elastic-agent" and host.os.type:linux and process.name:(mount or smbclient or showmount or rsync or cp) and process.command_line:(*cifs* or *nfs* or *smb* or *///* or */mnt/*)
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:process AND agent.type:"elastic-agent" AND host.os.type:linux AND process.name:(mount OR smbclient OR showmount OR rsync OR cp) AND process.command_line:(*cifs* OR *nfs* OR *smb* OR *\/\/\/* OR *\/mnt\/*) | groupby host.name host.os.type user.name process.name process.parent.name destination.ip destination.port event.action | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line process.executable file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port destination.domain network.transport event.code rule.name
```

**Tuning ideas:** allowlist known admin scripts, software deployment tools, scanners, EDR activity, patch management, and sanctioned cloud apps before alerting.

---

## T1123 — Audio Capture

**Tactic:** Collection  
**Detection idea:** Audio capture tools, APIs, or suspicious recording artifacts  
**Elastic implementation notes:** ECS field names vary by integration. Start with the KQL below, then tune for your Elastic Agent, Elastic Defend, Windows, System, Sysmon, cloud, and email data streams.

### Query 1
```kql
event.category:process and process.command_line:(*SoundRecorder* or *AudioCapture* or *waveInOpen* or *NAudio* or *MediaRecorder*)
```

### Query 2
```kql
event.category:file and event.action:creation and file.extension:(wav or mp3 or m4a or wma) and file.path:(*\\\\Temp\\\\* or *\\\\AppData\\\\* or *\\\\Users\\\\Public\\\\*)
```

**Tuning ideas:** allowlist known admin scripts, software deployment tools, scanners, EDR activity, patch management, and sanctioned cloud apps before alerting.

---

## T1119 — Automated Collection

**Tactic:** Collection  
**Detection idea:** Linux Elastic Agent bulk collection of user files or sensitive directories  
**Elastic implementation notes:** Host telemetry requires Elastic Agent with endpoint, system, Windows, macOS, Linux, or Elastic Defend integrations. Field availability varies by agent policy and event collection settings.

### Query 1 — Security Onion Linux Elastic Agent
**Security Onion specific:** Uses Elastic Agent telemetry in Security Onion 3.1.0 for Linux hosts. Requires Elastic Agent endpoint, system, Windows, macOS, Linux, or Elastic Defend data streams with ECS host, process, file, registry, authentication, or network fields.

```kql
event.category:process and agent.type:"elastic-agent" and host.os.type:linux and process.name:(find or tar or rsync or cp) and process.command_line:(*/home/* or */root/* or *.doc* or *.xls* or *.pdf* or *.ssh*)
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:process AND agent.type:"elastic-agent" AND host.os.type:linux AND process.name:(find OR tar OR rsync OR cp) AND process.command_line:(*\/home\/* OR *\/root\/* OR *.doc* OR *.xls* OR *.pdf* OR *.ssh*) | groupby host.name host.os.type user.name process.name process.parent.name destination.ip destination.port event.action | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port network.transport network.community_id event.code rule.name
```


**Tuning ideas:** allowlist approved admin scripts, package managers, MDM/GPO activity, backup tools, EDR activity, deployment systems, developer workflows, and sanctioned remote administration.

---

---

## T1074 — Data Staged

**Tactic:** Collection  
**Detection idea:** Collected data copied into temporary, public, shared, or archive staging locations before exfiltration.  
**Elastic implementation notes:** These filters use ECS-style fields commonly present in Elastic Agent, Elastic Defend, Windows, Linux, macOS, Zeek, and Suricata data streams. Tune command-line patterns and administrative allowlists before production use.

### Query 1 — Security Onion Windows Elastic Agent
**Security Onion specific:** Uses Elastic Agent or Security Onion network telemetry in Security Onion 3.1.0. Requires the relevant endpoint, Zeek, Suricata, Windows, Linux, macOS, system, or Elastic Defend data streams with ECS-compatible fields.

```kql
event.category:process and agent.type:"elastic-agent" and host.os.type:windows and process.name:("robocopy.exe" or "xcopy.exe" or "powershell.exe" or "cmd.exe") and process.command_line:(*\\Users\\Public\\* or *\\Windows\\Temp\\* or *\\ProgramData\\* or *Compress-Archive* or *.zip* or *copy\ \\\\*)
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:process AND agent.type:"elastic-agent" AND host.os.type:windows AND process.name:("robocopy.exe" OR "xcopy.exe" OR "powershell.exe" OR "cmd.exe") AND process.command_line:(*\\Users\\Public\\* OR *\\Windows\\Temp\\* OR *\\ProgramData\\* OR *Compress\-Archive* OR *.zip* OR *copy\ \\\\*) | groupby host.name host.os.type user.name process.name process.parent.name event.action destination.ip destination.port | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line process.executable file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port destination.domain network.transport network.community_id event.code rule.name
```
### Query 2 — Security Onion Linux Elastic Agent
**Security Onion specific:** Uses Elastic Agent or Security Onion network telemetry in Security Onion 3.1.0. Requires the relevant endpoint, Zeek, Suricata, Windows, Linux, macOS, system, or Elastic Defend data streams with ECS-compatible fields.

```kql
event.category:process and agent.type:"elastic-agent" and host.os.type:linux and process.name:(cp or rsync or tar or zip or gzip) and process.command_line:(*/tmp/* or */var/tmp/* or */dev/shm/* or */mnt/* or *.tar* or *.zip*)
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:process AND agent.type:"elastic-agent" AND host.os.type:linux AND process.name:(cp OR rsync OR tar OR zip OR gzip) AND process.command_line:(*\/tmp\/* OR *\/var\/tmp\/* OR *\/dev\/shm\/* OR *\/mnt\/* OR *.tar* OR *.zip*) | groupby host.name host.os.type user.name process.name process.parent.name event.action destination.ip destination.port | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line process.executable file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port destination.domain network.transport network.community_id event.code rule.name
```
### Query 3 — Security Onion macOS Elastic Agent
**Security Onion specific:** Uses Elastic Agent or Security Onion network telemetry in Security Onion 3.1.0. Requires the relevant endpoint, Zeek, Suricata, Windows, Linux, macOS, system, or Elastic Defend data streams with ECS-compatible fields.

```kql
event.category:process and agent.type:"elastic-agent" and host.os.type:macos and process.name:(cp or ditto or rsync or zip or tar) and process.command_line:(*/tmp/* or */Users/Shared/* or */Volumes/* or *.zip* or *.tar* or *.dmg*)
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:process AND agent.type:"elastic-agent" AND host.os.type:macos AND process.name:(cp OR ditto OR rsync OR zip OR tar) AND process.command_line:(*\/tmp\/* OR *\/Users\/Shared\/* OR *\/Volumes\/* OR *.zip* OR *.tar* OR *.dmg*) | groupby host.name host.os.type user.name process.name process.parent.name event.action destination.ip destination.port | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line process.executable file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port destination.domain network.transport network.community_id event.code rule.name
```

**Tuning ideas:** allowlist known administrators, software deployment tools, EDR activity, inventory systems, vulnerability scanners, patching tools, and sanctioned management workflows before alerting.

---

## T1025 — Data from Removable Media

**Tactic:** Collection  
**Detection idea:** Copying or archiving data from mounted removable media and external volumes.  
**Elastic implementation notes:** These filters use ECS-style fields commonly present in Elastic Agent, Elastic Defend, Windows, Linux, macOS, Zeek, Suricata, cloud, and SaaS data streams. Tune command-line patterns, data views, and administrative allowlists before production use.

### Query 1 — Security Onion Windows Elastic Agent
**Security Onion specific:** Uses Elastic Agent or Security Onion telemetry in Security Onion 3.1.0. Requires the relevant endpoint, Zeek, Suricata, cloud, SaaS, Windows, Linux, macOS, system, or Elastic Defend data streams with ECS-compatible fields.

```kql
event.category:process and agent.type:"elastic-agent" and host.os.type:windows and process.name:("robocopy.exe" or "xcopy.exe" or "powershell.exe" or "cmd.exe") and process.command_line:(*E\:\\* or *F\:\\* or *G\:\\* or *Get-Volume* or *DriveType*Removable*)
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:process AND agent.type:"elastic-agent" AND host.os.type:windows AND process.name:("robocopy.exe" OR "xcopy.exe" OR "powershell.exe" OR "cmd.exe") AND process.command_line:(*E\:\\* OR *F\:\\* OR *G\:\\* OR *Get\-Volume* OR *DriveType*Removable*) | groupby host.name host.os.type user.name process.name process.parent.name event.action destination.ip destination.port | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line process.executable file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port destination.domain network.transport network.community_id event.code rule.name
```
### Query 2 — Security Onion Linux/macOS Elastic Agent
**Security Onion specific:** Uses Elastic Agent or Security Onion telemetry in Security Onion 3.1.0. Requires the relevant endpoint, Zeek, Suricata, cloud, SaaS, Windows, Linux, macOS, system, or Elastic Defend data streams with ECS-compatible fields.

```kql
event.category:process and agent.type:"elastic-agent" and host.os.type:(linux or macos) and process.name:(cp or rsync or tar or zip or find) and process.command_line:(*/media/* or */mnt/* or */Volumes/* or *USB* or *External*)
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:process AND agent.type:"elastic-agent" AND host.os.type:(linux OR macos) AND process.name:(cp OR rsync OR tar OR zip OR find) AND process.command_line:(*\/media\/* OR *\/mnt\/* OR *\/Volumes\/* OR *USB* OR *External*) | groupby host.name host.os.type user.name process.name process.parent.name event.action destination.ip destination.port | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line process.executable file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port destination.domain network.transport network.community_id event.code rule.name
```

**Tuning ideas:** allowlist known administrators, software deployment tools, EDR activity, backup agents, inventory systems, vulnerability scanners, patching tools, and sanctioned management workflows before alerting.

---

## T1114 — Email Collection

**Tactic:** Collection  
**Detection idea:** Mailbox export, local mail store access, or SaaS email collection behavior.  
**Elastic implementation notes:** These filters use ECS-style fields commonly present in Elastic Agent, Elastic Defend, Windows, Linux, macOS, Zeek, Suricata, cloud, and SaaS data streams. Tune command-line patterns, data views, and administrative allowlists before production use.

### Query 1 — Security Onion Office 365 / SaaS
**Security Onion specific:** Uses Elastic Agent or Security Onion telemetry in Security Onion 3.1.0. Requires the relevant endpoint, Zeek, Suricata, cloud, SaaS, Windows, Linux, macOS, system, or Elastic Defend data streams with ECS-compatible fields.

```kql
event.dataset:("o365.audit" or "google_workspace.gmail" or "google_workspace.admin") and event.action:(*MailItemsAccessed* or *SearchQueryInitiated* or *New-MailboxExportRequest* or *messages.list* or *messages.get*)
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.dataset:("o365.audit" OR "google_workspace.gmail" OR "google_workspace.admin") AND event.action:(*MailItemsAccessed* OR *SearchQueryInitiated* OR *New\-MailboxExportRequest* OR *messages.list* OR *messages.get*) | groupby host.name host.os.type user.name process.name process.parent.name event.action destination.ip destination.port | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line process.executable file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port destination.domain network.transport network.community_id event.code rule.name
```
### Query 2 — Security Onion Windows/macOS/Linux Elastic Agent
**Security Onion specific:** Uses Elastic Agent or Security Onion telemetry in Security Onion 3.1.0. Requires the relevant endpoint, Zeek, Suricata, cloud, SaaS, Windows, Linux, macOS, system, or Elastic Defend data streams with ECS-compatible fields.

```kql
event.category:file and agent.type:"elastic-agent" and file.path:(*.pst or *.ost or */Thunderbird/Profiles/* or */Library/Mail/* or */.thunderbird/*)
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:file AND agent.type:"elastic-agent" AND file.path:(*.pst OR *.ost OR *\/Thunderbird\/Profiles\/* OR *\/Library\/Mail\/* OR *\/.thunderbird\/*) | groupby host.name host.os.type user.name process.name process.parent.name event.action destination.ip destination.port | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line process.executable file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port destination.domain network.transport network.community_id event.code rule.name
```

**Tuning ideas:** allowlist known administrators, software deployment tools, EDR activity, backup agents, inventory systems, vulnerability scanners, patching tools, and sanctioned management workflows before alerting.

---

## T1125 — Video Capture

**Tactic:** Collection  
**Detection idea:** Camera/video capture utility execution or suspicious media file creation.  
**Elastic implementation notes:** These filters use ECS-style fields commonly present in Elastic Agent, Elastic Defend, Windows, Linux, macOS, Zeek, Suricata, cloud, and SaaS data streams. Tune command-line patterns, data views, and administrative allowlists before production use.

### Query 1 — Security Onion Windows Elastic Agent
**Security Onion specific:** Uses Elastic Agent or Security Onion telemetry in Security Onion 3.1.0. Requires the relevant endpoint, Zeek, Suricata, cloud, SaaS, Windows, Linux, macOS, system, or Elastic Defend data streams with ECS-compatible fields.

```kql
event.category:process and agent.type:"elastic-agent" and host.os.type:windows and process.command_line:(*webcam* or *camera* or *DirectShow* or *ffmpeg* or *avicap32*)
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:process AND agent.type:"elastic-agent" AND host.os.type:windows AND process.command_line:(*webcam* OR *camera* OR *DirectShow* OR *ffmpeg* OR *avicap32*) | groupby host.name host.os.type user.name process.name process.parent.name event.action destination.ip destination.port | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line process.executable file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port destination.domain network.transport network.community_id event.code rule.name
```
### Query 2 — Security Onion Linux/macOS Elastic Agent
**Security Onion specific:** Uses Elastic Agent or Security Onion telemetry in Security Onion 3.1.0. Requires the relevant endpoint, Zeek, Suricata, cloud, SaaS, Windows, Linux, macOS, system, or Elastic Defend data streams with ECS-compatible fields.

```kql
event.category:process and agent.type:"elastic-agent" and host.os.type:(linux or macos) and process.name:(ffmpeg or imagesnap or avfoundation or streamer) and process.command_line:(*video* or *camera* or *FaceTime* or */dev/video*)
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:process AND agent.type:"elastic-agent" AND host.os.type:(linux OR macos) AND process.name:(ffmpeg OR imagesnap OR avfoundation OR streamer) AND process.command_line:(*video* OR *camera* OR *FaceTime* OR *\/dev\/video*) | groupby host.name host.os.type user.name process.name process.parent.name event.action destination.ip destination.port | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line process.executable file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port destination.domain network.transport network.community_id event.code rule.name
```

**Tuning ideas:** allowlist known administrators, software deployment tools, EDR activity, backup agents, inventory systems, vulnerability scanners, patching tools, and sanctioned management workflows before alerting.
