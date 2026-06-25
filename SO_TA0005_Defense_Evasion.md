# TA0005 — Defense Evasion

> Query dialect: Elastic Kibana Query Language (**Elastic KQL**) using ECS-style fields. These are hunting-grade filters intended for Kibana Discover, Timeline, and Elastic Security rules. Tune fields, data views, and allowlists to your environment.

**Coverage count:** 34 technique sections / 82 KQL queries

## Techniques in this tactic

- [T1027 / T1027.010 — Obfuscated Files or Information / Command Obfuscation](SO_TA0005_Defense_Evasion.md#t1027-t1027.010-obfuscated-files-or-information-command-obfuscation) — 2 queries
- [T1218.011 — Rundll32](SO_TA0005_Defense_Evasion.md#t1218.011-rundll32) — 3 queries
- [T1218.005 — Mshta](SO_TA0005_Defense_Evasion.md#t1218.005-mshta) — 3 queries
- [T1055 / T1055.012 — Process Injection / Process Hollowing](SO_TA0005_Defense_Evasion.md#t1055-t1055.012-process-injection-process-hollowing) — 2 queries
- [T1112 — Modify Registry](SO_TA0005_Defense_Evasion.md#t1112-modify-registry) — 3 queries
- [T1685 — Disable or Modify Tools](SO_TA0005_Defense_Evasion.md#t1685-disable-or-modify-tools) — 3 queries
- [T1686 — Disable or Modify System Firewall](SO_TA0005_Defense_Evasion.md#t1686-disable-or-modify-system-firewall) — 4 queries
- [T1685.005 — Clear Windows Event Logs](SO_TA0005_Defense_Evasion.md#t1685.005-clear-windows-event-logs) — 2 queries
- [T1070.004 — File Deletion](SO_TA0005_Defense_Evasion.md#t1070.004-file-deletion) — 4 queries
- [T1078 — Valid Accounts](SO_TA0005_Defense_Evasion.md#t1078-valid-accounts) — 2 queries
- [T1140 — Deobfuscate/Decode Files or Information](SO_TA0005_Defense_Evasion.md#t1140-deobfuscatedecode-files-or-information) — 3 queries
- [T1036 — Masquerading](SO_TA0005_Defense_Evasion.md#t1036-masquerading) — 5 queries
- [T1218.010 — System Binary Proxy Execution: Regsvr32](SO_TA0005_Defense_Evasion.md#t1218.010-system-binary-proxy-execution-regsvr32) — 3 queries
- [T1218.007 — System Binary Proxy Execution: Msiexec](SO_TA0005_Defense_Evasion.md#t1218.007-system-binary-proxy-execution-msiexec) — 2 queries
- [T1553.002 — Subvert Trust Controls: Code Signing](SO_TA0005_Defense_Evasion.md#t1553.002-subvert-trust-controls-code-signing) — 3 queries
- [T1497.001 — Virtualization/Sandbox Evasion: System Checks](SO_TA0005_Defense_Evasion.md#t1497.001-virtualizationsandbox-evasion-system-checks) — 3 queries
- [T1562.003 — Impair Defenses: Impair Command History Logging](SO_TA0005_Defense_Evasion.md#t1562.003-impair-defenses-impair-command-history-logging) — 1 query
- [T1562.001 — Impair Defenses: Disable or Modify Tools](SO_TA0005_Defense_Evasion.md#t1562.001-impair-defenses-disable-or-modify-tools) — 2 queries
- [T1070.002 — Clear Command History](SO_TA0005_Defense_Evasion.md#t1070.002-clear-command-history) — 1 query
- [T1553.001 — Subvert Trust Controls: Gatekeeper Bypass](SO_TA0005_Defense_Evasion.md#t1553.001-subvert-trust-controls-gatekeeper-bypass) — 1 query
- [T1027 — Obfuscated Files or Information](SO_TA0005_Defense_Evasion.md#t1027-obfuscated-files-or-information) — 1 query
- [T1564.001 — Hide Artifacts: Hidden Files and Directories](SO_TA0005_Defense_Evasion.md#t1564.001-hide-artifacts-hidden-files-and-directories) — 2 queries
- [T1070.003 — Clear Command History](SO_TA0005_Defense_Evasion.md#t1070.003-clear-command-history) — 1 query
- [T1647 — Plist File Modification](SO_TA0005_Defense_Evasion.md#t1647-plist-file-modification) — 3 queries
- [T1197 — BITS Jobs](SO_TA0005_Defense_Evasion.md#t1197-bits-jobs) — 3 queries
- [T1222 — File and Directory Permissions Modification](SO_TA0005_Defense_Evasion.md#t1222-file-and-directory-permissions-modification) — 3 queries
- [T1690 — Prevent Command History Logging](SO_TA0005_Defense_Evasion.md#t1690-prevent-command-history-logging) — 3 queries
- [T1027.013 — Obfuscated Files or Information: Encrypted/Encoded File](SO_TA0005_Defense_Evasion.md#t1027.013-obfuscated-files-or-information-encryptedencoded-file) — 2 queries
- [T1036.007 — Masquerading: Double File Extension](SO_TA0005_Defense_Evasion.md#t1036.007-masquerading-double-file-extension) — 2 queries
- [T1036.008 — Masquerading: Masquerade File Type](SO_TA0005_Defense_Evasion.md#t1036.008-masquerading-masquerade-file-type) — 2 queries
- [T1564.008 — Hide Artifacts: Email Hiding Rules](SO_TA0005_Defense_Evasion.md#t1564.008-hide-artifacts-email-hiding-rules) — 2 queries
- [T1574.001 — Hijack Execution Flow: DLL](SO_TA0005_Defense_Evasion.md#t1574.001-hijack-execution-flow-dll) — 2 queries
- [T1574.007 — Hijack Execution Flow: PATH Environment Variable](SO_TA0005_Defense_Evasion.md#t1574.007-hijack-execution-flow-path-environment-variable) — 2 queries
- [T1574.011 — Hijack Execution Flow: Services Registry Permissions Weakness](SO_TA0005_Defense_Evasion.md#t1574.011-hijack-execution-flow-services-registry-permissions-weakness) — 2 queries

---

## T1027 / T1027.010 — Obfuscated Files or Information / Command Obfuscation

**Tactic:** Defense Evasion  
**Detection idea:** Encoded commands, carets, string concatenation, and suspicious script obfuscation  
**Elastic implementation notes:** ECS field names vary by integration. Start with the KQL below, then tune for your Elastic Agent, Elastic Defend, Windows, System, Sysmon, cloud, and email data streams.

### Query 1
```kql
event.category:process and process.command_line:(*FromBase64String* or *-EncodedCommand* or *-enc* or *JAB* or *SQBFAFg* or *powershell\ -e*)
```

### Query 2
```kql
event.category:process and process.name:("cmd.exe" or "powershell.exe" or "pwsh.exe") and process.command_line:(*^^* or *``* or *%COMSPEC%* or *${env\:* or *char* or *replace\(* or *join\(*)
```

**Tuning ideas:** allowlist known admin scripts, software deployment tools, scanners, EDR activity, patch management, and sanctioned cloud apps before alerting. Treat short encoded-content fragments such as `JAB` and `SQBFAFg` as hunting pivots, not standalone blocking criteria; pair them with interpreter ancestry, encoded-command switches, unusual parent processes, or network/file activity for alerting.

---

## T1218.011 — Rundll32

**Tactic:** Defense Evasion  
**Detection idea:** Rundll32 scriptlet/proxy execution and network retrieval  
**Elastic implementation notes:** ECS field names vary by integration. Start with the KQL below, then tune for your Elastic Agent, Elastic Defend, Windows, System, Sysmon, cloud, and email data streams.

### Query 1
```kql
event.category:process and process.name:"rundll32.exe" and process.command_line:(*javascript\:* or *vbscript\:* or *url.dll,FileProtocolHandler* or *mshtml* or *scrobj.dll* or *shell32.dll,ShellExec_RunDLL*)
```

### Query 2
```kql
event.category:network and process.name:"rundll32.exe"
```

### Query 3 — Security Onion Windows Elastic Agent
**Security Onion specific:** Uses Elastic Agent telemetry in Security Onion 3.1.0 for Windows hosts. Requires Elastic Agent endpoint, system, Windows, macOS, Linux, or Elastic Defend data streams with ECS host, process, file, registry, authentication, or network fields.

```kql
event.category:process and agent.type:"elastic-agent" and host.os.type:windows and process.name:"rundll32.exe" and process.command_line:(*http* or *javascript\:* or *url.dll* or *mshtml* or *RunHTMLApplication* or *,#*)
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:process AND agent.type:"elastic-agent" AND host.os.type:windows AND process.name:"rundll32.exe" AND process.command_line:(*http* OR *javascript\:* OR *url.dll* OR *mshtml* OR *RunHTMLApplication* OR *,#*) | groupby host.name host.os.type user.name process.name process.parent.name destination.ip destination.port event.action | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port network.transport network.community_id event.code rule.name
```

**Tuning ideas:** allowlist known admin scripts, software deployment tools, scanners, EDR activity, patch management, and sanctioned cloud apps before alerting.

---

## T1218.005 — Mshta

**Tactic:** Defense Evasion  
**Detection idea:** Mshta executing remote or inline script content  
**Elastic implementation notes:** ECS field names vary by integration. Start with the KQL below, then tune for your Elastic Agent, Elastic Defend, Windows, System, Sysmon, cloud, and email data streams.

### Query 1
```kql
event.category:process and process.name:"mshta.exe" and process.command_line:(*http\://* or *https\://* or *javascript\:* or *vbscript\:* or *about\:* or *.hta*)
```

### Query 2
```kql
event.category:process and process.parent.name:("winword.exe" or "excel.exe" or "powerpnt.exe" or "outlook.exe") and process.name:"mshta.exe"
```

### Query 3 — Security Onion Windows Elastic Agent
**Security Onion specific:** Uses Elastic Agent telemetry in Security Onion 3.1.0 for Windows hosts. Requires Elastic Agent endpoint, system, Windows, macOS, Linux, or Elastic Defend data streams with ECS host, process, file, registry, authentication, or network fields.

```kql
event.category:process and agent.type:"elastic-agent" and host.os.type:windows and process.name:"mshta.exe" and (process.command_line:(*http* or *vbscript\:* or *javascript\:* or *.hta*) or process.parent.name:("winword.exe" or "excel.exe" or "outlook.exe"))
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:process AND agent.type:"elastic-agent" AND host.os.type:windows AND process.name:"mshta.exe" AND (process.command_line:(*http* OR *vbscript\:* OR *javascript\:* OR *.hta*) OR process.parent.name:("winword.exe" OR "excel.exe" OR "outlook.exe")) | groupby host.name host.os.type user.name process.name process.parent.name destination.ip destination.port event.action | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port network.transport network.community_id event.code rule.name
```

**Tuning ideas:** allowlist known admin scripts, software deployment tools, scanners, EDR activity, patch management, and sanctioned cloud apps before alerting.

---

## T1055 / T1055.012 — Process Injection / Process Hollowing

**Tactic:** Defense Evasion  
**Detection idea:** Suspicious process access, injection APIs, and anomalous child processes  
**Elastic implementation notes:** ECS field names vary by integration. Start with the KQL below, then tune for your Elastic Agent, Elastic Defend, Windows, System, Sysmon, cloud, and email data streams.

### Query 1
```kql
event.category:process and process.name:("rundll32.exe" or "regsvr32.exe" or "powershell.exe" or "msbuild.exe") and process.parent.name:("explorer.exe" or "winword.exe" or "excel.exe" or "outlook.exe") and process.command_line:(*VirtualAlloc* or *WriteProcessMemory* or *CreateRemoteThread* or *QueueUserAPC*)
```

### Query 2
```kql
event.category:process and process.parent.name:("svchost.exe" or "lsass.exe" or "spoolsv.exe" or "services.exe") and process.name:("cmd.exe" or "powershell.exe" or "pwsh.exe" or "rundll32.exe")
```

**Tuning ideas:** allowlist known admin scripts, software deployment tools, scanners, EDR activity, patch management, and sanctioned cloud apps before alerting.

---

## T1112 — Modify Registry

**Tactic:** Defense Evasion  
**Detection idea:** Registry changes associated with security weakening, persistence, and policy tampering  
**Elastic implementation notes:** ECS field names vary by integration. Start with the KQL below, then tune for your Elastic Agent, Elastic Defend, Windows, System, Sysmon, cloud, and email data streams.

### Query 1
```kql
event.category:process and process.name:"reg.exe" and process.command_line:(*add* or *delete*) and process.command_line:(*DisableAntiSpyware* or *DisableRealtimeMonitoring* or *EnableLUA* or *Run* or *Services*)
```

### Query 2
```kql
event.category:registry and registry.path:(*\\\\Policies\\\\Microsoft\\\\Windows\ Defender* or *\\\\CurrentVersion\\\\Run* or *\\\\CurrentControlSet\\\\Services*)
```

### Query 3 — Security Onion Windows Elastic Agent
**Security Onion specific:** Uses Elastic Agent telemetry in Security Onion 3.1.0 for Windows hosts. Requires Elastic Agent endpoint, system, Windows, macOS, Linux, or Elastic Defend data streams with ECS host, process, file, registry, authentication, or network fields.

```kql
event.category:process and agent.type:"elastic-agent" and host.os.type:windows and process.name:"reg.exe" and process.command_line:(*add* or *delete*) and process.command_line:(*DisableAntiSpyware* or *DisableRealtimeMonitoring* or *Run\\* or *Image\ File\ Execution\ Options* or *AppInit_DLLs*)
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:process AND agent.type:"elastic-agent" AND host.os.type:windows AND process.name:"reg.exe" AND process.command_line:(*add* OR *delete*) AND process.command_line:(*DisableAntiSpyware* OR *DisableRealtimeMonitoring* OR *Run\\* OR *Image\ File\ Execution\ Options* OR *AppInit_DLLs*) | groupby host.name host.os.type user.name process.name process.parent.name destination.ip destination.port event.action | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line process.executable file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port destination.domain network.transport event.code rule.name
```

**Tuning ideas:** allowlist known admin scripts, software deployment tools, scanners, EDR activity, patch management, and sanctioned cloud apps before alerting.

---

## T1685 — Disable or Modify Tools

**Tactic:** Defense Evasion  
**Detection idea:** Attempts to disable EDR, AV, logging, or security tooling  
**Elastic implementation notes:** ECS field names vary by integration. Start with the KQL below, then tune for your Elastic Agent, Elastic Defend, Windows, System, Sysmon, cloud, and email data streams.

### Query 1
```kql
event.category:process and process.command_line:(*Set-MpPreference* or *DisableRealtimeMonitoring* or *Add-MpPreference* or *ExclusionPath* or *ExclusionProcess* or *tamper* or *Defender*)
```

### Query 2
```kql
event.category:process and process.name:("net.exe" or "sc.exe" or "powershell.exe" or "taskkill.exe") and process.command_line:(*stop* or *disable* or */IM*) and process.command_line:(*Defender* or *Sense* or *CrowdStrike* or *csagent* or *elastic-agent* or *osqueryd* or *sysmon*)
```

### Query 3 — Security Onion Linux/macOS Elastic Agent
**Security Onion specific:** Uses Elastic Agent telemetry in Security Onion 3.1.0 for Linux/macOS hosts. Requires Elastic Agent endpoint, system, or Elastic Defend data streams with ECS host, process, file, or network fields.

```kql
event.category:process and agent.type:"elastic-agent" and host.os.type:(linux or macos) and process.name:(systemctl or service or launchctl or pkill or killall or elastic-agent) and process.command_line:(*stop\ auditd* or *disable\ auditd* or *unload*com.elastic* or *elastic-agent* or *auditbeat* or *osquery* or *falcon* or *defender* or *mdatp*)
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:process AND agent.type:"elastic-agent" AND host.os.type:(linux OR macos) AND process.name:(systemctl OR service OR launchctl OR pkill OR killall OR elastic-agent) AND process.command_line:(*stop\ auditd* OR *disable\ auditd* OR *unload*com.elastic* OR *elastic\-agent* OR *auditbeat* OR *osquery* OR *falcon* OR *defender* OR *mdatp*) | groupby host.name host.os.type user.name process.name source.ip destination.ip destination.port | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line file.path file.name file.extension source.ip source.port destination.ip destination.port network.transport network.community_id rule.name
```

**Tuning ideas:** allowlist known admin scripts, software deployment tools, scanners, EDR activity, patch management, and sanctioned cloud apps before alerting.

---

## T1686 — Disable or Modify System Firewall

**Tactic:** Defense Evasion  
**Detection idea:** Firewall disabling or rule manipulation  
**Elastic implementation notes:** ECS field names vary by integration. Start with the KQL below, then tune for your Elastic Agent, Elastic Defend, Windows, System, Sysmon, cloud, and email data streams.

### Query 1
```kql
event.category:process and process.command_line:(*netsh\ advfirewall\ set* or *Set-NetFirewallProfile* or *New-NetFirewallRule* or *Remove-NetFirewallRule*) and process.command_line:(*off* or *allow* or *disable*)
```

### Query 2
```kql
event.category:registry and registry.path:*\\\\System\\\\CurrentControlSet\\\\Services\\\\SharedAccess\\\\Parameters\\\\FirewallPolicy\\\\* and registry.value:(EnableFirewall or DoNotAllowExceptions)
```

### Query 3 — Security Onion Windows Elastic Agent
**Security Onion specific:** Uses Elastic Agent telemetry in Security Onion 3.1.0 for Windows hosts. Requires Elastic Agent endpoint, system, Windows, macOS, Linux, or Elastic Defend data streams with ECS host, process, file, registry, authentication, or network fields.

```kql
event.category:process and agent.type:"elastic-agent" and host.os.type:windows and process.name:("netsh.exe" or "powershell.exe" or "pwsh.exe") and process.command_line:(*advfirewall\ set*off* or *Set-NetFirewallProfile*False* or *New-NetFirewallRule* or *Disable-NetFirewallRule*)
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:process AND agent.type:"elastic-agent" AND host.os.type:windows AND process.name:("netsh.exe" OR "powershell.exe" OR "pwsh.exe") AND process.command_line:(*advfirewall\ set*off* OR *Set\-NetFirewallProfile*False* OR *New\-NetFirewallRule* OR *Disable\-NetFirewallRule*) | groupby host.name host.os.type user.name process.name process.parent.name destination.ip destination.port event.action | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line process.executable file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port destination.domain network.transport event.code rule.name
```

### Query 4 — Security Onion Linux Elastic Agent
**Security Onion specific:** Uses Elastic Agent telemetry in Security Onion 3.1.0 for Linux hosts. Requires Elastic Agent endpoint, system, Windows, macOS, Linux, or Elastic Defend data streams with ECS host, process, file, registry, authentication, or network fields.

```kql
event.category:process and agent.type:"elastic-agent" and host.os.type:linux and process.name:(iptables or nft or ufw or firewall-cmd or systemctl) and process.command_line:(*\ -F* or *flush* or *disable* or *stop\ firewalld* or *ufw\ disable*)
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:process AND agent.type:"elastic-agent" AND host.os.type:linux AND process.name:(iptables OR nft OR ufw OR firewall-cmd OR systemctl) AND process.command_line:(*\ \-F* OR *flush* OR *disable* OR *stop\ firewalld* OR *ufw\ disable*) | groupby host.name host.os.type user.name process.name process.parent.name destination.ip destination.port event.action | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line process.executable file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port destination.domain network.transport event.code rule.name
```

**Tuning ideas:** allowlist known admin scripts, software deployment tools, scanners, EDR activity, patch management, and sanctioned cloud apps before alerting.

---

## T1685.005 — Clear Windows Event Logs

**Tactic:** Defense Evasion  
**Detection idea:** Windows event log clearing  
**Elastic implementation notes:** ECS field names vary by integration. Start with the KQL below, then tune for your Elastic Agent, Elastic Defend, Windows, System, Sysmon, cloud, and email data streams.

### Query 1
```kql
event.category:process and process.name:("wevtutil.exe" or "powershell.exe" or "pwsh.exe") and process.command_line:(*cl\ * or *clear-log* or *Clear-EventLog*)
```

### Query 2
```kql
event.provider:"Microsoft-Windows-Eventlog" and event.code:1102
```

**Tuning ideas:** allowlist known admin scripts, software deployment tools, scanners, EDR activity, patch management, and sanctioned cloud apps before alerting.

---

## T1070.004 — File Deletion

**Tactic:** Defense Evasion  
**Detection idea:** Mass or targeted deletion of logs, backups, and staged tools  
**Elastic implementation notes:** ECS field names vary by integration. Start with the KQL below, then tune for your Elastic Agent, Elastic Defend, Windows, System, Sysmon, cloud, and email data streams.

### Query 1
```kql
event.category:process and process.name:("cmd.exe" or "powershell.exe" or "pwsh.exe" or "del.exe" or "erase.exe") and process.command_line:(*del\ /f* or *del\ /q* or *Remove-Item* or *rm\ -rf*) and process.command_line:(*.log* or *.evtx* or *Temp* or *AppData*)
```

### Query 2
```kql
event.category:file and event.action:deletion and file.extension:(exe or dll or ps1 or bat or vbs or js or evtx or log) and file.path:(*\\\\AppData\\\\Local\\\\Temp\\\\* or *\\\\Windows\\\\Temp\\\\* or *\\\\Users\\\\Public\\\\*)
```

### Query 3 — Security Onion Linux Elastic Agent
**Security Onion specific:** Uses Elastic Agent telemetry in Security Onion 3.1.0 for Linux hosts. Requires Elastic Agent endpoint, system, Windows, macOS, Linux, or Elastic Defend data streams with ECS host, process, file, registry, authentication, or network fields.

```kql
event.category:process and agent.type:"elastic-agent" and host.os.type:linux and process.name:(rm or shred or truncate or bash or sh) and process.command_line:(*/var/log/* or *.bash_history* or *history\ -c* or *journalctl\ --vacuum* or *truncate\ -s\ 0*)
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:process AND agent.type:"elastic-agent" AND host.os.type:linux AND process.name:(rm OR shred OR truncate OR bash OR sh) AND process.command_line:(*\/var\/log\/* OR *.bash_history* OR *history\ \-c* OR *journalctl\ \-\-vacuum* OR *truncate\ \-s\ 0*) | groupby host.name host.os.type user.name process.name process.parent.name destination.ip destination.port event.action | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port network.transport network.community_id event.code rule.name
```

### Query 4 — Security Onion macOS Elastic Agent
**Security Onion specific:** Uses Elastic Agent telemetry in Security Onion 3.1.0 for macOS hosts. Requires Elastic Agent endpoint, system, Windows, macOS, Linux, or Elastic Defend data streams with ECS host, process, file, registry, authentication, or network fields.

```kql
event.category:process and agent.type:"elastic-agent" and host.os.type:macos and process.name:(rm or srm or log or xattr) and process.command_line:(*/var/log/* or *.zsh_history* or *com.apple.quarantine* or *erase* or *delete*)
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:process AND agent.type:"elastic-agent" AND host.os.type:macos AND process.name:(rm OR srm OR log OR xattr) AND process.command_line:(*\/var\/log\/* OR *.zsh_history* OR *com.apple.quarantine* OR *erase* OR *delete*) | groupby host.name host.os.type user.name process.name process.parent.name destination.ip destination.port event.action | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line process.executable file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port destination.domain network.transport event.code rule.name
```

**Tuning ideas:** allowlist known admin scripts, software deployment tools, scanners, EDR activity, patch management, and sanctioned cloud apps before alerting.

---

## T1078 — Valid Accounts

**Tactic:** Defense Evasion / Persistence  
**Detection idea:** Successful logons from unusual sources, service accounts, or non-standard hosts  
**Elastic implementation notes:** ECS field names vary by integration. Start with the KQL below, then tune for your Elastic Agent, Elastic Defend, Windows, System, Sysmon, cloud, and email data streams.

### Query 1
```kql
event.category:authentication and event.outcome:success and user.name:* and source.ip:*
```

### Query 2
```kql
event.dataset:("windows.security" or "azure.signinlogs" or "o365.audit") and event.outcome:success and user.name:(*svc* or *admin* or *adm*)
```

**Tuning ideas:** allowlist known admin scripts, software deployment tools, scanners, EDR activity, patch management, and sanctioned cloud apps before alerting.

---

## T1140 — Deobfuscate/Decode Files or Information

**Tactic:** Defense Evasion  
**Detection idea:** Decoding, unpacking, or certificate utility activity used before execution  
**Elastic implementation notes:** ECS field names vary by integration. Start with the KQL below, then tune for your Elastic Agent, Elastic Defend, Windows, System, Sysmon, cloud, and email data streams.

### Query 1
```kql
event.category:process and process.name:("certutil.exe" or "powershell.exe" or "pwsh.exe") and process.command_line:(*-decode* or *FromBase64String* or *base64* or *Expand-Archive* or *gzip* or *DeflateStream*)
```

### Query 2
```kql
event.category:process and process.command_line:(*Invoke-Expression* or *IEX* or *WriteAllBytes* or *Reflection.Assembly* or *LoadWithPartialName*)
```

### Query 3 — Security Onion Windows Elastic Agent
**Security Onion specific:** Uses Elastic Agent telemetry in Security Onion 3.1.0 for Windows hosts. Requires Elastic Agent endpoint, system, Windows, macOS, Linux, or Elastic Defend data streams with ECS host, process, file, registry, authentication, or network fields.

```kql
event.category:process and agent.type:"elastic-agent" and host.os.type:windows and process.name:("certutil.exe" or "powershell.exe" or "pwsh.exe" or "cmd.exe") and process.command_line:(*-decode* or *-urlcache* or *FromBase64String* or *base64* or *certutil*\ -decode*)
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:process AND agent.type:"elastic-agent" AND host.os.type:windows AND process.name:("certutil.exe" OR "powershell.exe" OR "pwsh.exe" OR "cmd.exe") AND process.command_line:(*\-decode* OR *\-urlcache* OR *FromBase64String* OR *base64* OR *certutil*\ \-decode*) | groupby host.name host.os.type user.name process.name process.parent.name destination.ip destination.port event.action | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line process.executable file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port destination.domain network.transport event.code rule.name
```

**Tuning ideas:** allowlist known admin scripts, software deployment tools, scanners, EDR activity, patch management, and sanctioned cloud apps before alerting.

---

## T1036 — Masquerading

**Tactic:** Defense Evasion  
**Detection idea:** Suspicious process names or binaries launched from unexpected paths  
**Elastic implementation notes:** ECS field names vary by integration. Start with the KQL below, then tune for your Elastic Agent, Elastic Defend, Windows, System, Sysmon, cloud, and email data streams.

### Query 1
```kql
event.category:process and process.name:("svchost.exe" or "lsass.exe" or "csrss.exe" or "services.exe" or "spoolsv.exe") and not process.executable:(C\:\\Windows\\System32\\* or C\:\\Windows\\SysWOW64\\*)
```

### Query 2
```kql
event.category:file and file.name:("svchost.exe" or "lsass.exe" or "csrss.exe" or "services.exe") and file.path:(*\\\\AppData\\\\* or *\\\\Temp\\\\* or *\\\\Users\\\\Public\\\\* or *\\\\ProgramData\\\\*)
```

### Query 3 — Security Onion Windows Elastic Agent
**Security Onion specific:** Uses Elastic Agent telemetry in Security Onion 3.1.0 for Windows hosts. Requires Elastic Agent endpoint, system, Windows, macOS, Linux, or Elastic Defend data streams with ECS host, process, file, registry, authentication, or network fields.

```kql
event.category:process and agent.type:"elastic-agent" and host.os.type:windows and process.name:("svchost.exe" or "lsass.exe" or "csrss.exe" or "services.exe" or "spoolsv.exe") and process.executable:(*\\Users\\* or *\\AppData\\* or *\\Temp\\* or *\\ProgramData\\*)
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:process AND agent.type:"elastic-agent" AND host.os.type:windows AND process.name:("svchost.exe" OR "lsass.exe" OR "csrss.exe" OR "services.exe" OR "spoolsv.exe") AND process.executable:(*\\Users\\* OR *\\AppData\\* OR *\\Temp\\* OR *\\ProgramData\\*) | groupby host.name host.os.type user.name process.name process.parent.name destination.ip destination.port event.action | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line process.executable file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port destination.domain network.transport event.code rule.name
```

### Query 4 — Security Onion Linux Elastic Agent
**Security Onion specific:** Uses Elastic Agent telemetry in Security Onion 3.1.0 for Linux hosts. Requires Elastic Agent endpoint, system, Windows, macOS, Linux, or Elastic Defend data streams with ECS host, process, file, registry, authentication, or network fields.

```kql
event.category:process and agent.type:"elastic-agent" and host.os.type:linux and process.name:(sshd or cron or systemd or kworker or dbus-daemon) and process.executable:(/tmp/* or /var/tmp/* or /dev/shm/* or /home/*)
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:process AND agent.type:"elastic-agent" AND host.os.type:linux AND process.name:(sshd OR cron OR systemd OR kworker OR dbus-daemon) AND process.executable:(\/tmp\/* OR \/var\/tmp\/* OR \/dev\/shm\/* OR \/home\/*) | groupby host.name host.os.type user.name process.name process.parent.name destination.ip destination.port event.action | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line process.executable file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port destination.domain network.transport event.code rule.name
```

### Query 5 — Security Onion macOS Elastic Agent
**Security Onion specific:** Uses Elastic Agent telemetry in Security Onion 3.1.0 for macOS hosts. Requires Elastic Agent endpoint, system, Windows, macOS, Linux, or Elastic Defend data streams with ECS host, process, file, registry, authentication, or network fields.

```kql
event.category:process and agent.type:"elastic-agent" and host.os.type:macos and process.name:(launchd or syslogd or mdworker or trustd or distnoted) and process.executable:(/tmp/* or /Users/Shared/* or /Users/*/Downloads/*)
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:process AND agent.type:"elastic-agent" AND host.os.type:macos AND process.name:(launchd OR syslogd OR mdworker OR trustd OR distnoted) AND process.executable:(\/tmp\/* OR \/Users\/Shared\/* OR \/Users\/*\/Downloads\/*) | groupby host.name host.os.type user.name process.name process.parent.name destination.ip destination.port event.action | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line process.executable file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port destination.domain network.transport event.code rule.name
```

**Tuning ideas:** allowlist known admin scripts, software deployment tools, scanners, EDR activity, patch management, and sanctioned cloud apps before alerting.

---

## T1218.010 — System Binary Proxy Execution: Regsvr32

**Tactic:** Defense Evasion  
**Detection idea:** Regsvr32 scriptlet or remote COM script execution  
**Elastic implementation notes:** ECS field names vary by integration. Start with the KQL below, then tune for your Elastic Agent, Elastic Defend, Windows, System, Sysmon, cloud, and email data streams.

### Query 1
```kql
event.category:process and process.name:"regsvr32.exe" and process.command_line:(*/s* or */u* or */i\:* or *scrobj.dll* or *http\://* or *https\://*)
```

### Query 2
```kql
event.category:network and process.name:"regsvr32.exe" and destination.ip:*
```

### Query 3 — Security Onion Windows Elastic Agent
**Security Onion specific:** Uses Elastic Agent telemetry in Security Onion 3.1.0 for Windows hosts. Requires Elastic Agent endpoint, system, Windows, macOS, Linux, or Elastic Defend data streams with ECS host, process, file, registry, authentication, or network fields.

```kql
event.category:process and agent.type:"elastic-agent" and host.os.type:windows and process.name:"regsvr32.exe" and process.command_line:(*/s* or */u* or */i\:http* or *.sct* or *scrobj.dll*)
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:process AND agent.type:"elastic-agent" AND host.os.type:windows AND process.name:"regsvr32.exe" AND process.command_line:(*\/s* OR *\/u* OR *\/i\:http* OR *.sct* OR *scrobj.dll*) | groupby host.name host.os.type user.name process.name process.parent.name destination.ip destination.port event.action | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port network.transport network.community_id event.code rule.name
```

**Tuning ideas:** allowlist known admin scripts, software deployment tools, scanners, EDR activity, patch management, and sanctioned cloud apps before alerting.

---

## T1218.007 — System Binary Proxy Execution: Msiexec

**Tactic:** Defense Evasion  
**Detection idea:** Msiexec installing remote packages or spawning suspicious children  
**Elastic implementation notes:** ECS field names vary by integration. Start with the KQL below, then tune for your Elastic Agent, Elastic Defend, Windows, System, Sysmon, cloud, and email data streams.

### Query 1
```kql
event.category:process and process.name:"msiexec.exe" and process.command_line:(*http\://* or *https\://* or */i* or */quiet* or */qn*)
```

### Query 2
```kql
event.category:process and process.parent.name:"msiexec.exe" and process.name:("cmd.exe" or "powershell.exe" or "pwsh.exe" or "rundll32.exe" or "regsvr32.exe")
```

**Tuning ideas:** allowlist known admin scripts, software deployment tools, scanners, EDR activity, patch management, and sanctioned cloud apps before alerting.

---

## T1553.002 — Subvert Trust Controls: Code Signing

**Tactic:** Defense Evasion  
**Detection idea:** Suspicious signed binary execution or signature verification bypass indicators  
**Elastic implementation notes:** ECS field names vary by integration. Start with the KQL below, then tune for your Elastic Agent, Elastic Defend, Windows, System, Sysmon, cloud, and email data streams.

### Query 1
```kql
event.category:process and process.name:("signtool.exe" or "powershell.exe" or "pwsh.exe") and process.command_line:(*sign* or *Set-AuthenticodeSignature* or *Get-AuthenticodeSignature* or *-ExecutionPolicy\ Bypass*)
```

### Query 2
```kql
event.category:process and process.code_signature.trusted:false and process.executable:(*\\\\AppData\\\\* or *\\\\Temp\\\\* or *\\\\Users\\\\Public\\\\*)
```

### Query 3 — Security Onion Windows Elastic Agent
**Security Onion specific:** Uses Elastic Agent telemetry in Security Onion 3.1.0 for Windows hosts. Requires Elastic Agent endpoint, system, Windows, macOS, Linux, or Elastic Defend data streams with ECS host, process, file, registry, authentication, or network fields.

```kql
event.category:process and agent.type:"elastic-agent" and host.os.type:windows and process.executable:(*\\Users\\* or *\\AppData\\* or *\\Temp\\*) and process.code_signature.trusted:false
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:process AND agent.type:"elastic-agent" AND host.os.type:windows AND process.executable:(*\\Users\\* OR *\\AppData\\* OR *\\Temp\\*) AND process.code_signature.trusted:false | groupby host.name host.os.type user.name process.name process.parent.name destination.ip destination.port event.action | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line process.executable file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port destination.domain network.transport event.code rule.name
```

**Tuning ideas:** allowlist known admin scripts, software deployment tools, scanners, EDR activity, patch management, and sanctioned cloud apps before alerting.

---

## T1497.001 — Virtualization/Sandbox Evasion: System Checks

**Tactic:** Defense Evasion  
**Detection idea:** Environment and sandbox discovery checks before payload execution  
**Elastic implementation notes:** ECS field names vary by integration. Start with the KQL below, then tune for your Elastic Agent, Elastic Defend, Windows, System, Sysmon, cloud, and email data streams.

### Query 1
```kql
event.category:process and process.command_line:(*vbox* or *vmware* or *qemu* or *sandbox* or *wireshark* or *procmon* or *Get-WmiObject\ Win32_ComputerSystem*)
```

### Query 2
```kql
event.category:process and process.name:("wmic.exe" or "powershell.exe" or "pwsh.exe" or "systeminfo.exe") and process.command_line:(*Win32_BIOS* or *Win32_ComputerSystem* or *VirtualBox* or *VMware*)
```

### Query 3 — Security Onion Windows Elastic Agent
**Security Onion specific:** Uses Elastic Agent telemetry in Security Onion 3.1.0 for Windows hosts. Requires Elastic Agent endpoint, system, Windows, macOS, Linux, or Elastic Defend data streams with ECS host, process, file, registry, authentication, or network fields.

```kql
event.category:process and agent.type:"elastic-agent" and host.os.type:windows and process.command_line:(*vbox* or *vmware* or *qemu* or *VirtualBox* or *Get-WmiObject\ Win32_ComputerSystem* or *wmic\ computersystem*)
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:process AND agent.type:"elastic-agent" AND host.os.type:windows AND process.command_line:(*vbox* OR *vmware* OR *qemu* OR *VirtualBox* OR *Get\-WmiObject\ Win32_ComputerSystem* OR *wmic\ computersystem*) | groupby host.name host.os.type user.name process.name process.parent.name destination.ip destination.port event.action | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line process.executable file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port destination.domain network.transport event.code rule.name
```

**Tuning ideas:** allowlist known admin scripts, software deployment tools, scanners, EDR activity, patch management, and sanctioned cloud apps before alerting.

---

## T1562.003 — Impair Defenses: Impair Command History Logging

**Tactic:** Defense Evasion  
**Detection idea:** Linux Elastic Agent shell history suppression or redirection  
**Elastic implementation notes:** Host telemetry requires Elastic Agent with endpoint, system, Windows, macOS, Linux, or Elastic Defend integrations. Field availability varies by agent policy and event collection settings.

### Query 1 — Security Onion Linux Elastic Agent
**Security Onion specific:** Uses Elastic Agent telemetry in Security Onion 3.1.0 for Linux hosts. Requires Elastic Agent endpoint, system, Windows, macOS, Linux, or Elastic Defend data streams with ECS host, process, file, registry, authentication, or network fields.

```kql
event.category:process and agent.type:"elastic-agent" and host.os.type:linux and process.command_line:(*unset\ HISTFILE* or *HISTFILE=/dev/null* or *set\ +o\ history* or *export\ HISTSIZE=0*)
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:process AND agent.type:"elastic-agent" AND host.os.type:linux AND process.command_line:(*unset\ HISTFILE* OR *HISTFILE=\/dev\/null* OR *set\ \+o\ history* OR *export\ HISTSIZE=0*) | groupby host.name host.os.type user.name process.name process.parent.name destination.ip destination.port event.action | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port network.transport network.community_id event.code rule.name
```


**Tuning ideas:** allowlist approved admin scripts, package managers, MDM/GPO activity, backup tools, EDR activity, deployment systems, developer workflows, and sanctioned remote administration.

---

## T1562.001 — Impair Defenses: Disable or Modify Tools

**Tactic:** Defense Evasion  
**Detection idea:** macOS Elastic Agent attempts to disable security tools, Gatekeeper, firewall, or telemetry  
**Elastic implementation notes:** Host telemetry requires Elastic Agent with endpoint, system, Windows, macOS, Linux, or Elastic Defend integrations. Field availability varies by agent policy and event collection settings.

### Query 1 — Security Onion macOS Elastic Agent
**Security Onion specific:** Uses Elastic Agent telemetry in Security Onion 3.1.0 for macOS hosts. Requires Elastic Agent endpoint, system, Windows, macOS, Linux, or Elastic Defend data streams with ECS host, process, file, registry, authentication, or network fields.

```kql
event.category:process and agent.type:"elastic-agent" and host.os.type:macos and process.name:(spctl or launchctl or defaults or pfctl or killall) and process.command_line:(*--master-disable* or *com.apple.alf* or *unload* or *disable* or *elastic-agent* or *falcon*)
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:process AND agent.type:"elastic-agent" AND host.os.type:macos AND process.name:(spctl OR launchctl OR defaults OR pfctl OR killall) AND process.command_line:(*\-\-master\-disable* OR *com.apple.alf* OR *unload* OR *disable* OR *elastic\-agent* OR *falcon*) | groupby host.name host.os.type user.name process.name process.parent.name destination.ip destination.port event.action | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port network.transport network.community_id event.code rule.name
```


### Query 2 — Security Onion Linux Elastic Agent
**Security Onion specific:** Uses Elastic Agent telemetry in Security Onion 3.1.0 for Linux hosts. Requires Elastic Agent endpoint, system, Windows, macOS, Linux, or Elastic Defend data streams with ECS host, process, file, registry, authentication, or network fields.

```kql
event.category:process and agent.type:"elastic-agent" and host.os.type:linux and process.name:(systemctl or service or pkill or killall) and process.command_line:(*stop\ auditd* or *disable\ auditd* or *stop\ elastic-agent* or *stop\ rsyslog* or *stop\ firewalld* or *stop\ falcon*)
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:process AND agent.type:"elastic-agent" AND host.os.type:linux AND process.name:(systemctl OR service OR pkill OR killall) AND process.command_line:(*stop\ auditd* OR *disable\ auditd* OR *stop\ elastic\-agent* OR *stop\ rsyslog* OR *stop\ firewalld* OR *stop\ falcon*) | groupby host.name host.os.type user.name process.name process.parent.name destination.ip destination.port event.action | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line process.executable file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port destination.domain network.transport event.code rule.name
```

**Tuning ideas:** allowlist approved admin scripts, package managers, MDM/GPO activity, backup tools, EDR activity, deployment systems, developer workflows, and sanctioned remote administration.

---

## T1070.002 — Clear Command History

**Tactic:** Defense Evasion  
**Detection idea:** macOS Elastic Agent shell history clearing or deletion  
**Elastic implementation notes:** Host telemetry requires Elastic Agent with endpoint, system, Windows, macOS, Linux, or Elastic Defend integrations. Field availability varies by agent policy and event collection settings.

### Query 1 — Security Onion macOS Elastic Agent
**Security Onion specific:** Uses Elastic Agent telemetry in Security Onion 3.1.0 for macOS hosts. Requires Elastic Agent endpoint, system, Windows, macOS, Linux, or Elastic Defend data streams with ECS host, process, file, registry, authentication, or network fields.

```kql
event.category:process and agent.type:"elastic-agent" and host.os.type:macos and process.name:(rm or zsh or bash or sh) and process.command_line:(*.zsh_history* or *.bash_history* or *history\ -c* or *HISTFILE=/dev/null*)
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:process AND agent.type:"elastic-agent" AND host.os.type:macos AND process.name:(rm OR zsh OR bash OR sh) AND process.command_line:(*.zsh_history* OR *.bash_history* OR *history\ \-c* OR *HISTFILE=\/dev\/null*) | groupby host.name host.os.type user.name process.name process.parent.name destination.ip destination.port event.action | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port network.transport network.community_id event.code rule.name
```


**Tuning ideas:** allowlist approved admin scripts, package managers, MDM/GPO activity, backup tools, EDR activity, deployment systems, developer workflows, and sanctioned remote administration.

---

## T1553.001 — Subvert Trust Controls: Gatekeeper Bypass

**Tactic:** Defense Evasion  
**Detection idea:** macOS Elastic Agent Gatekeeper quarantine removal or bypass commands  
**Elastic implementation notes:** Host telemetry requires Elastic Agent with endpoint, system, Windows, macOS, Linux, or Elastic Defend integrations. Field availability varies by agent policy and event collection settings.

### Query 1 — Security Onion macOS Elastic Agent
**Security Onion specific:** Uses Elastic Agent telemetry in Security Onion 3.1.0 for macOS hosts. Requires Elastic Agent endpoint, system, Windows, macOS, Linux, or Elastic Defend data streams with ECS host, process, file, registry, authentication, or network fields.

```kql
event.category:process and agent.type:"elastic-agent" and host.os.type:macos and process.name:(xattr or spctl) and process.command_line:(*com.apple.quarantine* or *-d* or *--master-disable* or *--add*)
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:process AND agent.type:"elastic-agent" AND host.os.type:macos AND process.name:(xattr OR spctl) AND process.command_line:(*com.apple.quarantine* OR *\-d* OR *\-\-master\-disable* OR *\-\-add*) | groupby host.name host.os.type user.name process.name process.parent.name destination.ip destination.port event.action | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line process.executable file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port destination.domain network.transport event.code rule.name
```


**Tuning ideas:** allowlist approved admin scripts, package managers, MDM/GPO activity, backup tools, EDR activity, deployment systems, developer workflows, and sanctioned remote administration.

---

## T1027 — Obfuscated Files or Information

**Tactic:** Defense Evasion  
**Detection idea:** Windows Elastic Agent heavily obfuscated PowerShell or encoded payload execution  
**Elastic implementation notes:** Host telemetry requires Elastic Agent with endpoint, system, Windows, macOS, Linux, or Elastic Defend integrations. Field availability varies by agent policy and event collection settings.

### Query 1 — Security Onion Windows Elastic Agent
**Security Onion specific:** Uses Elastic Agent telemetry in Security Onion 3.1.0 for Windows hosts. Requires Elastic Agent endpoint, system, Windows, macOS, Linux, or Elastic Defend data streams with ECS host, process, file, registry, authentication, or network fields.

```kql
event.category:process and agent.type:"elastic-agent" and host.os.type:windows and process.name:("powershell.exe" or "pwsh.exe" or "cmd.exe") and process.command_line:(*FromBase64String* or *-EncodedCommand* or *\ -enc\ * or *`*`*`* or *char* or *bxor*)
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:process AND agent.type:"elastic-agent" AND host.os.type:windows AND process.name:("powershell.exe" OR "pwsh.exe" OR "cmd.exe") AND process.command_line:(*FromBase64String* OR *\-EncodedCommand* OR *\ \-enc\ * OR *`*`*`* OR *char* OR *bxor*) | groupby host.name host.os.type user.name process.name process.parent.name destination.ip destination.port event.action | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line process.executable file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port destination.domain network.transport event.code rule.name
```


**Tuning ideas:** allowlist approved admin scripts, package managers, MDM/GPO activity, backup tools, EDR activity, deployment systems, developer workflows, and sanctioned remote administration.

---

## T1564.001 — Hide Artifacts: Hidden Files and Directories

**Tactic:** Defense Evasion  
**Detection idea:** Linux Elastic Agent creation or movement of hidden executable files in writable paths  
**Elastic implementation notes:** Host telemetry requires Elastic Agent with endpoint, system, Windows, macOS, Linux, or Elastic Defend integrations. Field availability varies by agent policy and event collection settings.

### Query 1 — Security Onion Linux Elastic Agent
**Security Onion specific:** Uses Elastic Agent telemetry in Security Onion 3.1.0 for Linux hosts. Requires Elastic Agent endpoint, system, Windows, macOS, Linux, or Elastic Defend data streams with ECS host, process, file, registry, authentication, or network fields.

```kql
event.category:(process or file) and agent.type:"elastic-agent" and host.os.type:linux and (file.name:.* or process.command_line:(*mv\ *\ .* or *cp\ *\ .*)) and (file.path:(/tmp/* or /dev/shm/* or /home/*) or process.command_line:(*/tmp/* or */dev/shm/*))
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:(process OR file) AND agent.type:"elastic-agent" AND host.os.type:linux AND (file.name:.* OR process.command_line:(*mv\ *\ .* OR *cp\ *\ .*)) AND (file.path:(\/tmp\/* OR \/dev\/shm\/* OR \/home\/*) OR process.command_line:(*\/tmp\/* OR *\/dev\/shm\/*)) | groupby host.name host.os.type user.name process.name process.parent.name destination.ip destination.port event.action | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line process.executable file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port destination.domain network.transport event.code rule.name
```


### Query 2 — Security Onion macOS Elastic Agent
**Security Onion specific:** Uses Elastic Agent telemetry in Security Onion 3.1.0 for macOS hosts. Requires Elastic Agent endpoint, system, Windows, macOS, Linux, or Elastic Defend data streams with ECS host, process, file, registry, authentication, or network fields.

```kql
event.category:(process or file) and agent.type:"elastic-agent" and host.os.type:macos and (process.command_line:(*chflags\ hidden* or *mv\ *\ .* or *SetFile\ -a\ V*) or file.name:.*)
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:(process OR file) AND agent.type:"elastic-agent" AND host.os.type:macos AND (process.command_line:(*chflags\ hidden* OR *mv\ *\ .* OR *SetFile\ \-a\ V*) OR file.name:.*) | groupby host.name host.os.type user.name process.name process.parent.name destination.ip destination.port event.action | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line process.executable file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port destination.domain network.transport event.code rule.name
```

**Tuning ideas:** allowlist approved admin scripts, package managers, MDM/GPO activity, backup tools, EDR activity, deployment systems, developer workflows, and sanctioned remote administration.

---

## T1070.003 — Clear Command History

**Tactic:** Defense Evasion  
**Detection idea:** Linux Elastic Agent command history file deletion or truncation  
**Elastic implementation notes:** Host telemetry requires Elastic Agent with endpoint, system, Windows, macOS, Linux, or Elastic Defend integrations. Field availability varies by agent policy and event collection settings.

### Query 1 — Security Onion Linux Elastic Agent
**Security Onion specific:** Uses Elastic Agent telemetry in Security Onion 3.1.0 for Linux hosts. Requires Elastic Agent endpoint, system, Windows, macOS, Linux, or Elastic Defend data streams with ECS host, process, file, registry, authentication, or network fields.

```kql
event.category:(process or file) and agent.type:"elastic-agent" and host.os.type:linux and (file.name:(".bash_history" or ".zsh_history") or process.command_line:(*history\ -c* or *cat\ /dev/null\ \>\ ~/.bash_history* or *truncate\ -s\ 0*history*))
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:(process OR file) AND agent.type:"elastic-agent" AND host.os.type:linux AND (file.name:(".bash_history" OR ".zsh_history") OR process.command_line:(*history\ \-c* OR *cat\ \/dev\/null\ \>\ \~\/.bash_history* OR *truncate\ \-s\ 0*history*)) | groupby host.name host.os.type user.name process.name process.parent.name destination.ip destination.port event.action | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line process.executable file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port destination.domain network.transport event.code rule.name
```


**Tuning ideas:** allowlist approved admin scripts, package managers, MDM/GPO activity, backup tools, EDR activity, deployment systems, developer workflows, and sanctioned remote administration.

---

---

## T1647 — Plist File Modification

**Tactic:** Defense Evasion  
**Detection idea:** macOS plist modification in LaunchAgent, LaunchDaemon, preference, Dock, and application Info.plist locations.  
**Elastic implementation notes:** These filters use ECS-style fields commonly present in Elastic Agent, Elastic Defend, Windows, Linux, macOS, Zeek, and Suricata data streams. Tune command-line patterns and administrative allowlists before production use.

### Query 1 — Security Onion macOS Elastic Agent
**Security Onion specific:** Uses Elastic Agent or Security Onion network telemetry in Security Onion 3.1.0. Requires the relevant endpoint, Zeek, Suricata, Windows, Linux, macOS, system, or Elastic Defend data streams with ECS-compatible fields.

```kql
event.category:process and agent.type:"elastic-agent" and host.os.type:macos and process.name:(defaults or plutil or PlistBuddy or osascript) and process.command_line:(*.plist* or *LSUIElement* or *LSEnvironment* or *RunAtLoad* or *ProgramArguments*)
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:process AND agent.type:"elastic-agent" AND host.os.type:macos AND process.name:(defaults OR plutil OR PlistBuddy OR osascript) AND process.command_line:(*.plist* OR *LSUIElement* OR *LSEnvironment* OR *RunAtLoad* OR *ProgramArguments*) | groupby host.name host.os.type user.name process.name process.parent.name event.action destination.ip destination.port | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line process.executable file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port destination.domain network.transport network.community_id event.code rule.name
```
### Query 2 — Security Onion macOS Elastic Agent
**Security Onion specific:** Uses Elastic Agent or Security Onion network telemetry in Security Onion 3.1.0. Requires the relevant endpoint, Zeek, Suricata, Windows, Linux, macOS, system, or Elastic Defend data streams with ECS-compatible fields.

```kql
event.category:file and agent.type:"elastic-agent" and host.os.type:macos and event.action:(creation or modification) and file.path:(*/Library/LaunchAgents/*.plist or */Library/LaunchDaemons/*.plist or */Library/Preferences/*.plist or */Contents/Info.plist)
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:file AND agent.type:"elastic-agent" AND host.os.type:macos AND event.action:(creation OR modification) AND file.path:(*\/Library\/LaunchAgents\/*.plist OR *\/Library\/LaunchDaemons\/*.plist OR *\/Library\/Preferences\/*.plist OR *\/Contents\/Info.plist) | groupby host.name host.os.type user.name process.name process.parent.name event.action destination.ip destination.port | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line process.executable file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port destination.domain network.transport network.community_id event.code rule.name
```
### Query 3 — Security Onion macOS Elastic Agent
**Security Onion specific:** Uses Elastic Agent or Security Onion network telemetry in Security Onion 3.1.0. Requires the relevant endpoint, Zeek, Suricata, Windows, Linux, macOS, system, or Elastic Defend data streams with ECS-compatible fields.

```kql
event.category:process and agent.type:"elastic-agent" and host.os.type:macos and process.name:(launchctl or open or defaults) and process.command_line:(*com.apple.dock.plist* or *LaunchAgents* or *LaunchDaemons* or *Info.plist*)
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:process AND agent.type:"elastic-agent" AND host.os.type:macos AND process.name:(launchctl OR open OR defaults) AND process.command_line:(*com.apple.dock.plist* OR *LaunchAgents* OR *LaunchDaemons* OR *Info.plist*) | groupby host.name host.os.type user.name process.name process.parent.name event.action destination.ip destination.port | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line process.executable file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port destination.domain network.transport network.community_id event.code rule.name
```

**Tuning ideas:** allowlist known administrators, software deployment tools, EDR activity, inventory systems, vulnerability scanners, patching tools, and sanctioned management workflows before alerting.

---

## T1197 — BITS Jobs

**Tactic:** Defense Evasion  
**Detection idea:** BITS job abuse that hides transfer, execution, and cleanup in the Windows background transfer service.  
**Elastic implementation notes:** These filters use ECS-style fields commonly present in Elastic Agent, Elastic Defend, Windows, Linux, macOS, Zeek, and Suricata data streams. Tune command-line patterns and administrative allowlists before production use.

### Query 1 — Security Onion Windows Elastic Agent
**Security Onion specific:** Uses Elastic Agent or Security Onion network telemetry in Security Onion 3.1.0. Requires the relevant endpoint, Zeek, Suricata, Windows, Linux, macOS, system, or Elastic Defend data streams with ECS-compatible fields.

```kql
event.category:process and agent.type:"elastic-agent" and host.os.type:windows and process.name:"bitsadmin.exe" and process.command_line:(*/create* or */transfer* or */addfile* or */setcustomheaders* or */complete* or */cancel*)
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:process AND agent.type:"elastic-agent" AND host.os.type:windows AND process.name:"bitsadmin.exe" AND process.command_line:(*\/create* OR *\/transfer* OR *\/addfile* OR *\/setcustomheaders* OR *\/complete* OR *\/cancel*) | groupby host.name host.os.type user.name process.name process.parent.name event.action destination.ip destination.port | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line process.executable file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port destination.domain network.transport network.community_id event.code rule.name
```
### Query 2 — Security Onion Windows Elastic Agent
**Security Onion specific:** Uses Elastic Agent or Security Onion network telemetry in Security Onion 3.1.0. Requires the relevant endpoint, Zeek, Suricata, Windows, Linux, macOS, system, or Elastic Defend data streams with ECS-compatible fields.

```kql
event.category:process and agent.type:"elastic-agent" and host.os.type:windows and process.name:("powershell.exe" or "pwsh.exe") and process.command_line:(*Start-BitsTransfer* or *Add-BitsFile* or *Complete-BitsTransfer* or *Remove-BitsTransfer*)
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:process AND agent.type:"elastic-agent" AND host.os.type:windows AND process.name:("powershell.exe" OR "pwsh.exe") AND process.command_line:(*Start\-BitsTransfer* OR *Add\-BitsFile* OR *Complete\-BitsTransfer* OR *Remove\-BitsTransfer*) | groupby host.name host.os.type user.name process.name process.parent.name event.action destination.ip destination.port | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line process.executable file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port destination.domain network.transport network.community_id event.code rule.name
```
### Query 3 — Security Onion Windows Elastic Agent
**Security Onion specific:** Uses Elastic Agent or Security Onion network telemetry in Security Onion 3.1.0. Requires the relevant endpoint, Zeek, Suricata, Windows, Linux, macOS, system, or Elastic Defend data streams with ECS-compatible fields.

```kql
event.category:network and agent.type:"elastic-agent" and host.os.type:windows and process.name:"svchost.exe" and destination.ip:* and destination.port:(80 or 443 or 8080 or 8443) and user.name:("SYSTEM" or "LOCAL SERVICE" or "NETWORK SERVICE")
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:network AND agent.type:"elastic-agent" AND host.os.type:windows AND process.name:"svchost.exe" AND destination.ip:* AND destination.port:(80 OR 443 OR 8080 OR 8443) AND user.name:("SYSTEM" OR "LOCAL SERVICE" OR "NETWORK SERVICE") | groupby host.name host.os.type user.name process.name process.parent.name event.action destination.ip destination.port | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line process.executable file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port destination.domain network.transport network.community_id event.code rule.name
```

**Tuning ideas:** allowlist known administrators, software deployment tools, EDR activity, inventory systems, vulnerability scanners, patching tools, and sanctioned management workflows before alerting.

---

## T1222 — File and Directory Permissions Modification

**Tactic:** Defense Evasion  
**Detection idea:** Permission and ownership changes that weaken protections on scripts, binaries, persistence paths, or sensitive files.  
**Elastic implementation notes:** These filters use ECS-style fields commonly present in Elastic Agent, Elastic Defend, Windows, Linux, macOS, Zeek, and Suricata data streams. Tune command-line patterns and administrative allowlists before production use.

### Query 1 — Security Onion Windows Elastic Agent
**Security Onion specific:** Uses Elastic Agent or Security Onion network telemetry in Security Onion 3.1.0. Requires the relevant endpoint, Zeek, Suricata, Windows, Linux, macOS, system, or Elastic Defend data streams with ECS-compatible fields.

```kql
event.category:process and agent.type:"elastic-agent" and host.os.type:windows and process.name:("icacls.exe" or "takeown.exe" or "attrib.exe" or "powershell.exe") and process.command_line:(*/grant* or */inheritance* or */setowner* or *Set-Acl* or *Everyone\:F* or *Users\:F*)
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:process AND agent.type:"elastic-agent" AND host.os.type:windows AND process.name:("icacls.exe" OR "takeown.exe" OR "attrib.exe" OR "powershell.exe") AND process.command_line:(*\/grant* OR *\/inheritance* OR *\/setowner* OR *Set\-Acl* OR *Everyone\:F* OR *Users\:F*) | groupby host.name host.os.type user.name process.name process.parent.name event.action destination.ip destination.port | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line process.executable file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port destination.domain network.transport network.community_id event.code rule.name
```
### Query 2 — Security Onion Linux Elastic Agent
**Security Onion specific:** Uses Elastic Agent or Security Onion network telemetry in Security Onion 3.1.0. Requires the relevant endpoint, Zeek, Suricata, Windows, Linux, macOS, system, or Elastic Defend data streams with ECS-compatible fields.

```kql
event.category:process and agent.type:"elastic-agent" and host.os.type:linux and process.name:(chmod or chown or chgrp or setfacl) and process.command_line:(*\ 777* or *\ a+w* or *\ u+s* or *\ g+s* or */etc/* or */usr/bin/* or */var/www/*)
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:process AND agent.type:"elastic-agent" AND host.os.type:linux AND process.name:(chmod OR chown OR chgrp OR setfacl) AND process.command_line:(*\ 777* OR *\ a\+w* OR *\ u\+s* OR *\ g\+s* OR *\/etc\/* OR *\/usr\/bin\/* OR *\/var\/www\/*) | groupby host.name host.os.type user.name process.name process.parent.name event.action destination.ip destination.port | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line process.executable file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port destination.domain network.transport network.community_id event.code rule.name
```
### Query 3 — Security Onion macOS Elastic Agent
**Security Onion specific:** Uses Elastic Agent or Security Onion network telemetry in Security Onion 3.1.0. Requires the relevant endpoint, Zeek, Suricata, Windows, Linux, macOS, system, or Elastic Defend data streams with ECS-compatible fields.

```kql
event.category:process and agent.type:"elastic-agent" and host.os.type:macos and process.name:(chmod or chown or chflags or xattr) and process.command_line:(*\ 777* or *\ a+w* or *\ u+s* or *hidden* or */Library/LaunchAgents/* or */Library/LaunchDaemons/*)
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:process AND agent.type:"elastic-agent" AND host.os.type:macos AND process.name:(chmod OR chown OR chflags OR xattr) AND process.command_line:(*\ 777* OR *\ a\+w* OR *\ u\+s* OR *hidden* OR *\/Library\/LaunchAgents\/* OR *\/Library\/LaunchDaemons\/*) | groupby host.name host.os.type user.name process.name process.parent.name event.action destination.ip destination.port | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line process.executable file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port destination.domain network.transport network.community_id event.code rule.name
```

**Tuning ideas:** allowlist known administrators, software deployment tools, EDR activity, inventory systems, vulnerability scanners, patching tools, and sanctioned management workflows before alerting.

---

## T1690 — Prevent Command History Logging

**Tactic:** Defense Evasion  
**Detection idea:** Shell or PowerShell configuration changes that prevent command history from being written.  
**Elastic implementation notes:** These filters use ECS-style fields commonly present in Elastic Agent, Elastic Defend, Windows, Linux, macOS, Zeek, and Suricata data streams. Tune command-line patterns and administrative allowlists before production use.

### Query 1 — Security Onion Linux Elastic Agent
**Security Onion specific:** Uses Elastic Agent or Security Onion network telemetry in Security Onion 3.1.0. Requires the relevant endpoint, Zeek, Suricata, Windows, Linux, macOS, system, or Elastic Defend data streams with ECS-compatible fields.

```kql
event.category:process and agent.type:"elastic-agent" and host.os.type:linux and process.name:(bash or sh or zsh or env) and process.command_line:(*unset\ HISTFILE* or *HISTFILE=/dev/null* or *HISTSIZE=0* or *HISTFILESIZE=0* or *HISTCONTROL=ignorespace*)
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:process AND agent.type:"elastic-agent" AND host.os.type:linux AND process.name:(bash OR sh OR zsh OR env) AND process.command_line:(*unset\ HISTFILE* OR *HISTFILE=\/dev\/null* OR *HISTSIZE=0* OR *HISTFILESIZE=0* OR *HISTCONTROL=ignorespace*) | groupby host.name host.os.type user.name process.name process.parent.name event.action destination.ip destination.port | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line process.executable file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port destination.domain network.transport network.community_id event.code rule.name
```
### Query 2 — Security Onion macOS Elastic Agent
**Security Onion specific:** Uses Elastic Agent or Security Onion network telemetry in Security Onion 3.1.0. Requires the relevant endpoint, Zeek, Suricata, Windows, Linux, macOS, system, or Elastic Defend data streams with ECS-compatible fields.

```kql
event.category:process and agent.type:"elastic-agent" and host.os.type:macos and process.name:(bash or zsh or sh or env) and process.command_line:(*unset\ HISTFILE* or *HISTFILE=/dev/null* or *HISTSIZE=0* or *SAVEHIST=0* or *setopt\ HIST_IGNORE_SPACE*)
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:process AND agent.type:"elastic-agent" AND host.os.type:macos AND process.name:(bash OR zsh OR sh OR env) AND process.command_line:(*unset\ HISTFILE* OR *HISTFILE=\/dev\/null* OR *HISTSIZE=0* OR *SAVEHIST=0* OR *setopt\ HIST_IGNORE_SPACE*) | groupby host.name host.os.type user.name process.name process.parent.name event.action destination.ip destination.port | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line process.executable file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port destination.domain network.transport network.community_id event.code rule.name
```
### Query 3 — Security Onion Windows Elastic Agent
**Security Onion specific:** Uses Elastic Agent or Security Onion network telemetry in Security Onion 3.1.0. Requires the relevant endpoint, Zeek, Suricata, Windows, Linux, macOS, system, or Elastic Defend data streams with ECS-compatible fields.

```kql
event.category:process and agent.type:"elastic-agent" and host.os.type:windows and process.name:("powershell.exe" or "pwsh.exe") and process.command_line:(*Set-PSReadLineOption* and *-HistorySaveStyle* and *SaveNothing*)
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:process AND agent.type:"elastic-agent" AND host.os.type:windows AND process.name:("powershell.exe" OR "pwsh.exe") AND process.command_line:(*Set\-PSReadLineOption* AND *\-HistorySaveStyle* AND *SaveNothing*) | groupby host.name host.os.type user.name process.name process.parent.name event.action destination.ip destination.port | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line process.executable file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port destination.domain network.transport network.community_id event.code rule.name
```

**Tuning ideas:** allowlist known administrators, software deployment tools, EDR activity, inventory systems, vulnerability scanners, patching tools, and sanctioned management workflows before alerting.

---

## T1027.013 — Obfuscated Files or Information: Encrypted/Encoded File

**Tactic:** Defense Evasion  
**Detection idea:** Creation or decoding of encoded payload files before execution.  
**Elastic implementation notes:** These filters use ECS-style fields commonly present in Elastic Agent, Elastic Defend, Windows, Linux, macOS, Zeek, Suricata, cloud, and SaaS data streams. Tune command-line patterns, data views, and administrative allowlists before production use.

### Query 1 — Security Onion Windows Elastic Agent
**Security Onion specific:** Uses Elastic Agent or Security Onion telemetry in Security Onion 3.1.0. Requires the relevant endpoint, Zeek, Suricata, cloud, SaaS, Windows, Linux, macOS, system, or Elastic Defend data streams with ECS-compatible fields.

```kql
event.category:process and agent.type:"elastic-agent" and host.os.type:windows and process.name:("certutil.exe" or "powershell.exe" or "cmd.exe") and process.command_line:(*\ -decode* or *\ -encode* or *FromBase64String* or *Set-Content* or *.b64*)
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:process AND agent.type:"elastic-agent" AND host.os.type:windows AND process.name:("certutil.exe" OR "powershell.exe" OR "cmd.exe") AND process.command_line:(*\ \-decode* OR *\ \-encode* OR *FromBase64String* OR *Set\-Content* OR *.b64*) | groupby host.name host.os.type user.name process.name process.parent.name event.action destination.ip destination.port | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line process.executable file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port destination.domain network.transport network.community_id event.code rule.name
```
### Query 2 — Security Onion Linux/macOS Elastic Agent
**Security Onion specific:** Uses Elastic Agent or Security Onion telemetry in Security Onion 3.1.0. Requires the relevant endpoint, Zeek, Suricata, cloud, SaaS, Windows, Linux, macOS, system, or Elastic Defend data streams with ECS-compatible fields.

```kql
event.category:process and agent.type:"elastic-agent" and host.os.type:(linux or macos) and process.name:(base64 or openssl or python or python3) and process.command_line:(*\ -d* or *enc\ -d* or *b64decode* or *.b64* or *.encoded*)
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:process AND agent.type:"elastic-agent" AND host.os.type:(linux OR macos) AND process.name:(base64 OR openssl OR python OR python3) AND process.command_line:(*\ \-d* OR *enc\ \-d* OR *b64decode* OR *.b64* OR *.encoded*) | groupby host.name host.os.type user.name process.name process.parent.name event.action destination.ip destination.port | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line process.executable file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port destination.domain network.transport network.community_id event.code rule.name
```

**Tuning ideas:** allowlist known administrators, software deployment tools, EDR activity, backup agents, inventory systems, vulnerability scanners, patching tools, and sanctioned management workflows before alerting.

---

## T1036.007 — Masquerading: Double File Extension

**Tactic:** Defense Evasion  
**Detection idea:** Files or executions with misleading double extensions such as document-looking executables.  
**Elastic implementation notes:** These filters use ECS-style fields commonly present in Elastic Agent, Elastic Defend, Windows, Linux, macOS, Zeek, Suricata, cloud, and SaaS data streams. Tune command-line patterns, data views, and administrative allowlists before production use.

### Query 1 — Security Onion Windows Elastic Agent
**Security Onion specific:** Uses Elastic Agent or Security Onion telemetry in Security Onion 3.1.0. Requires the relevant endpoint, Zeek, Suricata, cloud, SaaS, Windows, Linux, macOS, system, or Elastic Defend data streams with ECS-compatible fields.

```kql
event.category:file and agent.type:"elastic-agent" and host.os.type:windows and file.name:(*.pdf.exe or *.doc.exe or *.docx.exe or *.xls.exe or *.xlsx.exe or *.jpg.exe or *.png.exe or *.txt.exe)
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:file AND agent.type:"elastic-agent" AND host.os.type:windows AND file.name:(*.pdf.exe OR *.doc.exe OR *.docx.exe OR *.xls.exe OR *.xlsx.exe OR *.jpg.exe OR *.png.exe OR *.txt.exe) | groupby host.name host.os.type user.name process.name process.parent.name event.action destination.ip destination.port | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line process.executable file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port destination.domain network.transport network.community_id event.code rule.name
```
### Query 2 — Security Onion Windows Elastic Agent
**Security Onion specific:** Uses Elastic Agent or Security Onion telemetry in Security Onion 3.1.0. Requires the relevant endpoint, Zeek, Suricata, cloud, SaaS, Windows, Linux, macOS, system, or Elastic Defend data streams with ECS-compatible fields.

```kql
event.category:process and agent.type:"elastic-agent" and host.os.type:windows and process.name:(*.pdf.exe or *.doc.exe or *.jpg.exe or *.txt.exe)
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:process AND agent.type:"elastic-agent" AND host.os.type:windows AND process.name:(*.pdf.exe OR *.doc.exe OR *.jpg.exe OR *.txt.exe) | groupby host.name host.os.type user.name process.name process.parent.name event.action destination.ip destination.port | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line process.executable file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port destination.domain network.transport network.community_id event.code rule.name
```

**Tuning ideas:** allowlist known administrators, software deployment tools, EDR activity, backup agents, inventory systems, vulnerability scanners, patching tools, and sanctioned management workflows before alerting.

---

## T1036.008 — Masquerading: Masquerade File Type

**Tactic:** Defense Evasion  
**Detection idea:** Scripts or executables masquerading as benign document/media file types.  
**Elastic implementation notes:** These filters use ECS-style fields commonly present in Elastic Agent, Elastic Defend, Windows, Linux, macOS, Zeek, Suricata, cloud, and SaaS data streams. Tune command-line patterns, data views, and administrative allowlists before production use.

### Query 1 — Security Onion Windows Elastic Agent
**Security Onion specific:** Uses Elastic Agent or Security Onion telemetry in Security Onion 3.1.0. Requires the relevant endpoint, Zeek, Suricata, cloud, SaaS, Windows, Linux, macOS, system, or Elastic Defend data streams with ECS-compatible fields.

```kql
event.category:file and agent.type:"elastic-agent" and host.os.type:windows and file.extension:(lnk or scr or ps1 or js or vbs or hta) and file.name:(*.pdf* or *.doc* or *.xlsx* or *.jpg* or *.png*)
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:file AND agent.type:"elastic-agent" AND host.os.type:windows AND file.extension:(lnk OR scr OR ps1 OR js OR vbs OR hta) AND file.name:(*.pdf* OR *.doc* OR *.xlsx* OR *.jpg* OR *.png*) | groupby host.name host.os.type user.name process.name process.parent.name event.action destination.ip destination.port | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line process.executable file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port destination.domain network.transport network.community_id event.code rule.name
```
### Query 2 — Security Onion Linux/macOS Elastic Agent
**Security Onion specific:** Uses Elastic Agent or Security Onion telemetry in Security Onion 3.1.0. Requires the relevant endpoint, Zeek, Suricata, cloud, SaaS, Windows, Linux, macOS, system, or Elastic Defend data streams with ECS-compatible fields.

```kql
event.category:file and agent.type:"elastic-agent" and host.os.type:(linux or macos) and file.name:(*.pdf.sh or *.jpg.sh or *.png.command or *.txt.command or *.doc.py)
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:file AND agent.type:"elastic-agent" AND host.os.type:(linux OR macos) AND file.name:(*.pdf.sh OR *.jpg.sh OR *.png.command OR *.txt.command OR *.doc.py) | groupby host.name host.os.type user.name process.name process.parent.name event.action destination.ip destination.port | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line process.executable file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port destination.domain network.transport network.community_id event.code rule.name
```

**Tuning ideas:** allowlist known administrators, software deployment tools, EDR activity, backup agents, inventory systems, vulnerability scanners, patching tools, and sanctioned management workflows before alerting.

---

## T1564.008 — Hide Artifacts: Email Hiding Rules

**Tactic:** Defense Evasion  
**Detection idea:** Mailbox rule changes that hide, delete, move, or forward messages to reduce visibility.  
**Elastic implementation notes:** These filters use ECS-style fields commonly present in Elastic Agent, Elastic Defend, Windows, Linux, macOS, Zeek, Suricata, cloud, and SaaS data streams. Tune command-line patterns, data views, and administrative allowlists before production use.

### Query 1 — Security Onion Office 365 / SaaS
**Security Onion specific:** Uses Elastic Agent or Security Onion telemetry in Security Onion 3.1.0. Requires the relevant endpoint, Zeek, Suricata, cloud, SaaS, Windows, Linux, macOS, system, or Elastic Defend data streams with ECS-compatible fields.

```kql
event.dataset:("o365.audit" or "google_workspace.admin") and event.action:(*New-InboxRule* or *Set-InboxRule* or *UpdateInboxRules* or *Create\ Rule* or *Modify\ Rule*)
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.dataset:("o365.audit" OR "google_workspace.admin") AND event.action:(*New\-InboxRule* OR *Set\-InboxRule* OR *UpdateInboxRules* OR *Create\ Rule* OR *Modify\ Rule*) | groupby host.name host.os.type user.name process.name process.parent.name event.action destination.ip destination.port | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line process.executable file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port destination.domain network.transport network.community_id event.code rule.name
```
### Query 2 — Security Onion Office 365 / SaaS
**Security Onion specific:** Uses Elastic Agent or Security Onion telemetry in Security Onion 3.1.0. Requires the relevant endpoint, Zeek, Suricata, cloud, SaaS, Windows, Linux, macOS, system, or Elastic Defend data streams with ECS-compatible fields.

```kql
event.category:iam and event.action:(*inbox*rule* or *mail*rule* or *forward* or *delete*message*) and user.name:*
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:iam AND event.action:(*inbox*rule* OR *mail*rule* OR *forward* OR *delete*message*) AND user.name:* | groupby host.name host.os.type user.name process.name process.parent.name event.action destination.ip destination.port | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line process.executable file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port destination.domain network.transport network.community_id event.code rule.name
```

**Tuning ideas:** allowlist known administrators, software deployment tools, EDR activity, backup agents, inventory systems, vulnerability scanners, patching tools, and sanctioned management workflows before alerting.

---

## T1574.001 — Hijack Execution Flow: DLL

**Tactic:** Defense Evasion / Execution  
**Detection idea:** DLL planting, search-order hijacking, or suspicious DLL writes near executables.  
**Elastic implementation notes:** These filters use ECS-style fields commonly present in Elastic Agent, Elastic Defend, Windows, Linux, macOS, Zeek, Suricata, cloud, and SaaS data streams. Tune command-line patterns, data views, and administrative allowlists before production use.

### Query 1 — Security Onion Windows Elastic Agent
**Security Onion specific:** Uses Elastic Agent or Security Onion telemetry in Security Onion 3.1.0. Requires the relevant endpoint, Zeek, Suricata, cloud, SaaS, Windows, Linux, macOS, system, or Elastic Defend data streams with ECS-compatible fields.

```kql
event.category:file and agent.type:"elastic-agent" and host.os.type:windows and event.action:(creation or modification) and file.extension:dll and file.path:(*\\Users\\* or *\\AppData\\* or *\\Temp\\* or *\\ProgramData\\*)
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:file AND agent.type:"elastic-agent" AND host.os.type:windows AND event.action:(creation OR modification) AND file.extension:dll AND file.path:(*\\Users\\* OR *\\AppData\\* OR *\\Temp\\* OR *\\ProgramData\\*) | groupby host.name host.os.type user.name process.name process.parent.name event.action destination.ip destination.port | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line process.executable file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port destination.domain network.transport network.community_id event.code rule.name
```
### Query 2 — Security Onion Windows Elastic Agent
**Security Onion specific:** Uses Elastic Agent or Security Onion telemetry in Security Onion 3.1.0. Requires the relevant endpoint, Zeek, Suricata, cloud, SaaS, Windows, Linux, macOS, system, or Elastic Defend data streams with ECS-compatible fields.

```kql
event.category:process and agent.type:"elastic-agent" and host.os.type:windows and process.command_line:(*SetDllDirectory* or *LoadLibrary* or *rundll32* or *.dll,*)
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:process AND agent.type:"elastic-agent" AND host.os.type:windows AND process.command_line:(*SetDllDirectory* OR *LoadLibrary* OR *rundll32* OR *.dll,*) | groupby host.name host.os.type user.name process.name process.parent.name event.action destination.ip destination.port | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line process.executable file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port destination.domain network.transport network.community_id event.code rule.name
```

**Tuning ideas:** allowlist known administrators, software deployment tools, EDR activity, backup agents, inventory systems, vulnerability scanners, patching tools, and sanctioned management workflows before alerting.

---

## T1574.007 — Hijack Execution Flow: PATH Environment Variable

**Tactic:** Defense Evasion / Execution  
**Detection idea:** PATH or loader environment manipulation that can redirect process execution.  
**Elastic implementation notes:** These filters use ECS-style fields commonly present in Elastic Agent, Elastic Defend, Windows, Linux, macOS, Zeek, Suricata, cloud, and SaaS data streams. Tune command-line patterns, data views, and administrative allowlists before production use.

### Query 1 — Security Onion Linux/macOS Elastic Agent
**Security Onion specific:** Uses Elastic Agent or Security Onion telemetry in Security Onion 3.1.0. Requires the relevant endpoint, Zeek, Suricata, cloud, SaaS, Windows, Linux, macOS, system, or Elastic Defend data streams with ECS-compatible fields.

```kql
event.category:process and agent.type:"elastic-agent" and host.os.type:(linux or macos) and process.command_line:(*export\ PATH=* or *PATH=.\:* or *PATH=/tmp* or *DYLD_LIBRARY_PATH* or *LD_LIBRARY_PATH*)
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:process AND agent.type:"elastic-agent" AND host.os.type:(linux OR macos) AND process.command_line:(*export\ PATH=* OR *PATH=.\:* OR *PATH=\/tmp* OR *DYLD_LIBRARY_PATH* OR *LD_LIBRARY_PATH*) | groupby host.name host.os.type user.name process.name process.parent.name event.action destination.ip destination.port | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line process.executable file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port destination.domain network.transport network.community_id event.code rule.name
```
### Query 2 — Security Onion Windows Elastic Agent
**Security Onion specific:** Uses Elastic Agent or Security Onion telemetry in Security Onion 3.1.0. Requires the relevant endpoint, Zeek, Suricata, cloud, SaaS, Windows, Linux, macOS, system, or Elastic Defend data streams with ECS-compatible fields.

```kql
event.category:process and agent.type:"elastic-agent" and host.os.type:windows and process.name:("setx.exe" or "powershell.exe" or "cmd.exe") and process.command_line:(*\ PATH\ * or *Environment*Path* or *SetEnvironmentVariable*)
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:process AND agent.type:"elastic-agent" AND host.os.type:windows AND process.name:("setx.exe" OR "powershell.exe" OR "cmd.exe") AND process.command_line:(*\ PATH\ * OR *Environment*Path* OR *SetEnvironmentVariable*) | groupby host.name host.os.type user.name process.name process.parent.name event.action destination.ip destination.port | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line process.executable file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port destination.domain network.transport network.community_id event.code rule.name
```

**Tuning ideas:** allowlist known administrators, software deployment tools, EDR activity, backup agents, inventory systems, vulnerability scanners, patching tools, and sanctioned management workflows before alerting.

---

## T1574.011 — Hijack Execution Flow: Services Registry Permissions Weakness

**Tactic:** Defense Evasion / Execution  
**Detection idea:** Service registry permission or image path changes that enable service hijacking.  
**Elastic implementation notes:** These filters use ECS-style fields commonly present in Elastic Agent, Elastic Defend, Windows, Linux, macOS, Zeek, Suricata, cloud, and SaaS data streams. Tune command-line patterns, data views, and administrative allowlists before production use.

### Query 1 — Security Onion Windows Elastic Agent
**Security Onion specific:** Uses Elastic Agent or Security Onion telemetry in Security Onion 3.1.0. Requires the relevant endpoint, Zeek, Suricata, cloud, SaaS, Windows, Linux, macOS, system, or Elastic Defend data streams with ECS-compatible fields.

```kql
event.category:registry and agent.type:"elastic-agent" and host.os.type:windows and registry.path:*\\System\\CurrentControlSet\\Services\\* and registry.value:(ImagePath or ServiceDll or FailureCommand)
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:registry AND agent.type:"elastic-agent" AND host.os.type:windows AND registry.path:*\\System\\CurrentControlSet\\Services\\* AND registry.value:(ImagePath OR ServiceDll OR FailureCommand) | groupby host.name host.os.type user.name process.name process.parent.name event.action destination.ip destination.port | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line process.executable file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port destination.domain network.transport network.community_id event.code rule.name
```
### Query 2 — Security Onion Windows Elastic Agent
**Security Onion specific:** Uses Elastic Agent or Security Onion telemetry in Security Onion 3.1.0. Requires the relevant endpoint, Zeek, Suricata, cloud, SaaS, Windows, Linux, macOS, system, or Elastic Defend data streams with ECS-compatible fields.

```kql
event.category:process and agent.type:"elastic-agent" and host.os.type:windows and process.name:("sc.exe" or "reg.exe" or "powershell.exe") and process.command_line:(*sdset* or *ImagePath* or *ServiceDll* or *CurrentControlSet\\Services*)
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:process AND agent.type:"elastic-agent" AND host.os.type:windows AND process.name:("sc.exe" OR "reg.exe" OR "powershell.exe") AND process.command_line:(*sdset* OR *ImagePath* OR *ServiceDll* OR *CurrentControlSet\\Services*) | groupby host.name host.os.type user.name process.name process.parent.name event.action destination.ip destination.port | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line process.executable file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port destination.domain network.transport network.community_id event.code rule.name
```

**Tuning ideas:** allowlist known administrators, software deployment tools, EDR activity, backup agents, inventory systems, vulnerability scanners, patching tools, and sanctioned management workflows before alerting.
