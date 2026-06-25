# TA0003 — Persistence

> Query dialect: Elastic Kibana Query Language (**Elastic KQL**) using ECS-style fields. These are hunting-grade filters intended for Kibana Discover, Timeline, and Elastic Security rules. Tune fields, data views, and allowlists to your environment.

**Coverage count:** 32 technique sections / 63 KQL queries

## Techniques in this tactic

- [T1053.005 — Scheduled Task / Job: Scheduled Task](SO_TA0003_Persistence.md#t1053.005-scheduled-task-job-scheduled-task) — 3 queries
- [T1547.001 — Registry Run Keys / Startup Folder](SO_TA0003_Persistence.md#t1547.001-registry-run-keys-startup-folder) — 3 queries
- [T1543.003 — Windows Service](SO_TA0003_Persistence.md#t1543.003-windows-service) — 3 queries
- [T1078 — Valid Accounts](SO_TA0003_Persistence.md#t1078-valid-accounts) — 2 queries
- [T1098 — Account Manipulation](SO_TA0003_Persistence.md#t1098-account-manipulation) — 4 queries
- [T1136.003 — Create Account: Cloud Account](SO_TA0003_Persistence.md#t1136.003-create-account-cloud-account) — 2 queries
- [T1546.003 — Event Triggered Execution: Windows Management Instrumentation Event Subscription](SO_TA0003_Persistence.md#t1546.003-event-triggered-execution-windows-management-instrumentation-event-subscription) — 3 queries
- [T1505.003 — Server Software Component: Web Shell](SO_TA0003_Persistence.md#t1505.003-server-software-component-web-shell) — 3 queries
- [T1136.001 — Create Account: Local Account](SO_TA0003_Persistence.md#t1136.001-create-account-local-account) — 5 queries
- [T1136.002 — Create Account: Domain Account](SO_TA0003_Persistence.md#t1136.002-create-account-domain-account) — 2 queries
- [T1547.009 — Boot or Logon Autostart Execution: Shortcut Modification](SO_TA0003_Persistence.md#t1547.009-boot-or-logon-autostart-execution-shortcut-modification) — 2 queries
- [T1053.003 — Scheduled Task/Job: Cron](SO_TA0003_Persistence.md#t1053.003-scheduled-taskjob-cron) — 1 query
- [T1543.002 — Create or Modify System Process: Systemd Service](SO_TA0003_Persistence.md#t1543.002-create-or-modify-system-process-systemd-service) — 2 queries
- [T1543.001 / T1543.004 — Create or Modify System Process: Launch Agent / Launch Daemon](SO_TA0003_Persistence.md#t1543.001-t1543.004-create-or-modify-system-process-launch-agent-launch-daemon) — 2 queries
- [T1037.004 — Boot or Logon Initialization Scripts: RC Scripts](SO_TA0003_Persistence.md#t1037.004-boot-or-logon-initialization-scripts-rc-scripts) — 1 query
- [T1547.006 — Boot or Logon Autostart Execution: Kernel Modules and Extensions](SO_TA0003_Persistence.md#t1547.006-boot-or-logon-autostart-execution-kernel-modules-and-extensions) — 1 query
- [T1037.002 — Boot or Logon Initialization Scripts: Login Hook](SO_TA0003_Persistence.md#t1037.002-boot-or-logon-initialization-scripts-login-hook) — 1 query
- [T1547.011 — Boot or Logon Autostart Execution: Plist Modification](SO_TA0003_Persistence.md#t1547.011-boot-or-logon-autostart-execution-plist-modification) — 1 query
- [T1546.004 — Event Triggered Execution: Unix Shell Configuration Modification](SO_TA0003_Persistence.md#t1546.004-event-triggered-execution-unix-shell-configuration-modification) — 2 queries
- [T1546.016 — Event Triggered Execution: Installer Packages](SO_TA0003_Persistence.md#t1546.016-event-triggered-execution-installer-packages) — 1 query
- [T1546.011 — Event Triggered Execution: Application Shimming](SO_TA0003_Persistence.md#t1546.011-event-triggered-execution-application-shimming) — 1 query
- [T1546.008 — Event Triggered Execution: Accessibility Features](SO_TA0003_Persistence.md#t1546.008-event-triggered-execution-accessibility-features) — 1 query
- [T1546.012 — Event Triggered Execution: Image File Execution Options Injection](SO_TA0003_Persistence.md#t1546.012-event-triggered-execution-image-file-execution-options-injection) — 1 query
- [T1053.006 — Scheduled Task/Job: Systemd Timers](SO_TA0003_Persistence.md#t1053.006-scheduled-taskjob-systemd-timers) — 1 query
- [T1053.002 — Scheduled Task/Job: At](SO_TA0003_Persistence.md#t1053.002-scheduled-taskjob-at) — 1 query
- [T1546.014 — Event Triggered Execution: Emond](SO_TA0003_Persistence.md#t1546.014-event-triggered-execution-emond) — 1 query
- [T1547.015 — Boot or Logon Autostart Execution: Login Items](SO_TA0003_Persistence.md#t1547.015-boot-or-logon-autostart-execution-login-items) — 1 query
- [T1197 — BITS Jobs](SO_TA0003_Persistence.md#t1197-bits-jobs) — 3 queries
- [T1176 — Software Extensions](SO_TA0003_Persistence.md#t1176-software-extensions) — 3 queries
- [T1546.013 — Event Triggered Execution: PowerShell Profile](SO_TA0003_Persistence.md#t1546.013-event-triggered-execution-powershell-profile) — 2 queries
- [T1547.014 — Boot or Logon Autostart Execution: Active Setup](SO_TA0003_Persistence.md#t1547.014-boot-or-logon-autostart-execution-active-setup) — 2 queries
- [T1137 — Office Application Startup](SO_TA0003_Persistence.md#t1137-office-application-startup) — 2 queries

---

## T1053.005 — Scheduled Task / Job: Scheduled Task

**Tactic:** Persistence  
**Detection idea:** Creation or modification of scheduled tasks with suspicious payloads  
**Elastic implementation notes:** ECS field names vary by integration. Start with the KQL below, then tune for your Elastic Agent, Elastic Defend, Windows, System, Sysmon, cloud, and email data streams.

### Query 1
```kql
event.category:process and process.name:"schtasks.exe" and process.command_line:("*/create*" or "*/change*" or "*/run*") and process.command_line:("*powershell*" or "*cmd*" or "*wscript*" or "*cscript*" or "*mshta*" or "*rundll32*" or "*http*")
```

### Query 2
```kql
event.category:file and file.path:("C:\\Windows\\System32\\Tasks\\*" or "C:\\Windows\\SysWOW64\\Tasks\\*") and event.action:(creation or modification)
```

### Query 3 — Security Onion Windows Elastic Agent
**Security Onion specific:** Uses Elastic Agent telemetry in Security Onion 3.1.0 for Windows hosts. Requires Elastic Agent endpoint, system, Windows, macOS, Linux, or Elastic Defend data streams with ECS host, process, file, registry, authentication, or network fields.

```kql
event.category:process and agent.type:"elastic-agent" and host.os.type:windows and process.name:"schtasks.exe" and process.command_line:("*/create*" or "*/change*") and process.command_line:("*powershell*" or "*cmd*" or "*wscript*" or "*mshta*" or "*rundll32*" or "*http*")
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:process AND agent.type:"elastic-agent" AND host.os.type:windows AND process.name:"schtasks.exe" AND process.command_line:("*/create*" OR "*/change*") AND process.command_line:("*powershell*" OR "*cmd*" OR "*wscript*" OR "*mshta*" OR "*rundll32*" OR "*http*") | groupby host.name host.os.type user.name process.name process.parent.name destination.ip destination.port event.action | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port network.transport network.community_id event.code rule.name
```

**Tuning ideas:** allowlist known admin scripts, software deployment tools, scanners, EDR activity, patch management, and sanctioned cloud apps before alerting.

---

## T1547.001 — Registry Run Keys / Startup Folder

**Tactic:** Persistence  
**Detection idea:** Run key or Startup folder persistence  
**Elastic implementation notes:** ECS field names vary by integration. Start with the KQL below, then tune for your Elastic Agent, Elastic Defend, Windows, System, Sysmon, cloud, and email data streams.

### Query 1
```kql
event.category:registry and registry.path:("*\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\*" or "*\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce\\*" or "*\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run\\*")
```

### Query 2
```kql
event.category:file and file.path:("*\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\*" or "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\*")
```

### Query 3 — Security Onion Windows Elastic Agent
**Security Onion specific:** Uses Elastic Agent telemetry in Security Onion 3.1.0 for Windows hosts. Requires Elastic Agent endpoint, system, Windows, macOS, Linux, or Elastic Defend data streams with ECS host, process, file, registry, authentication, or network fields.

```kql
event.category:(registry or file) and agent.type:"elastic-agent" and host.os.type:windows and (registry.path:("*\CurrentVersion\Run\*" or "*\CurrentVersion\RunOnce\*" or "*\Policies\Explorer\Run\*") or file.path:("*\Start Menu\Programs\Startup\*" or "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\*"))
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:(registry OR file) AND agent.type:"elastic-agent" AND host.os.type:windows AND (registry.path:("*\CurrentVersion\Run\*" OR "*\CurrentVersion\RunOnce\*" OR "*\Policies\Explorer\Run\*") OR file.path:("*\Start Menu\Programs\Startup\*" OR "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\*")) | groupby host.name host.os.type user.name process.name process.parent.name destination.ip destination.port event.action | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line process.executable file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port destination.domain network.transport event.code rule.name
```

**Tuning ideas:** allowlist known admin scripts, software deployment tools, scanners, EDR activity, patch management, and sanctioned cloud apps before alerting.

---

## T1543.003 — Windows Service

**Tactic:** Persistence  
**Detection idea:** Suspicious service creation or service binary modification  
**Elastic implementation notes:** ECS field names vary by integration. Start with the KQL below, then tune for your Elastic Agent, Elastic Defend, Windows, System, Sysmon, cloud, and email data streams.

### Query 1
```kql
event.category:process and process.name:("sc.exe" or "powershell.exe" or "pwsh.exe") and process.command_line:("*create*" or "*New-Service*" or "*Set-Service*") and process.command_line:("*.exe*" or "*powershell*" or "*cmd*")
```

### Query 2
```kql
event.category:registry and registry.path:"*\\System\\CurrentControlSet\\Services\\*" and registry.path:("*\\ImagePath" or "*\\ServiceDll") and registry.data.strings:("*powershell*" or "*cmd.exe*" or "*rundll32*" or "*mshta*" or "*AppData*" or "*Temp*")
```

### Query 3 — Security Onion Windows Elastic Agent
**Security Onion specific:** Uses Elastic Agent telemetry in Security Onion 3.1.0 for Windows hosts. Requires Elastic Agent endpoint, system, Windows, macOS, Linux, or Elastic Defend data streams with ECS host, process, file, registry, authentication, or network fields.

```kql
event.category:process and agent.type:"elastic-agent" and host.os.type:windows and process.name:("sc.exe" or "powershell.exe" or "pwsh.exe") and process.command_line:("* create *" or "*New-Service*") and process.command_line:("*AppData*" or "*Temp*" or "*powershell*" or "*cmd.exe*" or "*rundll32*")
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:process AND agent.type:"elastic-agent" AND host.os.type:windows AND process.name:("sc.exe" OR "powershell.exe" OR "pwsh.exe") AND process.command_line:("* create *" OR "*New-Service*") AND process.command_line:("*AppData*" OR "*Temp*" OR "*powershell*" OR "*cmd.exe*" OR "*rundll32*") | groupby host.name host.os.type user.name process.name process.parent.name destination.ip destination.port event.action | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port network.transport network.community_id event.code rule.name
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
event.dataset:("windows.security" or "azure.signinlogs" or "o365.audit") and event.outcome:success and user.name:("*svc*" or "*admin*" or "*adm*")
```

**Tuning ideas:** allowlist known admin scripts, software deployment tools, scanners, EDR activity, patch management, and sanctioned cloud apps before alerting.

---

## T1098 — Account Manipulation

**Tactic:** Persistence / Privilege Escalation  
**Detection idea:** Cloud or directory account changes, MFA changes, and role assignments  
**Elastic implementation notes:** ECS field names vary by integration. Start with the KQL below, then tune for your Elastic Agent, Elastic Defend, Windows, System, Sysmon, cloud, and email data streams.

### Query 1
```kql
event.category:iam and event.action:(user-change or user-modification or password-change or mfa-change or role-assignment or group-membership-add)
```

### Query 2
```kql
event.dataset:("azure.auditlogs" or "o365.audit") and event.action:("*Add member*" or "*Update user*" or "*Reset password*" or "*Add app role assignment*" or "*Add owner*")
```

### Query 3 — Security Onion Linux Elastic Agent
**Security Onion specific:** Uses Elastic Agent telemetry in Security Onion 3.1.0 for Linux hosts. Requires Elastic Agent endpoint, system, Windows, macOS, Linux, or Elastic Defend data streams with ECS host, process, file, registry, authentication, or network fields.

```kql
event.category:process and agent.type:"elastic-agent" and host.os.type:linux and process.name:(useradd or usermod or groupadd or gpasswd or passwd or chpasswd) and process.command_line:("*sudo*" or "*wheel*" or "*root*" or "*-aG*" or "*--append*")
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:process AND agent.type:"elastic-agent" AND host.os.type:linux AND process.name:(useradd OR usermod OR groupadd OR gpasswd OR passwd OR chpasswd) AND process.command_line:("*sudo*" OR "*wheel*" OR "*root*" OR "*-aG*" OR "*--append*") | groupby host.name host.os.type user.name process.name process.parent.name destination.ip destination.port event.action | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port network.transport network.community_id event.code rule.name
```

### Query 4 — Security Onion Linux Elastic Agent
**Security Onion specific:** Uses Elastic Agent telemetry in Security Onion 3.1.0 for Linux hosts. Requires Elastic Agent endpoint, system, Windows, macOS, Linux, or Elastic Defend data streams with ECS host, process, file, registry, authentication, or network fields.

```kql
event.category:file and agent.type:"elastic-agent" and host.os.type:linux and event.action:(creation or modification) and file.path:("/home/*/.ssh/authorized_keys" or "/root/.ssh/authorized_keys")
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:file AND agent.type:"elastic-agent" AND host.os.type:linux AND event.action:(creation OR modification) AND file.path:("/home/*/.ssh/authorized_keys" OR "/root/.ssh/authorized_keys") | groupby host.name host.os.type user.name process.name process.parent.name destination.ip destination.port event.action | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line process.executable file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port destination.domain network.transport event.code rule.name
```

**Tuning ideas:** allowlist known admin scripts, software deployment tools, scanners, EDR activity, patch management, and sanctioned cloud apps before alerting.

---

## T1136.003 — Create Account: Cloud Account

**Tactic:** Persistence  
**Detection idea:** Creation of new cloud or SaaS accounts  
**Elastic implementation notes:** ECS field names vary by integration. Start with the KQL below, then tune for your Elastic Agent, Elastic Defend, Windows, System, Sysmon, cloud, and email data streams.

### Query 1
```kql
event.category:iam and event.action:(user-creation or add-user or create-user) and cloud.provider:*
```

### Query 2
```kql
event.dataset:("azure.auditlogs" or "o365.audit" or "google_workspace.admin") and event.action:("*Add user*" or "*Create user*" or "*New user*")
```

**Tuning ideas:** allowlist known admin scripts, software deployment tools, scanners, EDR activity, patch management, and sanctioned cloud apps before alerting.

---

## T1546.003 — Event Triggered Execution: Windows Management Instrumentation Event Subscription

**Tactic:** Persistence  
**Detection idea:** Creation of WMI permanent event subscriptions or suspicious WMI consumers  
**Elastic implementation notes:** ECS field names vary by integration. Start with the KQL below, then tune for your Elastic Agent, Elastic Defend, Windows, System, Sysmon, cloud, and email data streams.

### Query 1
```kql
event.category:process and process.name:("wmic.exe" or "powershell.exe" or "pwsh.exe") and process.command_line:("*__EventFilter*" or "*CommandLineEventConsumer*" or "*FilterToConsumerBinding*" or "*Register-WmiEvent*")
```

### Query 2
```kql
event.category:registry and registry.path:("*\\WBEM\\CIMOM*" or "*\\Microsoft\\Wbem\\CIMOM*") and event.action:(creation or modification)
```

### Query 3 — Security Onion Windows Elastic Agent
**Security Onion specific:** Uses Elastic Agent telemetry in Security Onion 3.1.0 for Windows hosts. Requires Elastic Agent endpoint, system, Windows, macOS, Linux, or Elastic Defend data streams with ECS host, process, file, registry, authentication, or network fields.

```kql
event.category:process and agent.type:"elastic-agent" and host.os.type:windows and process.name:("powershell.exe" or "wmic.exe" or "mofcomp.exe") and process.command_line:("*__EventFilter*" or "*CommandLineEventConsumer*" or "*FilterToConsumerBinding*" or "*Register-WmiEvent*" or "*.mof*")
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:process AND agent.type:"elastic-agent" AND host.os.type:windows AND process.name:("powershell.exe" OR "wmic.exe" OR "mofcomp.exe") AND process.command_line:("*__EventFilter*" OR "*CommandLineEventConsumer*" OR "*FilterToConsumerBinding*" OR "*Register-WmiEvent*" OR "*.mof*") | groupby host.name host.os.type user.name process.name process.parent.name destination.ip destination.port event.action | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line process.executable file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port destination.domain network.transport event.code rule.name
```

**Tuning ideas:** allowlist known admin scripts, software deployment tools, scanners, EDR activity, patch management, and sanctioned cloud apps before alerting.

---

## T1505.003 — Server Software Component: Web Shell

**Tactic:** Persistence  
**Detection idea:** Web shell file creation or suspicious web server child processes  
**Elastic implementation notes:** ECS field names vary by integration. Start with the KQL below, then tune for your Elastic Agent, Elastic Defend, Windows, System, Sysmon, cloud, and email data streams.

### Query 1
```kql
event.category:file and file.extension:(aspx or asp or php or jsp or cfm) and file.path:("*\\inetpub\\wwwroot\\*" or "*/var/www/*" or "*/usr/share/nginx/html/*") and event.action:(creation or modification)
```

### Query 2
```kql
event.category:process and process.parent.name:("w3wp.exe" or "httpd.exe" or "nginx.exe" or "php-fpm" or "tomcat.exe") and process.name:("cmd.exe" or "powershell.exe" or "pwsh.exe" or "bash" or "sh" or "python" or "perl")
```

### Query 3 — Security Onion Windows Elastic Agent
**Security Onion specific:** Uses Elastic Agent telemetry in Security Onion 3.1.0 for Windows hosts. Requires Elastic Agent endpoint, system, Windows, macOS, Linux, or Elastic Defend data streams with ECS host, process, file, registry, authentication, or network fields.

```kql
event.category:file and agent.type:"elastic-agent" and host.os.type:windows and event.action:(creation or modification) and file.path:("*\inetpub\wwwroot\*" or "*\Apache24\htdocs\*" or "*\nginx\html\*") and file.extension:(aspx or asp or php or jsp or ashx)
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:file AND agent.type:"elastic-agent" AND host.os.type:windows AND event.action:(creation OR modification) AND file.path:("*\inetpub\wwwroot\*" OR "*\Apache24\htdocs\*" OR "*\nginx\html\*") AND file.extension:(aspx OR asp OR php OR jsp OR ashx) | groupby host.name host.os.type user.name process.name process.parent.name destination.ip destination.port event.action | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line process.executable file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port destination.domain network.transport event.code rule.name
```

**Tuning ideas:** allowlist known admin scripts, software deployment tools, scanners, EDR activity, patch management, and sanctioned cloud apps before alerting.

---

## T1136.001 — Create Account: Local Account

**Tactic:** Persistence  
**Detection idea:** Local account creation on endpoints or servers  
**Elastic implementation notes:** ECS field names vary by integration. Start with the KQL below, then tune for your Elastic Agent, Elastic Defend, Windows, System, Sysmon, cloud, and email data streams.

### Query 1
```kql
event.category:process and process.name:("net.exe" or "net1.exe" or "powershell.exe" or "pwsh.exe") and process.command_line:("* user * /add*" or "*New-LocalUser*" or "*Add-LocalGroupMember*")
```

### Query 2
```kql
event.dataset:"windows.security" and event.code:(4720 or 4732)
```

### Query 3 — Security Onion Windows Elastic Agent
**Security Onion specific:** Uses Elastic Agent telemetry in Security Onion 3.1.0 for Windows hosts. Requires Elastic Agent endpoint, system, Windows, macOS, Linux, or Elastic Defend data streams with ECS host, process, file, registry, authentication, or network fields.

```kql
event.category:(process or iam) and agent.type:"elastic-agent" and host.os.type:windows and (process.command_line:("* user * /add*" or "*localgroup administrators* /add*" or "*New-LocalUser*" or "*Add-LocalGroupMember*") or event.code:(4720 or 4732))
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:(process OR iam) AND agent.type:"elastic-agent" AND host.os.type:windows AND (process.command_line:("* user * /add*" OR "*localgroup administrators* /add*" OR "*New-LocalUser*" OR "*Add-LocalGroupMember*") OR event.code:(4720 OR 4732)) | groupby host.name host.os.type user.name process.name process.parent.name destination.ip destination.port event.action | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line process.executable file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port destination.domain network.transport event.code rule.name
```

### Query 4 — Security Onion Linux Elastic Agent
**Security Onion specific:** Uses Elastic Agent telemetry in Security Onion 3.1.0 for Linux hosts. Requires Elastic Agent endpoint, system, Windows, macOS, Linux, or Elastic Defend data streams with ECS host, process, file, registry, authentication, or network fields.

```kql
event.category:process and agent.type:"elastic-agent" and host.os.type:linux and process.name:(useradd or adduser or usermod or gpasswd) and process.command_line:("* -m *" or "* -aG *" or "*sudo*" or "*wheel*" or "*root*")
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:process AND agent.type:"elastic-agent" AND host.os.type:linux AND process.name:(useradd OR adduser OR usermod OR gpasswd) AND process.command_line:("* -m *" OR "* -aG *" OR "*sudo*" OR "*wheel*" OR "*root*") | groupby host.name host.os.type user.name process.name process.parent.name destination.ip destination.port event.action | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line process.executable file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port destination.domain network.transport event.code rule.name
```

### Query 5 — Security Onion macOS Elastic Agent
**Security Onion specific:** Uses Elastic Agent telemetry in Security Onion 3.1.0 for macOS hosts. Requires Elastic Agent endpoint, system, Windows, macOS, Linux, or Elastic Defend data streams with ECS host, process, file, registry, authentication, or network fields.

```kql
event.category:process and agent.type:"elastic-agent" and host.os.type:macos and process.name:(sysadminctl or dscl or dseditgroup) and process.command_line:("*-addUser*" or "*create /Users*" or "*admin*" or "*-append*" or "*GroupMembership*")
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:process AND agent.type:"elastic-agent" AND host.os.type:macos AND process.name:(sysadminctl OR dscl OR dseditgroup) AND process.command_line:("*-addUser*" OR "*create /Users*" OR "*admin*" OR "*-append*" OR "*GroupMembership*") | groupby host.name host.os.type user.name process.name process.parent.name destination.ip destination.port event.action | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line process.executable file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port destination.domain network.transport event.code rule.name
```

**Tuning ideas:** allowlist known admin scripts, software deployment tools, scanners, EDR activity, patch management, and sanctioned cloud apps before alerting.

---

## T1136.002 — Create Account: Domain Account

**Tactic:** Persistence  
**Detection idea:** Domain account creation or privileged group membership changes  
**Elastic implementation notes:** ECS field names vary by integration. Start with the KQL below, then tune for your Elastic Agent, Elastic Defend, Windows, System, Sysmon, cloud, and email data streams.

### Query 1
```kql
event.dataset:"windows.security" and event.code:(4720 or 4728 or 4732 or 4756) and user.name:*
```

### Query 2
```kql
event.category:iam and event.action:(user-creation or add-user or group-membership-add) and user.name:*
```

**Tuning ideas:** allowlist known admin scripts, software deployment tools, scanners, EDR activity, patch management, and sanctioned cloud apps before alerting.

---

## T1547.009 — Boot or Logon Autostart Execution: Shortcut Modification

**Tactic:** Persistence  
**Detection idea:** Shortcut creation or modification in startup and user-writable locations  
**Elastic implementation notes:** ECS field names vary by integration. Start with the KQL below, then tune for your Elastic Agent, Elastic Defend, Windows, System, Sysmon, cloud, and email data streams.

### Query 1
```kql
event.category:file and file.extension:lnk and event.action:(creation or modification) and file.path:("*\\Start Menu\\Programs\\Startup\\*" or "*\\Desktop\\*" or "*\\Downloads\\*")
```

### Query 2
```kql
event.category:process and process.name:("powershell.exe" or "cmd.exe" or "wscript.exe" or "cscript.exe") and process.command_line:("*.lnk*" or "*Startup*" or "*WScript.Shell*" or "*CreateShortcut*")
```

**Tuning ideas:** allowlist known admin scripts, software deployment tools, scanners, EDR activity, patch management, and sanctioned cloud apps before alerting.

---

## T1053.003 — Scheduled Task/Job: Cron

**Tactic:** Persistence  
**Detection idea:** Creation or modification of Linux/macOS cron and at-job persistence locations from Elastic Agent file telemetry  
**Elastic implementation notes:** Linux/macOS host telemetry requires Elastic Agent with endpoint, system, or Elastic Defend integrations. Field availability varies by policy and event collection settings.

### Query 1 — Security Onion Linux/macOS Elastic Agent
**Security Onion specific:** Uses Elastic Agent telemetry in Security Onion 3.1.0 for Linux/macOS hosts. Requires Elastic Agent endpoint, system, or Elastic Defend data streams with ECS host, process, file, or network fields.

```kql
event.category:file and agent.type:"elastic-agent" and host.os.type:(linux or macos) and event.action:(creation or modification) and file.path:("/etc/crontab" or "/etc/cron.d/*" or "/etc/cron.hourly/*" or "/etc/cron.daily/*" or "/etc/cron.weekly/*" or "/var/spool/cron/*" or "/var/at/tabs/*")
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:file AND agent.type:"elastic-agent" AND host.os.type:(linux OR macos) AND event.action:(creation OR modification) AND file.path:("/etc/crontab" OR "/etc/cron.d/*" OR "/etc/cron.hourly/*" OR "/etc/cron.daily/*" OR "/etc/cron.weekly/*" OR "/var/spool/cron/*" OR "/var/at/tabs/*") | groupby host.name host.os.type user.name process.name source.ip destination.ip destination.port | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line file.path file.name file.extension source.ip source.port destination.ip destination.port network.transport network.community_id rule.name
```


**Tuning ideas:** allowlist approved admin scripts, package managers, MDM activity, backup tools, deployment systems, developer workflows, and sanctioned remote administration.

---

## T1543.002 — Create or Modify System Process: Systemd Service

**Tactic:** Persistence  
**Detection idea:** Systemd unit creation or modification on Linux hosts monitored by Elastic Agent  
**Elastic implementation notes:** Linux/macOS host telemetry requires Elastic Agent with endpoint, system, or Elastic Defend integrations. Field availability varies by policy and event collection settings.

### Query 1 — Security Onion Linux/macOS Elastic Agent
**Security Onion specific:** Uses Elastic Agent telemetry in Security Onion 3.1.0 for Linux/macOS hosts. Requires Elastic Agent endpoint, system, or Elastic Defend data streams with ECS host, process, file, or network fields.

```kql
event.category:file and agent.type:"elastic-agent" and host.os.type:linux and event.action:(creation or modification) and file.path:("/etc/systemd/system/*.service" or "/usr/lib/systemd/system/*.service" or "/lib/systemd/system/*.service" or "/run/systemd/system/*.service")
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:file AND agent.type:"elastic-agent" AND host.os.type:linux AND event.action:(creation OR modification) AND file.path:("/etc/systemd/system/*.service" OR "/usr/lib/systemd/system/*.service" OR "/lib/systemd/system/*.service" OR "/run/systemd/system/*.service") | groupby host.name host.os.type user.name process.name source.ip destination.ip destination.port | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line file.path file.name file.extension source.ip source.port destination.ip destination.port network.transport network.community_id rule.name
```


### Query 2 — Security Onion Linux Elastic Agent
**Security Onion specific:** Uses Elastic Agent telemetry in Security Onion 3.1.0 for Linux hosts. Requires Elastic Agent endpoint, system, Windows, macOS, Linux, or Elastic Defend data streams with ECS host, process, file, registry, authentication, or network fields.

```kql
event.category:process and agent.type:"elastic-agent" and host.os.type:linux and process.name:systemctl and process.command_line:("* enable *" or "* link *" or "* daemon-reload*" or "* start *")
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:process AND agent.type:"elastic-agent" AND host.os.type:linux AND process.name:systemctl AND process.command_line:("* enable *" OR "* link *" OR "* daemon-reload*" OR "* start *") | groupby host.name host.os.type user.name process.name process.parent.name destination.ip destination.port event.action | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line process.executable file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port destination.domain network.transport event.code rule.name
```

**Tuning ideas:** allowlist approved admin scripts, package managers, MDM activity, backup tools, deployment systems, developer workflows, and sanctioned remote administration.

---

## T1543.001 / T1543.004 — Create or Modify System Process: Launch Agent / Launch Daemon

**Tactic:** Persistence  
**Detection idea:** macOS LaunchAgent or LaunchDaemon plist creation or modification from Elastic Agent file telemetry  
**Elastic implementation notes:** Linux/macOS host telemetry requires Elastic Agent with endpoint, system, or Elastic Defend integrations. Field availability varies by policy and event collection settings.

### Query 1 — Security Onion Linux/macOS Elastic Agent
**Security Onion specific:** Uses Elastic Agent telemetry in Security Onion 3.1.0 for Linux/macOS hosts. Requires Elastic Agent endpoint, system, or Elastic Defend data streams with ECS host, process, file, or network fields.

```kql
event.category:file and agent.type:"elastic-agent" and host.os.type:macos and event.action:(creation or modification) and file.path:("/Library/LaunchAgents/*.plist" or "/Library/LaunchDaemons/*.plist" or "/Users/*/Library/LaunchAgents/*.plist" or "/System/Library/LaunchAgents/*.plist" or "/System/Library/LaunchDaemons/*.plist")
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:file AND agent.type:"elastic-agent" AND host.os.type:macos AND event.action:(creation OR modification) AND file.path:("/Library/LaunchAgents/*.plist" OR "/Library/LaunchDaemons/*.plist" OR "/Users/*/Library/LaunchAgents/*.plist" OR "/System/Library/LaunchAgents/*.plist" OR "/System/Library/LaunchDaemons/*.plist") | groupby host.name host.os.type user.name process.name source.ip destination.ip destination.port | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line file.path file.name file.extension source.ip source.port destination.ip destination.port network.transport network.community_id rule.name
```


### Query 2 — Security Onion macOS Elastic Agent
**Security Onion specific:** Uses Elastic Agent telemetry in Security Onion 3.1.0 for macOS hosts. Requires Elastic Agent endpoint, system, Windows, macOS, Linux, or Elastic Defend data streams with ECS host, process, file, registry, authentication, or network fields.

```kql
event.category:process and agent.type:"elastic-agent" and host.os.type:macos and process.name:launchctl and process.command_line:("*load*" or "*bootstrap*" or "*enable*" or "*kickstart*" or "*LaunchAgents*" or "*LaunchDaemons*")
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:process AND agent.type:"elastic-agent" AND host.os.type:macos AND process.name:launchctl AND process.command_line:("*load*" OR "*bootstrap*" OR "*enable*" OR "*kickstart*" OR "*LaunchAgents*" OR "*LaunchDaemons*") | groupby host.name host.os.type user.name process.name process.parent.name destination.ip destination.port event.action | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port network.transport network.community_id event.code rule.name
```

**Tuning ideas:** allowlist approved admin scripts, package managers, MDM activity, backup tools, deployment systems, developer workflows, and sanctioned remote administration.

---

## T1037.004 — Boot or Logon Initialization Scripts: RC Scripts

**Tactic:** Persistence  
**Detection idea:** Linux Elastic Agent rc.local or init script persistence file changes  
**Elastic implementation notes:** Host telemetry requires Elastic Agent with endpoint, system, Windows, macOS, Linux, or Elastic Defend integrations. Field availability varies by agent policy and event collection settings.

### Query 1 — Security Onion Linux Elastic Agent
**Security Onion specific:** Uses Elastic Agent telemetry in Security Onion 3.1.0 for Linux hosts. Requires Elastic Agent endpoint, system, Windows, macOS, Linux, or Elastic Defend data streams with ECS host, process, file, registry, authentication, or network fields.

```kql
event.category:file and agent.type:"elastic-agent" and host.os.type:linux and event.action:(creation or modification) and file.path:("/etc/rc.local" or "/etc/init.d/*" or "/etc/rc*.d/*")
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:file AND agent.type:"elastic-agent" AND host.os.type:linux AND event.action:(creation OR modification) AND file.path:("/etc/rc.local" OR "/etc/init.d/*" OR "/etc/rc*.d/*") | groupby host.name host.os.type user.name process.name process.parent.name destination.ip destination.port event.action | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port network.transport network.community_id event.code rule.name
```


**Tuning ideas:** allowlist approved admin scripts, package managers, MDM/GPO activity, backup tools, EDR activity, deployment systems, developer workflows, and sanctioned remote administration.

---

## T1547.006 — Boot or Logon Autostart Execution: Kernel Modules and Extensions

**Tactic:** Persistence  
**Detection idea:** Linux Elastic Agent kernel module loading or persistence configuration  
**Elastic implementation notes:** Host telemetry requires Elastic Agent with endpoint, system, Windows, macOS, Linux, or Elastic Defend integrations. Field availability varies by agent policy and event collection settings.

### Query 1 — Security Onion Linux Elastic Agent
**Security Onion specific:** Uses Elastic Agent telemetry in Security Onion 3.1.0 for Linux hosts. Requires Elastic Agent endpoint, system, Windows, macOS, Linux, or Elastic Defend data streams with ECS host, process, file, registry, authentication, or network fields.

```kql
event.category:process and agent.type:"elastic-agent" and host.os.type:linux and process.name:(insmod or modprobe or depmod) and process.command_line:*
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:process AND agent.type:"elastic-agent" AND host.os.type:linux AND process.name:(insmod OR modprobe OR depmod) AND process.command_line:* | groupby host.name host.os.type user.name process.name process.parent.name destination.ip destination.port event.action | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port network.transport network.community_id event.code rule.name
```


**Tuning ideas:** allowlist approved admin scripts, package managers, MDM/GPO activity, backup tools, EDR activity, deployment systems, developer workflows, and sanctioned remote administration.

---

## T1037.002 — Boot or Logon Initialization Scripts: Login Hook

**Tactic:** Persistence  
**Detection idea:** macOS Elastic Agent login hook or logout hook configuration via defaults  
**Elastic implementation notes:** Host telemetry requires Elastic Agent with endpoint, system, Windows, macOS, Linux, or Elastic Defend integrations. Field availability varies by agent policy and event collection settings.

### Query 1 — Security Onion macOS Elastic Agent
**Security Onion specific:** Uses Elastic Agent telemetry in Security Onion 3.1.0 for macOS hosts. Requires Elastic Agent endpoint, system, Windows, macOS, Linux, or Elastic Defend data streams with ECS host, process, file, registry, authentication, or network fields.

```kql
event.category:process and agent.type:"elastic-agent" and host.os.type:macos and process.name:defaults and process.command_line:("*LoginHook*" or "*LogoutHook*" or "*/var/root/Library/Preferences/com.apple.loginwindow*")
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:process AND agent.type:"elastic-agent" AND host.os.type:macos AND process.name:defaults AND process.command_line:("*LoginHook*" OR "*LogoutHook*" OR "*/var/root/Library/Preferences/com.apple.loginwindow*") | groupby host.name host.os.type user.name process.name process.parent.name destination.ip destination.port event.action | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port network.transport network.community_id event.code rule.name
```


**Tuning ideas:** allowlist approved admin scripts, package managers, MDM/GPO activity, backup tools, EDR activity, deployment systems, developer workflows, and sanctioned remote administration.

---

## T1547.011 — Boot or Logon Autostart Execution: Plist Modification

**Tactic:** Persistence  
**Detection idea:** macOS Elastic Agent suspicious plist modification in user or system launch locations  
**Elastic implementation notes:** Host telemetry requires Elastic Agent with endpoint, system, Windows, macOS, Linux, or Elastic Defend integrations. Field availability varies by agent policy and event collection settings.

### Query 1 — Security Onion macOS Elastic Agent
**Security Onion specific:** Uses Elastic Agent telemetry in Security Onion 3.1.0 for macOS hosts. Requires Elastic Agent endpoint, system, Windows, macOS, Linux, or Elastic Defend data streams with ECS host, process, file, registry, authentication, or network fields.

```kql
event.category:file and agent.type:"elastic-agent" and host.os.type:macos and event.action:(creation or modification) and file.path:("/Library/LaunchAgents/*.plist" or "/Library/LaunchDaemons/*.plist" or "/Users/*/Library/LaunchAgents/*.plist")
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:file AND agent.type:"elastic-agent" AND host.os.type:macos AND event.action:(creation OR modification) AND file.path:("/Library/LaunchAgents/*.plist" OR "/Library/LaunchDaemons/*.plist" OR "/Users/*/Library/LaunchAgents/*.plist") | groupby host.name host.os.type user.name process.name process.parent.name destination.ip destination.port event.action | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port network.transport network.community_id event.code rule.name
```


**Tuning ideas:** allowlist approved admin scripts, package managers, MDM/GPO activity, backup tools, EDR activity, deployment systems, developer workflows, and sanctioned remote administration.

---

## T1546.004 — Event Triggered Execution: Unix Shell Configuration Modification

**Tactic:** Persistence  
**Detection idea:** Linux Elastic Agent shell profile or shell startup persistence changes  
**Elastic implementation notes:** Host telemetry requires Elastic Agent with endpoint, system, Windows, macOS, Linux, or Elastic Defend integrations. Field availability varies by agent policy and event collection settings.

### Query 1 — Security Onion Linux Elastic Agent
**Security Onion specific:** Uses Elastic Agent telemetry in Security Onion 3.1.0 for Linux hosts. Requires Elastic Agent endpoint, system, Windows, macOS, Linux, or Elastic Defend data streams with ECS host, process, file, registry, authentication, or network fields.

```kql
event.category:file and agent.type:"elastic-agent" and host.os.type:linux and event.action:(creation or modification) and file.name:(".bashrc" or ".bash_profile" or ".profile" or ".zshrc" or ".zprofile")
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:file AND agent.type:"elastic-agent" AND host.os.type:linux AND event.action:(creation OR modification) AND file.name:(".bashrc" OR ".bash_profile" OR ".profile" OR ".zshrc" OR ".zprofile") | groupby host.name host.os.type user.name process.name process.parent.name destination.ip destination.port event.action | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line process.executable file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port destination.domain network.transport event.code rule.name
```


### Query 2 — Security Onion macOS Elastic Agent
**Security Onion specific:** Uses Elastic Agent telemetry in Security Onion 3.1.0 for macOS hosts. Requires Elastic Agent endpoint, system, Windows, macOS, Linux, or Elastic Defend data streams with ECS host, process, file, registry, authentication, or network fields.

```kql
event.category:file and agent.type:"elastic-agent" and host.os.type:macos and event.action:(creation or modification) and file.name:(".zshrc" or ".zprofile" or ".bash_profile" or ".bashrc" or ".profile") and file.path:"/Users/*"
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:file AND agent.type:"elastic-agent" AND host.os.type:macos AND event.action:(creation OR modification) AND file.name:(".zshrc" OR ".zprofile" OR ".bash_profile" OR ".bashrc" OR ".profile") AND file.path:"/Users/*" | groupby host.name host.os.type user.name process.name process.parent.name destination.ip destination.port event.action | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line process.executable file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port destination.domain network.transport event.code rule.name
```

**Tuning ideas:** allowlist approved admin scripts, package managers, MDM/GPO activity, backup tools, EDR activity, deployment systems, developer workflows, and sanctioned remote administration.

---

## T1546.016 — Event Triggered Execution: Installer Packages

**Tactic:** Persistence  
**Detection idea:** Linux Elastic Agent package manager script or hook persistence changes  
**Elastic implementation notes:** Host telemetry requires Elastic Agent with endpoint, system, Windows, macOS, Linux, or Elastic Defend integrations. Field availability varies by agent policy and event collection settings.

### Query 1 — Security Onion Linux Elastic Agent
**Security Onion specific:** Uses Elastic Agent telemetry in Security Onion 3.1.0 for Linux hosts. Requires Elastic Agent endpoint, system, Windows, macOS, Linux, or Elastic Defend data streams with ECS host, process, file, registry, authentication, or network fields.

```kql
event.category:file and agent.type:"elastic-agent" and host.os.type:linux and event.action:(creation or modification) and file.path:("/etc/apt/apt.conf.d/*" or "/etc/yum/pluginconf.d/*" or "/etc/dnf/plugins/*" or "/var/lib/dpkg/info/*.postinst")
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:file AND agent.type:"elastic-agent" AND host.os.type:linux AND event.action:(creation OR modification) AND file.path:("/etc/apt/apt.conf.d/*" OR "/etc/yum/pluginconf.d/*" OR "/etc/dnf/plugins/*" OR "/var/lib/dpkg/info/*.postinst") | groupby host.name host.os.type user.name process.name process.parent.name destination.ip destination.port event.action | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line process.executable file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port destination.domain network.transport event.code rule.name
```


**Tuning ideas:** allowlist approved admin scripts, package managers, MDM/GPO activity, backup tools, EDR activity, deployment systems, developer workflows, and sanctioned remote administration.

---

## T1546.011 — Event Triggered Execution: Application Shimming

**Tactic:** Persistence  
**Detection idea:** macOS Elastic Agent dynamic library injection or DYLD persistence indicators  
**Elastic implementation notes:** Host telemetry requires Elastic Agent with endpoint, system, Windows, macOS, Linux, or Elastic Defend integrations. Field availability varies by agent policy and event collection settings.

### Query 1 — Security Onion macOS Elastic Agent
**Security Onion specific:** Uses Elastic Agent telemetry in Security Onion 3.1.0 for macOS hosts. Requires Elastic Agent endpoint, system, Windows, macOS, Linux, or Elastic Defend data streams with ECS host, process, file, registry, authentication, or network fields.

```kql
event.category:process and agent.type:"elastic-agent" and host.os.type:macos and process.command_line:("*DYLD_INSERT_LIBRARIES*" or "*DYLD_LIBRARY_PATH*" or "*insert_dylib*" or "*install_name_tool*")
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:process AND agent.type:"elastic-agent" AND host.os.type:macos AND process.command_line:("*DYLD_INSERT_LIBRARIES*" OR "*DYLD_LIBRARY_PATH*" OR "*insert_dylib*" OR "*install_name_tool*") | groupby host.name host.os.type user.name process.name process.parent.name destination.ip destination.port event.action | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line process.executable file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port destination.domain network.transport event.code rule.name
```


**Tuning ideas:** allowlist approved admin scripts, package managers, MDM/GPO activity, backup tools, EDR activity, deployment systems, developer workflows, and sanctioned remote administration.

---

## T1546.008 — Event Triggered Execution: Accessibility Features

**Tactic:** Persistence / Privilege Escalation  
**Detection idea:** Windows Elastic Agent accessibility binary replacement or debugger persistence indicators  
**Elastic implementation notes:** Host telemetry requires Elastic Agent with endpoint, system, Windows, macOS, Linux, or Elastic Defend integrations. Field availability varies by agent policy and event collection settings.

### Query 1 — Security Onion Windows Elastic Agent
**Security Onion specific:** Uses Elastic Agent telemetry in Security Onion 3.1.0 for Windows hosts. Requires Elastic Agent endpoint, system, Windows, macOS, Linux, or Elastic Defend data streams with ECS host, process, file, registry, authentication, or network fields.

```kql
event.category:(process or registry or file) and agent.type:"elastic-agent" and host.os.type:windows and (process.command_line:("*sethc.exe*" or "*utilman.exe*" or "*osk.exe*" or "*magnify.exe*") or registry.path:"*\Image File Execution Options\*")
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:(process OR registry OR file) AND agent.type:"elastic-agent" AND host.os.type:windows AND (process.command_line:("*sethc.exe*" OR "*utilman.exe*" OR "*osk.exe*" OR "*magnify.exe*") OR registry.path:"*\Image File Execution Options\*") | groupby host.name host.os.type user.name process.name process.parent.name destination.ip destination.port event.action | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line process.executable file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port destination.domain network.transport event.code rule.name
```


**Tuning ideas:** allowlist approved admin scripts, package managers, MDM/GPO activity, backup tools, EDR activity, deployment systems, developer workflows, and sanctioned remote administration.

---

## T1546.012 — Event Triggered Execution: Image File Execution Options Injection

**Tactic:** Persistence / Privilege Escalation  
**Detection idea:** Windows Elastic Agent IFEO debugger key creation or modification  
**Elastic implementation notes:** Host telemetry requires Elastic Agent with endpoint, system, Windows, macOS, Linux, or Elastic Defend integrations. Field availability varies by agent policy and event collection settings.

### Query 1 — Security Onion Windows Elastic Agent
**Security Onion specific:** Uses Elastic Agent telemetry in Security Onion 3.1.0 for Windows hosts. Requires Elastic Agent endpoint, system, Windows, macOS, Linux, or Elastic Defend data streams with ECS host, process, file, registry, authentication, or network fields.

```kql
event.category:registry and agent.type:"elastic-agent" and host.os.type:windows and registry.path:"*\Image File Execution Options\*\Debugger" and event.action:(creation or modification)
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:registry AND agent.type:"elastic-agent" AND host.os.type:windows AND registry.path:"*\Image File Execution Options\*\Debugger" AND event.action:(creation OR modification) | groupby host.name host.os.type user.name process.name process.parent.name destination.ip destination.port event.action | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line process.executable file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port destination.domain network.transport event.code rule.name
```


**Tuning ideas:** allowlist approved admin scripts, package managers, MDM/GPO activity, backup tools, EDR activity, deployment systems, developer workflows, and sanctioned remote administration.

---

## T1053.006 — Scheduled Task/Job: Systemd Timers

**Tactic:** Persistence  
**Detection idea:** Linux Elastic Agent systemd timer file creation or modification  
**Elastic implementation notes:** Host telemetry requires Elastic Agent with endpoint, system, Windows, macOS, Linux, or Elastic Defend integrations. Field availability varies by agent policy and event collection settings.

### Query 1 — Security Onion Linux Elastic Agent
**Security Onion specific:** Uses Elastic Agent telemetry in Security Onion 3.1.0 for Linux hosts. Requires Elastic Agent endpoint, system, Windows, macOS, Linux, or Elastic Defend data streams with ECS host, process, file, registry, authentication, or network fields.

```kql
event.category:file and agent.type:"elastic-agent" and host.os.type:linux and event.action:(creation or modification) and file.path:("/etc/systemd/system/*.timer" or "/usr/lib/systemd/system/*.timer" or "/lib/systemd/system/*.timer")
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:file AND agent.type:"elastic-agent" AND host.os.type:linux AND event.action:(creation OR modification) AND file.path:("/etc/systemd/system/*.timer" OR "/usr/lib/systemd/system/*.timer" OR "/lib/systemd/system/*.timer") | groupby host.name host.os.type user.name process.name process.parent.name destination.ip destination.port event.action | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line process.executable file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port destination.domain network.transport event.code rule.name
```


**Tuning ideas:** allowlist approved admin scripts, package managers, MDM/GPO activity, backup tools, EDR activity, deployment systems, developer workflows, and sanctioned remote administration.

---

## T1053.002 — Scheduled Task/Job: At

**Tactic:** Persistence  
**Detection idea:** Linux Elastic Agent at-job scheduling or spool file creation  
**Elastic implementation notes:** Host telemetry requires Elastic Agent with endpoint, system, Windows, macOS, Linux, or Elastic Defend integrations. Field availability varies by agent policy and event collection settings.

### Query 1 — Security Onion Linux Elastic Agent
**Security Onion specific:** Uses Elastic Agent telemetry in Security Onion 3.1.0 for Linux hosts. Requires Elastic Agent endpoint, system, Windows, macOS, Linux, or Elastic Defend data streams with ECS host, process, file, registry, authentication, or network fields.

```kql
event.category:(process or file) and agent.type:"elastic-agent" and host.os.type:linux and (process.name:(at or atd or batch) or file.path:("/var/spool/at/*" or "/var/spool/cron/atjobs/*"))
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:(process OR file) AND agent.type:"elastic-agent" AND host.os.type:linux AND (process.name:(at OR atd OR batch) OR file.path:("/var/spool/at/*" OR "/var/spool/cron/atjobs/*")) | groupby host.name host.os.type user.name process.name process.parent.name destination.ip destination.port event.action | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line process.executable file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port destination.domain network.transport event.code rule.name
```


**Tuning ideas:** allowlist approved admin scripts, package managers, MDM/GPO activity, backup tools, EDR activity, deployment systems, developer workflows, and sanctioned remote administration.

---

## T1546.014 — Event Triggered Execution: Emond

**Tactic:** Persistence  
**Detection idea:** macOS Elastic Agent emond rule or plist persistence changes  
**Elastic implementation notes:** Host telemetry requires Elastic Agent with endpoint, system, Windows, macOS, Linux, or Elastic Defend integrations. Field availability varies by agent policy and event collection settings.

### Query 1 — Security Onion macOS Elastic Agent
**Security Onion specific:** Uses Elastic Agent telemetry in Security Onion 3.1.0 for macOS hosts. Requires Elastic Agent endpoint, system, Windows, macOS, Linux, or Elastic Defend data streams with ECS host, process, file, registry, authentication, or network fields.

```kql
event.category:file and agent.type:"elastic-agent" and host.os.type:macos and event.action:(creation or modification) and file.path:("/etc/emond.d/*" or "/private/etc/emond.d/*")
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:file AND agent.type:"elastic-agent" AND host.os.type:macos AND event.action:(creation OR modification) AND file.path:("/etc/emond.d/*" OR "/private/etc/emond.d/*") | groupby host.name host.os.type user.name process.name process.parent.name destination.ip destination.port event.action | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line process.executable file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port destination.domain network.transport event.code rule.name
```


**Tuning ideas:** allowlist approved admin scripts, package managers, MDM/GPO activity, backup tools, EDR activity, deployment systems, developer workflows, and sanctioned remote administration.

---

## T1547.015 — Boot or Logon Autostart Execution: Login Items

**Tactic:** Persistence  
**Detection idea:** macOS Elastic Agent login item persistence through osascript or helper utilities  
**Elastic implementation notes:** Host telemetry requires Elastic Agent with endpoint, system, Windows, macOS, Linux, or Elastic Defend integrations. Field availability varies by agent policy and event collection settings.

### Query 1 — Security Onion macOS Elastic Agent
**Security Onion specific:** Uses Elastic Agent telemetry in Security Onion 3.1.0 for macOS hosts. Requires Elastic Agent endpoint, system, Windows, macOS, Linux, or Elastic Defend data streams with ECS host, process, file, registry, authentication, or network fields.

```kql
event.category:process and agent.type:"elastic-agent" and host.os.type:macos and process.name:(osascript or sfltool) and process.command_line:("*login item*" or "*LoginItems*" or "*System Events*" or "*com.apple.LSSharedFileList*")
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:process AND agent.type:"elastic-agent" AND host.os.type:macos AND process.name:(osascript OR sfltool) AND process.command_line:("*login item*" OR "*LoginItems*" OR "*System Events*" OR "*com.apple.LSSharedFileList*") | groupby host.name host.os.type user.name process.name process.parent.name destination.ip destination.port event.action | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line process.executable file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port destination.domain network.transport event.code rule.name
```


**Tuning ideas:** allowlist approved admin scripts, package managers, MDM/GPO activity, backup tools, EDR activity, deployment systems, developer workflows, and sanctioned remote administration.

---

---

## T1197 — BITS Jobs

**Tactic:** Persistence  
**Detection idea:** Long-lived BITS transfer jobs with notification commands or payload retrieval paths that can survive reboots.  
**Elastic implementation notes:** These filters use ECS-style fields commonly present in Elastic Agent, Elastic Defend, Windows, Linux, macOS, Zeek, and Suricata data streams. Tune command-line patterns and administrative allowlists before production use.

### Query 1 — Security Onion Windows Elastic Agent
**Security Onion specific:** Uses Elastic Agent or Security Onion network telemetry in Security Onion 3.1.0. Requires the relevant endpoint, Zeek, Suricata, Windows, Linux, macOS, system, or Elastic Defend data streams with ECS-compatible fields.

```kql
event.category:process and agent.type:"elastic-agent" and host.os.type:windows and process.name:"bitsadmin.exe" and process.command_line:("*/setnotifycmdline*" or "*/SetNotifyCmdLine*" or "*/setminretrydelay*" or "*/setcustomheaders*")
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:process AND agent.type:"elastic-agent" AND host.os.type:windows AND process.name:"bitsadmin.exe" AND process.command_line:("*/setnotifycmdline*" OR "*/SetNotifyCmdLine*" OR "*/setminretrydelay*" OR "*/setcustomheaders*") | groupby host.name host.os.type user.name process.name process.parent.name event.action destination.ip destination.port | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line process.executable file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port destination.domain network.transport network.community_id event.code rule.name
```
### Query 2 — Security Onion Windows Elastic Agent
**Security Onion specific:** Uses Elastic Agent or Security Onion network telemetry in Security Onion 3.1.0. Requires the relevant endpoint, Zeek, Suricata, Windows, Linux, macOS, system, or Elastic Defend data streams with ECS-compatible fields.

```kql
event.category:process and agent.type:"elastic-agent" and host.os.type:windows and process.name:("powershell.exe" or "pwsh.exe") and process.command_line:("*BitsTransfer*" or "*Background Intelligent Transfer*" or "*SetNotifyCmdLine*" or "*IBackgroundCopyJob*")
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:process AND agent.type:"elastic-agent" AND host.os.type:windows AND process.name:("powershell.exe" OR "pwsh.exe") AND process.command_line:("*BitsTransfer*" OR "*Background Intelligent Transfer*" OR "*SetNotifyCmdLine*" OR "*IBackgroundCopyJob*") | groupby host.name host.os.type user.name process.name process.parent.name event.action destination.ip destination.port | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line process.executable file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port destination.domain network.transport network.community_id event.code rule.name
```
### Query 3 — Security Onion Windows Elastic Agent
**Security Onion specific:** Uses Elastic Agent or Security Onion network telemetry in Security Onion 3.1.0. Requires the relevant endpoint, Zeek, Suricata, Windows, Linux, macOS, system, or Elastic Defend data streams with ECS-compatible fields.

```kql
event.category:file and agent.type:"elastic-agent" and host.os.type:windows and event.action:(creation or modification) and file.path:("C:\ProgramData\Microsoft\Network\Downloader\*" or "C:\Windows\System32\config\systemprofile\AppData\Local\Microsoft\Windows\INetCache\*")
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:file AND agent.type:"elastic-agent" AND host.os.type:windows AND event.action:(creation OR modification) AND file.path:("C:\ProgramData\Microsoft\Network\Downloader\*" OR "C:\Windows\System32\config\systemprofile\AppData\Local\Microsoft\Windows\INetCache\*") | groupby host.name host.os.type user.name process.name process.parent.name event.action destination.ip destination.port | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line process.executable file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port destination.domain network.transport network.community_id event.code rule.name
```

**Tuning ideas:** allowlist known administrators, software deployment tools, EDR activity, inventory systems, vulnerability scanners, patching tools, and sanctioned management workflows before alerting.

---

## T1176 — Software Extensions

**Tactic:** Persistence  
**Detection idea:** Browser or IDE extension installation, sideloading, and extension manifest changes used for persistent access.  
**Elastic implementation notes:** These filters use ECS-style fields commonly present in Elastic Agent, Elastic Defend, Windows, Linux, macOS, Zeek, and Suricata data streams. Tune command-line patterns and administrative allowlists before production use.

### Query 1 — Security Onion Windows Elastic Agent
**Security Onion specific:** Uses Elastic Agent or Security Onion network telemetry in Security Onion 3.1.0. Requires the relevant endpoint, Zeek, Suricata, Windows, Linux, macOS, system, or Elastic Defend data streams with ECS-compatible fields.

```kql
event.category:file and agent.type:"elastic-agent" and host.os.type:windows and event.action:(creation or modification) and file.path:("*\Chrome\User Data\*\Extensions\*" or "*\Microsoft\Edge\User Data\*\Extensions\*" or "*\Mozilla\Firefox\Profiles\*\extensions\*") and file.name:("manifest.json" or "*.xpi" or "*.crx")
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:file AND agent.type:"elastic-agent" AND host.os.type:windows AND event.action:(creation OR modification) AND file.path:("*\Chrome\User Data\*\Extensions\*" OR "*\Microsoft\Edge\User Data\*\Extensions\*" OR "*\Mozilla\Firefox\Profiles\*\extensions\*") AND file.name:("manifest.json" OR "*.xpi" OR "*.crx") | groupby host.name host.os.type user.name process.name process.parent.name event.action destination.ip destination.port | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line process.executable file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port destination.domain network.transport network.community_id event.code rule.name
```
### Query 2 — Security Onion Linux Elastic Agent
**Security Onion specific:** Uses Elastic Agent or Security Onion network telemetry in Security Onion 3.1.0. Requires the relevant endpoint, Zeek, Suricata, Windows, Linux, macOS, system, or Elastic Defend data streams with ECS-compatible fields.

```kql
event.category:file and agent.type:"elastic-agent" and host.os.type:linux and event.action:(creation or modification) and file.path:("*/.config/google-chrome/*/Extensions/*" or "*/.config/chromium/*/Extensions/*" or "*/.mozilla/firefox/*/extensions/*" or "*/.vscode/extensions/*")
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:file AND agent.type:"elastic-agent" AND host.os.type:linux AND event.action:(creation OR modification) AND file.path:("*/.config/google-chrome/*/Extensions/*" OR "*/.config/chromium/*/Extensions/*" OR "*/.mozilla/firefox/*/extensions/*" OR "*/.vscode/extensions/*") | groupby host.name host.os.type user.name process.name process.parent.name event.action destination.ip destination.port | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line process.executable file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port destination.domain network.transport network.community_id event.code rule.name
```
### Query 3 — Security Onion macOS Elastic Agent
**Security Onion specific:** Uses Elastic Agent or Security Onion network telemetry in Security Onion 3.1.0. Requires the relevant endpoint, Zeek, Suricata, Windows, Linux, macOS, system, or Elastic Defend data streams with ECS-compatible fields.

```kql
event.category:file and agent.type:"elastic-agent" and host.os.type:macos and event.action:(creation or modification) and file.path:("*/Library/Application Support/Google/Chrome/*/Extensions/*" or "*/Library/Application Support/Microsoft Edge/*/Extensions/*" or "*/Library/Application Support/Firefox/Profiles/*/extensions/*" or "*/.vscode/extensions/*")
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:file AND agent.type:"elastic-agent" AND host.os.type:macos AND event.action:(creation OR modification) AND file.path:("*/Library/Application Support/Google/Chrome/*/Extensions/*" OR "*/Library/Application Support/Microsoft Edge/*/Extensions/*" OR "*/Library/Application Support/Firefox/Profiles/*/extensions/*" OR "*/.vscode/extensions/*") | groupby host.name host.os.type user.name process.name process.parent.name event.action destination.ip destination.port | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line process.executable file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port destination.domain network.transport network.community_id event.code rule.name
```

**Tuning ideas:** allowlist known administrators, software deployment tools, EDR activity, inventory systems, vulnerability scanners, patching tools, and sanctioned management workflows before alerting.

---

## T1546.013 — Event Triggered Execution: PowerShell Profile

**Tactic:** Persistence / Privilege Escalation  
**Detection idea:** Creation or modification of PowerShell profile scripts used to execute commands at shell startup.  
**Elastic implementation notes:** These filters use ECS-style fields commonly present in Elastic Agent, Elastic Defend, Windows, Linux, macOS, Zeek, Suricata, cloud, and SaaS data streams. Tune command-line patterns, data views, and administrative allowlists before production use.

### Query 1 — Security Onion Windows Elastic Agent
**Security Onion specific:** Uses Elastic Agent or Security Onion telemetry in Security Onion 3.1.0. Requires the relevant endpoint, Zeek, Suricata, cloud, SaaS, Windows, Linux, macOS, system, or Elastic Defend data streams with ECS-compatible fields.

```kql
event.category:file and agent.type:"elastic-agent" and host.os.type:windows and event.action:(creation or modification) and file.path:("*\Documents\WindowsPowerShell\Microsoft.PowerShell_profile.ps1" or "*\Documents\PowerShell\Microsoft.PowerShell_profile.ps1" or "*\WindowsPowerShell\profile.ps1")
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:file AND agent.type:"elastic-agent" AND host.os.type:windows AND event.action:(creation OR modification) AND file.path:("*\Documents\WindowsPowerShell\Microsoft.PowerShell_profile.ps1" OR "*\Documents\PowerShell\Microsoft.PowerShell_profile.ps1" OR "*\WindowsPowerShell\profile.ps1") | groupby host.name host.os.type user.name process.name process.parent.name event.action destination.ip destination.port | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line process.executable file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port destination.domain network.transport network.community_id event.code rule.name
```
### Query 2 — Security Onion Windows Elastic Agent
**Security Onion specific:** Uses Elastic Agent or Security Onion telemetry in Security Onion 3.1.0. Requires the relevant endpoint, Zeek, Suricata, cloud, SaaS, Windows, Linux, macOS, system, or Elastic Defend data streams with ECS-compatible fields.

```kql
event.category:process and agent.type:"elastic-agent" and host.os.type:windows and process.name:("powershell.exe" or "pwsh.exe") and process.command_line:("*$PROFILE*" or "*Microsoft.PowerShell_profile.ps1*" or "*CurrentUserAllHosts*" or "*AllUsersAllHosts*")
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:process AND agent.type:"elastic-agent" AND host.os.type:windows AND process.name:("powershell.exe" OR "pwsh.exe") AND process.command_line:("*$PROFILE*" OR "*Microsoft.PowerShell_profile.ps1*" OR "*CurrentUserAllHosts*" OR "*AllUsersAllHosts*") | groupby host.name host.os.type user.name process.name process.parent.name event.action destination.ip destination.port | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line process.executable file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port destination.domain network.transport network.community_id event.code rule.name
```

**Tuning ideas:** allowlist known administrators, software deployment tools, EDR activity, backup agents, inventory systems, vulnerability scanners, patching tools, and sanctioned management workflows before alerting.

---

## T1547.014 — Boot or Logon Autostart Execution: Active Setup

**Tactic:** Persistence / Privilege Escalation  
**Detection idea:** Active Setup registry changes that trigger user-logon command execution.  
**Elastic implementation notes:** These filters use ECS-style fields commonly present in Elastic Agent, Elastic Defend, Windows, Linux, macOS, Zeek, Suricata, cloud, and SaaS data streams. Tune command-line patterns, data views, and administrative allowlists before production use.

### Query 1 — Security Onion Windows Elastic Agent
**Security Onion specific:** Uses Elastic Agent or Security Onion telemetry in Security Onion 3.1.0. Requires the relevant endpoint, Zeek, Suricata, cloud, SaaS, Windows, Linux, macOS, system, or Elastic Defend data streams with ECS-compatible fields.

```kql
event.category:registry and agent.type:"elastic-agent" and host.os.type:windows and registry.path:("*\Microsoft\Active Setup\Installed Components\*\StubPath" or "*\Wow6432Node\Microsoft\Active Setup\Installed Components\*\StubPath")
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:registry AND agent.type:"elastic-agent" AND host.os.type:windows AND registry.path:("*\Microsoft\Active Setup\Installed Components\*\StubPath" OR "*\Wow6432Node\Microsoft\Active Setup\Installed Components\*\StubPath") | groupby host.name host.os.type user.name process.name process.parent.name event.action destination.ip destination.port | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line process.executable file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port destination.domain network.transport network.community_id event.code rule.name
```
### Query 2 — Security Onion Windows Elastic Agent
**Security Onion specific:** Uses Elastic Agent or Security Onion telemetry in Security Onion 3.1.0. Requires the relevant endpoint, Zeek, Suricata, cloud, SaaS, Windows, Linux, macOS, system, or Elastic Defend data streams with ECS-compatible fields.

```kql
event.category:process and agent.type:"elastic-agent" and host.os.type:windows and process.name:"reg.exe" and process.command_line:("*Active Setup*" or "*Installed Components*" or "*StubPath*")
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:process AND agent.type:"elastic-agent" AND host.os.type:windows AND process.name:"reg.exe" AND process.command_line:("*Active Setup*" OR "*Installed Components*" OR "*StubPath*") | groupby host.name host.os.type user.name process.name process.parent.name event.action destination.ip destination.port | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line process.executable file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port destination.domain network.transport network.community_id event.code rule.name
```

**Tuning ideas:** allowlist known administrators, software deployment tools, EDR activity, backup agents, inventory systems, vulnerability scanners, patching tools, and sanctioned management workflows before alerting.

---

## T1137 — Office Application Startup

**Tactic:** Persistence  
**Detection idea:** Office startup folder, template, add-in, and registry persistence used to launch code with Office applications.  
**Elastic implementation notes:** These filters use ECS-style fields commonly present in Elastic Agent, Elastic Defend, Windows, Linux, macOS, Zeek, Suricata, cloud, and SaaS data streams. Tune command-line patterns, data views, and administrative allowlists before production use.

### Query 1 — Security Onion Windows Elastic Agent
**Security Onion specific:** Uses Elastic Agent or Security Onion telemetry in Security Onion 3.1.0. Requires the relevant endpoint, Zeek, Suricata, cloud, SaaS, Windows, Linux, macOS, system, or Elastic Defend data streams with ECS-compatible fields.

```kql
event.category:file and agent.type:"elastic-agent" and host.os.type:windows and event.action:(creation or modification) and file.path:("*\Microsoft\Word\STARTUP\*" or "*\Microsoft\Excel\XLSTART\*" or "*\Microsoft\AddIns\*" or "*\Templates\Normal.dotm")
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:file AND agent.type:"elastic-agent" AND host.os.type:windows AND event.action:(creation OR modification) AND file.path:("*\Microsoft\Word\STARTUP\*" OR "*\Microsoft\Excel\XLSTART\*" OR "*\Microsoft\AddIns\*" OR "*\Templates\Normal.dotm") | groupby host.name host.os.type user.name process.name process.parent.name event.action destination.ip destination.port | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line process.executable file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port destination.domain network.transport network.community_id event.code rule.name
```
### Query 2 — Security Onion Windows Elastic Agent
**Security Onion specific:** Uses Elastic Agent or Security Onion telemetry in Security Onion 3.1.0. Requires the relevant endpoint, Zeek, Suricata, cloud, SaaS, Windows, Linux, macOS, system, or Elastic Defend data streams with ECS-compatible fields.

```kql
event.category:registry and agent.type:"elastic-agent" and host.os.type:windows and registry.path:("*\Microsoft\Office\*\Addins\*" or "*\Microsoft\Office\*\Word\Options*" or "*\Microsoft\Office\*\Excel\Options*")
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:registry AND agent.type:"elastic-agent" AND host.os.type:windows AND registry.path:("*\Microsoft\Office\*\Addins\*" OR "*\Microsoft\Office\*\Word\Options*" OR "*\Microsoft\Office\*\Excel\Options*") | groupby host.name host.os.type user.name process.name process.parent.name event.action destination.ip destination.port | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line process.executable file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port destination.domain network.transport network.community_id event.code rule.name
```

**Tuning ideas:** allowlist known administrators, software deployment tools, EDR activity, backup agents, inventory systems, vulnerability scanners, patching tools, and sanctioned management workflows before alerting.

