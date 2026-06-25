# TA0002 — Execution

> Query dialect: Elastic Kibana Query Language (**Elastic KQL**) using ECS-style fields. These are hunting-grade filters intended for Kibana Discover, Timeline, and Elastic Security rules. Tune fields, data views, and allowlists to your environment.

**Coverage count:** 20 technique sections / 48 KQL queries

## Techniques in this tactic

- [T1059.001 — PowerShell](SO_TA0002_Execution.md#t1059.001-powershell) — 3 queries
- [T1059.003 — Windows Command Shell](SO_TA0002_Execution.md#t1059.003-windows-command-shell) — 3 queries
- [T1047 — Windows Management Instrumentation](SO_TA0002_Execution.md#t1047-windows-management-instrumentation) — 3 queries
- [T1204.002 — User Execution: Malicious File](SO_TA0002_Execution.md#t1204.002-user-execution-malicious-file) — 5 queries
- [T1059.005 — Command and Scripting Interpreter: Visual Basic](SO_TA0002_Execution.md#t1059.005-command-and-scripting-interpreter-visual-basic) — 3 queries
- [T1059.006 — Command and Scripting Interpreter: Python](SO_TA0002_Execution.md#t1059.006-command-and-scripting-interpreter-python) — 4 queries
- [T1059.007 — Command and Scripting Interpreter: JavaScript](SO_TA0002_Execution.md#t1059.007-command-and-scripting-interpreter-javascript) — 4 queries
- [T1203 — Exploitation for Client Execution](SO_TA0002_Execution.md#t1203-exploitation-for-client-execution) — 2 queries
- [T1059.004 — Command and Scripting Interpreter: Unix Shell](SO_TA0002_Execution.md#t1059.004-command-and-scripting-interpreter-unix-shell) — 3 queries
- [T1059.002 — Command and Scripting Interpreter: AppleScript](SO_TA0002_Execution.md#t1059.002-command-and-scripting-interpreter-applescript) — 1 query
- [T1106 — Native API](SO_TA0002_Execution.md#t1106-native-api) — 1 query
- [T1127.001 — Trusted Developer Utilities Proxy Execution: MSBuild](SO_TA0002_Execution.md#t1127.001-trusted-developer-utilities-proxy-execution-msbuild) — 1 query
- [T1218.007 — System Binary Proxy Execution: Msiexec](SO_TA0002_Execution.md#t1218.007-system-binary-proxy-execution-msiexec) — 1 query
- [T1059.008 — Command and Scripting Interpreter: Network Device CLI](SO_TA0002_Execution.md#t1059.008-command-and-scripting-interpreter-network-device-cli) — 1 query
- [T1197 — BITS Jobs](SO_TA0002_Execution.md#t1197-bits-jobs) — 3 queries
- [T1129 — Shared Modules](SO_TA0002_Execution.md#t1129-shared-modules) — 2 queries
- [T1559.001 — Inter-Process Communication: Component Object Model](SO_TA0002_Execution.md#t1559.001-inter-process-communication-component-object-model) — 2 queries
- [T1559.002 — Inter-Process Communication: Dynamic Data Exchange](SO_TA0002_Execution.md#t1559.002-inter-process-communication-dynamic-data-exchange) — 2 queries
- [T1218.004 — System Binary Proxy Execution: InstallUtil](SO_TA0002_Execution.md#t1218.004-system-binary-proxy-execution-installutil) — 2 queries
- [T1218.013 — System Binary Proxy Execution: Mavinject](SO_TA0002_Execution.md#t1218.013-system-binary-proxy-execution-mavinject) — 2 queries

---

## T1059.001 — PowerShell

**Tactic:** Execution  
**Detection idea:** PowerShell with encoded, hidden, download, or in-memory execution indicators  
**Elastic implementation notes:** ECS field names vary by integration. Start with the KQL below, then tune for your Elastic Agent, Elastic Defend, Windows, System, Sysmon, cloud, and email data streams.

### Query 1
```kql
event.category:process and process.name:("powershell.exe" or "pwsh.exe") and process.command_line:("*EncodedCommand*" or "*-enc*" or "*FromBase64String*" or "*IEX*" or "*Invoke-Expression*" or "*DownloadString*" or "*DownloadFile*" or "*WebClient*" or "*Net.WebRequest*" or "*-nop*" or "*-w hidden*" or "*bypass*")
```

### Query 2
```kql
event.category:process and process.name:("powershell.exe" or "pwsh.exe") and process.parent.name:("winword.exe" or "excel.exe" or "powerpnt.exe" or "outlook.exe" or "mshta.exe" or "wscript.exe" or "cscript.exe")
```

### Query 3 — Security Onion Windows Elastic Agent
**Security Onion specific:** Uses Elastic Agent telemetry in Security Onion 3.1.0 for Windows hosts. Requires Elastic Agent endpoint, system, Windows, macOS, Linux, or Elastic Defend data streams with ECS host, process, file, registry, authentication, or network fields.

```kql
event.category:process and agent.type:"elastic-agent" and host.os.type:windows and process.name:("powershell.exe" or "pwsh.exe") and process.command_line:("*-EncodedCommand*" or "*-enc *" or "*FromBase64String*" or "*AmsiUtils*" or "*amsiInitFailed*" or "*IEX*" or "*Invoke-WebRequest*" or "*DownloadString*")
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:process AND agent.type:"elastic-agent" AND host.os.type:windows AND process.name:("powershell.exe" OR "pwsh.exe") AND process.command_line:("*-EncodedCommand*" OR "*-enc *" OR "*FromBase64String*" OR "*AmsiUtils*" OR "*amsiInitFailed*" OR "*IEX*" OR "*Invoke-WebRequest*" OR "*DownloadString*") | groupby host.name host.os.type user.name process.name process.parent.name destination.ip destination.port event.action | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port network.transport network.community_id event.code rule.name
```

**Tuning ideas:** allowlist known admin scripts, software deployment tools, scanners, EDR activity, patch management, and sanctioned cloud apps before alerting.

---

## T1059.003 — Windows Command Shell

**Tactic:** Execution  
**Detection idea:** Suspicious cmd.exe execution used for staging, discovery, or defense evasion  
**Elastic implementation notes:** ECS field names vary by integration. Start with the KQL below, then tune for your Elastic Agent, Elastic Defend, Windows, System, Sysmon, cloud, and email data streams.

### Query 1
```kql
event.category:process and process.name:"cmd.exe" and process.command_line:("*/c powershell*" or "*/c certutil*" or "*/c bitsadmin*" or "*/c curl*" or "*/c wget*" or "*/c whoami*" or "*/c net user*" or "*/c net group*")
```

### Query 2
```kql
event.category:process and process.name:"cmd.exe" and process.parent.name:("winword.exe" or "excel.exe" or "powerpnt.exe" or "outlook.exe" or "acrord32.exe" or "mshta.exe")
```

### Query 3 — Security Onion Windows Elastic Agent
**Security Onion specific:** Uses Elastic Agent telemetry in Security Onion 3.1.0 for Windows hosts. Requires Elastic Agent endpoint, system, Windows, macOS, Linux, or Elastic Defend data streams with ECS host, process, file, registry, authentication, or network fields.

```kql
event.category:process and agent.type:"elastic-agent" and host.os.type:windows and process.name:"cmd.exe" and process.command_line:("*/c powershell*" or "*/c certutil*" or "*/c bitsadmin*" or "*/c curl*" or "*/c wget*" or "*/c whoami*" or "*/c nltest*" or "*/c net view*")
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:process AND agent.type:"elastic-agent" AND host.os.type:windows AND process.name:"cmd.exe" AND process.command_line:("*/c powershell*" OR "*/c certutil*" OR "*/c bitsadmin*" OR "*/c curl*" OR "*/c wget*" OR "*/c whoami*" OR "*/c nltest*" OR "*/c net view*") | groupby host.name host.os.type user.name process.name process.parent.name destination.ip destination.port event.action | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port network.transport network.community_id event.code rule.name
```

**Tuning ideas:** allowlist known admin scripts, software deployment tools, scanners, EDR activity, patch management, and sanctioned cloud apps before alerting.

---

## T1047 — Windows Management Instrumentation

**Tactic:** Execution  
**Detection idea:** WMI process creation, remote execution, and suspicious WMI consumers  
**Elastic implementation notes:** ECS field names vary by integration. Start with the KQL below, then tune for your Elastic Agent, Elastic Defend, Windows, System, Sysmon, cloud, and email data streams.

### Query 1
```kql
event.category:process and process.name:("wmic.exe" or "WmiPrvSE.exe") and process.command_line:("*process call create*" or "*/node:*" or "*shadowcopy*" or "*service*" or "*startup*" or "*product*")
```

### Query 2
```kql
event.category:process and process.parent.name:"WmiPrvSE.exe" and process.name:("cmd.exe" or "powershell.exe" or "pwsh.exe" or "rundll32.exe" or "regsvr32.exe" or "mshta.exe")
```

### Query 3 — Security Onion Windows Elastic Agent
**Security Onion specific:** Uses Elastic Agent telemetry in Security Onion 3.1.0 for Windows hosts. Requires Elastic Agent endpoint, system, Windows, macOS, Linux, or Elastic Defend data streams with ECS host, process, file, registry, authentication, or network fields.

```kql
event.category:process and agent.type:"elastic-agent" and host.os.type:windows and process.name:("wmic.exe" or "powershell.exe" or "pwsh.exe") and process.command_line:("*/node:*" or "*process call create*" or "*Invoke-WmiMethod*" or "*Win32_Process*")
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:process AND agent.type:"elastic-agent" AND host.os.type:windows AND process.name:("wmic.exe" OR "powershell.exe" OR "pwsh.exe") AND process.command_line:("*/node:*" OR "*process call create*" OR "*Invoke-WmiMethod*" OR "*Win32_Process*") | groupby host.name host.os.type user.name process.name process.parent.name destination.ip destination.port event.action | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line process.executable file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port destination.domain network.transport event.code rule.name
```

**Tuning ideas:** allowlist known admin scripts, software deployment tools, scanners, EDR activity, patch management, and sanctioned cloud apps before alerting.

---

## T1204.002 — User Execution: Malicious File

**Tactic:** Execution  
**Detection idea:** User-opened files spawning interpreters or LOLBins  
**Elastic implementation notes:** ECS field names vary by integration. Start with the KQL below, then tune for your Elastic Agent, Elastic Defend, Windows, System, Sysmon, cloud, and email data streams.

### Query 1
```kql
event.category:process and process.parent.name:("winword.exe" or "excel.exe" or "powerpnt.exe" or "outlook.exe" or "acrord32.exe") and process.name:("cmd.exe" or "powershell.exe" or "pwsh.exe" or "wscript.exe" or "cscript.exe" or "mshta.exe" or "rundll32.exe")
```

### Query 2
```kql
event.category:process and process.name:("wscript.exe" or "cscript.exe" or "mshta.exe") and process.command_line:("*.js*" or "*.jse*" or "*.vbs*" or "*.vbe*" or "*.hta*" or "*http*")
```

### Query 3 — Security Onion Windows Elastic Agent
**Security Onion specific:** Uses Elastic Agent telemetry in Security Onion 3.1.0 for Windows hosts. Requires Elastic Agent endpoint, system, Windows, macOS, Linux, or Elastic Defend data streams with ECS host, process, file, registry, authentication, or network fields.

```kql
event.category:process and agent.type:"elastic-agent" and host.os.type:windows and process.parent.name:("explorer.exe" or "winword.exe" or "excel.exe" or "outlook.exe" or "acrord32.exe") and process.name:("powershell.exe" or "cmd.exe" or "mshta.exe" or "rundll32.exe" or "regsvr32.exe" or "wscript.exe" or "cscript.exe")
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:process AND agent.type:"elastic-agent" AND host.os.type:windows AND process.parent.name:("explorer.exe" OR "winword.exe" OR "excel.exe" OR "outlook.exe" OR "acrord32.exe") AND process.name:("powershell.exe" OR "cmd.exe" OR "mshta.exe" OR "rundll32.exe" OR "regsvr32.exe" OR "wscript.exe" OR "cscript.exe") | groupby host.name host.os.type user.name process.name process.parent.name destination.ip destination.port event.action | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line process.executable file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port destination.domain network.transport event.code rule.name
```

### Query 4 — Security Onion Linux Elastic Agent
**Security Onion specific:** Uses Elastic Agent telemetry in Security Onion 3.1.0 for Linux hosts. Requires Elastic Agent endpoint, system, Windows, macOS, Linux, or Elastic Defend data streams with ECS host, process, file, registry, authentication, or network fields.

```kql
event.category:process and agent.type:"elastic-agent" and host.os.type:linux and process.executable:("/tmp/*" or "/var/tmp/*" or "/dev/shm/*" or "/home/*/Downloads/*")
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:process AND agent.type:"elastic-agent" AND host.os.type:linux AND process.executable:("/tmp/*" OR "/var/tmp/*" OR "/dev/shm/*" OR "/home/*/Downloads/*") | groupby host.name host.os.type user.name process.name process.parent.name destination.ip destination.port event.action | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line process.executable file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port destination.domain network.transport event.code rule.name
```

### Query 5 — Security Onion macOS Elastic Agent
**Security Onion specific:** Uses Elastic Agent telemetry in Security Onion 3.1.0 for macOS hosts. Requires Elastic Agent endpoint, system, Windows, macOS, Linux, or Elastic Defend data streams with ECS host, process, file, registry, authentication, or network fields.

```kql
event.category:process and agent.type:"elastic-agent" and host.os.type:macos and process.executable:("/Users/*/Downloads/*" or "/Volumes/*" or "/Users/Shared/*")
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:process AND agent.type:"elastic-agent" AND host.os.type:macos AND process.executable:("/Users/*/Downloads/*" OR "/Volumes/*" OR "/Users/Shared/*") | groupby host.name host.os.type user.name process.name process.parent.name destination.ip destination.port event.action | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line process.executable file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port destination.domain network.transport event.code rule.name
```

**Tuning ideas:** allowlist known admin scripts, software deployment tools, scanners, EDR activity, patch management, and sanctioned cloud apps before alerting.

---

## T1059.005 — Command and Scripting Interpreter: Visual Basic

**Tactic:** Execution  
**Detection idea:** VBScript or Office-spawned script execution  
**Elastic implementation notes:** ECS field names vary by integration. Start with the KQL below, then tune for your Elastic Agent, Elastic Defend, Windows, System, Sysmon, cloud, and email data streams.

### Query 1
```kql
event.category:process and process.name:("wscript.exe" or "cscript.exe") and process.command_line:("*.vbs*" or "*.vbe*" or "*vbscript:*" or "*CreateObject*")
```

### Query 2
```kql
event.category:process and process.parent.name:("winword.exe" or "excel.exe" or "powerpnt.exe" or "outlook.exe") and process.name:("wscript.exe" or "cscript.exe" or "mshta.exe")
```

### Query 3 — Security Onion Windows Elastic Agent
**Security Onion specific:** Uses Elastic Agent telemetry in Security Onion 3.1.0 for Windows hosts. Requires Elastic Agent endpoint, system, Windows, macOS, Linux, or Elastic Defend data streams with ECS host, process, file, registry, authentication, or network fields.

```kql
event.category:process and agent.type:"elastic-agent" and host.os.type:windows and process.name:("wscript.exe" or "cscript.exe") and process.command_line:("*.vbs*" or "*.vbe*" or "*http*" or "*\AppData\*" or "*\Temp\*" or "*CreateObject*")
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:process AND agent.type:"elastic-agent" AND host.os.type:windows AND process.name:("wscript.exe" OR "cscript.exe") AND process.command_line:("*.vbs*" OR "*.vbe*" OR "*http*" OR "*\AppData\*" OR "*\Temp\*" OR "*CreateObject*") | groupby host.name host.os.type user.name process.name process.parent.name destination.ip destination.port event.action | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line process.executable file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port destination.domain network.transport event.code rule.name
```

**Tuning ideas:** allowlist known admin scripts, software deployment tools, scanners, EDR activity, patch management, and sanctioned cloud apps before alerting.

---

## T1059.006 — Command and Scripting Interpreter: Python

**Tactic:** Execution  
**Detection idea:** Python execution from user-writable paths or with download/execution indicators  
**Elastic implementation notes:** ECS field names vary by integration. Start with the KQL below, then tune for your Elastic Agent, Elastic Defend, Windows, System, Sysmon, cloud, and email data streams.

### Query 1
```kql
event.category:process and process.name:("python.exe" or "python3.exe" or "pythonw.exe") and process.command_line:("*-c *" or "*import socket*" or "*urllib*" or "*requests*" or "*subprocess*" or "*base64*")
```

### Query 2
```kql
event.category:process and process.name:("python.exe" or "python3.exe" or "pythonw.exe") and process.executable:("*\\AppData\\*" or "*\\Temp\\*" or "*\\Users\\Public\\*")
```

### Query 3 — Security Onion Linux Elastic Agent
**Security Onion specific:** Uses Elastic Agent telemetry in Security Onion 3.1.0 for Linux hosts. Requires Elastic Agent endpoint, system, Windows, macOS, Linux, or Elastic Defend data streams with ECS host, process, file, registry, authentication, or network fields.

```kql
event.category:process and agent.type:"elastic-agent" and host.os.type:linux and process.name:(python or python3) and process.command_line:("*-c *" or "*import socket*" or "*subprocess*" or "*base64*" or "*pty.spawn*" or "*urllib*" or "*requests*")
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:process AND agent.type:"elastic-agent" AND host.os.type:linux AND process.name:(python OR python3) AND process.command_line:("*-c *" OR "*import socket*" OR "*subprocess*" OR "*base64*" OR "*pty.spawn*" OR "*urllib*" OR "*requests*") | groupby host.name host.os.type user.name process.name process.parent.name destination.ip destination.port event.action | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line process.executable file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port destination.domain network.transport event.code rule.name
```

### Query 4 — Security Onion macOS Elastic Agent
**Security Onion specific:** Uses Elastic Agent telemetry in Security Onion 3.1.0 for macOS hosts. Requires Elastic Agent endpoint, system, Windows, macOS, Linux, or Elastic Defend data streams with ECS host, process, file, registry, authentication, or network fields.

```kql
event.category:process and agent.type:"elastic-agent" and host.os.type:macos and process.name:(python or python3) and process.command_line:("*-c *" or "*import socket*" or "*subprocess*" or "*urllib*" or "*requests*" or "*base64*")
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:process AND agent.type:"elastic-agent" AND host.os.type:macos AND process.name:(python OR python3) AND process.command_line:("*-c *" OR "*import socket*" OR "*subprocess*" OR "*urllib*" OR "*requests*" OR "*base64*") | groupby host.name host.os.type user.name process.name process.parent.name destination.ip destination.port event.action | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line process.executable file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port destination.domain network.transport event.code rule.name
```

**Tuning ideas:** allowlist known admin scripts, software deployment tools, scanners, EDR activity, patch management, and sanctioned cloud apps before alerting.

---

## T1059.007 — Command and Scripting Interpreter: JavaScript

**Tactic:** Execution  
**Detection idea:** JavaScript execution by Windows script hosts or Node from suspicious locations  
**Elastic implementation notes:** ECS field names vary by integration. Start with the KQL below, then tune for your Elastic Agent, Elastic Defend, Windows, System, Sysmon, cloud, and email data streams.

### Query 1
```kql
event.category:process and process.name:("wscript.exe" or "cscript.exe" or "node.exe") and process.command_line:("*.js*" or "*.jse*" or "*eval(*" or "*fromCharCode*" or "*ActiveXObject*")
```

### Query 2
```kql
event.category:process and process.name:("wscript.exe" or "cscript.exe") and process.parent.name:("winword.exe" or "excel.exe" or "outlook.exe" or "explorer.exe")
```

### Query 3 — Security Onion Windows Elastic Agent
**Security Onion specific:** Uses Elastic Agent telemetry in Security Onion 3.1.0 for Windows hosts. Requires Elastic Agent endpoint, system, Windows, macOS, Linux, or Elastic Defend data streams with ECS host, process, file, registry, authentication, or network fields.

```kql
event.category:process and agent.type:"elastic-agent" and host.os.type:windows and process.name:("wscript.exe" or "cscript.exe" or "node.exe") and process.command_line:("*.js*" or "*.jse*" or "*eval(*" or "*ActiveXObject*" or "*\AppData\*" or "*\Temp\*")
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:process AND agent.type:"elastic-agent" AND host.os.type:windows AND process.name:("wscript.exe" OR "cscript.exe" OR "node.exe") AND process.command_line:("*.js*" OR "*.jse*" OR "*eval(*" OR "*ActiveXObject*" OR "*\AppData\*" OR "*\Temp\*") | groupby host.name host.os.type user.name process.name process.parent.name destination.ip destination.port event.action | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line process.executable file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port destination.domain network.transport event.code rule.name
```

### Query 4 — Security Onion Linux Elastic Agent
**Security Onion specific:** Uses Elastic Agent telemetry in Security Onion 3.1.0 for Linux hosts. Requires Elastic Agent endpoint, system, Windows, macOS, Linux, or Elastic Defend data streams with ECS host, process, file, registry, authentication, or network fields.

```kql
event.category:process and agent.type:"elastic-agent" and host.os.type:linux and process.name:(node or nodejs) and process.command_line:("*-e *" or "*eval*" or "*child_process*" or "*http*" or "*/tmp/*" or "*/dev/shm/*")
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:process AND agent.type:"elastic-agent" AND host.os.type:linux AND process.name:(node OR nodejs) AND process.command_line:("*-e *" OR "*eval*" OR "*child_process*" OR "*http*" OR "*/tmp/*" OR "*/dev/shm/*") | groupby host.name host.os.type user.name process.name process.parent.name destination.ip destination.port event.action | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line process.executable file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port destination.domain network.transport event.code rule.name
```

**Tuning ideas:** allowlist known admin scripts, software deployment tools, scanners, EDR activity, patch management, and sanctioned cloud apps before alerting.

---

## T1203 — Exploitation for Client Execution

**Tactic:** Execution  
**Detection idea:** Client application spawning script interpreters, shells, or LOLBins  
**Elastic implementation notes:** ECS field names vary by integration. Start with the KQL below, then tune for your Elastic Agent, Elastic Defend, Windows, System, Sysmon, cloud, and email data streams.

### Query 1
```kql
event.category:process and process.parent.name:("winword.exe" or "excel.exe" or "powerpnt.exe" or "outlook.exe" or "acrord32.exe" or "chrome.exe" or "msedge.exe" or "firefox.exe") and process.name:("cmd.exe" or "powershell.exe" or "pwsh.exe" or "wscript.exe" or "cscript.exe" or "mshta.exe" or "rundll32.exe")
```

### Query 2
```kql
event.category:process and process.parent.name:("acrord32.exe" or "chrome.exe" or "msedge.exe" or "firefox.exe") and process.command_line:("*http*" or "*powershell*" or "*cmd /c*" or "*rundll32*")
```

**Tuning ideas:** allowlist known admin scripts, software deployment tools, scanners, EDR activity, patch management, and sanctioned cloud apps before alerting.

---

## T1059.004 — Command and Scripting Interpreter: Unix Shell

**Tactic:** Execution  
**Detection idea:** Linux and macOS shells launching download, decode, staging, or reverse-shell behavior from Elastic Agent endpoint telemetry  
**Elastic implementation notes:** Linux/macOS host telemetry requires Elastic Agent with endpoint, system, or Elastic Defend integrations. Field availability varies by policy and event collection settings.

### Query 1 — Security Onion Linux/macOS Elastic Agent
**Security Onion specific:** Uses Elastic Agent telemetry in Security Onion 3.1.0 for Linux/macOS hosts. Requires Elastic Agent endpoint, system, or Elastic Defend data streams with ECS host, process, file, or network fields.

```kql
event.category:process and agent.type:"elastic-agent" and host.os.type:(linux or macos) and process.name:(bash or sh or zsh or dash or ksh) and process.command_line:("*curl*" or "*wget*" or "*base64*" or "*chmod +x*" or "*/dev/tcp/*" or "*mkfifo*" or "*nc *" or "*python* -c*" or "*perl* -e*")
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:process AND agent.type:"elastic-agent" AND host.os.type:(linux OR macos) AND process.name:(bash OR sh OR zsh OR dash OR ksh) AND process.command_line:("*curl*" OR "*wget*" OR "*base64*" OR "*chmod +x*" OR "*/dev/tcp/*" OR "*mkfifo*" OR "*nc *" OR "*python* -c*" OR "*perl* -e*") | groupby host.name host.os.type user.name process.name source.ip destination.ip destination.port | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line file.path file.name file.extension source.ip source.port destination.ip destination.port network.transport network.community_id rule.name
```


### Query 2 — Security Onion Linux Elastic Agent
**Security Onion specific:** Uses Elastic Agent telemetry in Security Onion 3.1.0 for Linux hosts. Requires Elastic Agent endpoint, system, Windows, macOS, Linux, or Elastic Defend data streams with ECS host, process, file, registry, authentication, or network fields.

```kql
event.category:process and agent.type:"elastic-agent" and host.os.type:linux and process.name:(bash or sh or dash or zsh) and process.command_line:("*/tmp/*" or "*/dev/shm/*" or "*curl*|*sh*" or "*wget*|*sh*" or "*base64 -d*" or "*chmod +x*")
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:process AND agent.type:"elastic-agent" AND host.os.type:linux AND process.name:(bash OR sh OR dash OR zsh) AND process.command_line:("*/tmp/*" OR "*/dev/shm/*" OR "*curl*|*sh*" OR "*wget*|*sh*" OR "*base64 -d*" OR "*chmod +x*") | groupby host.name host.os.type user.name process.name process.parent.name destination.ip destination.port event.action | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port network.transport network.community_id event.code rule.name
```

### Query 3 — Security Onion macOS Elastic Agent
**Security Onion specific:** Uses Elastic Agent telemetry in Security Onion 3.1.0 for macOS hosts. Requires Elastic Agent endpoint, system, Windows, macOS, Linux, or Elastic Defend data streams with ECS host, process, file, registry, authentication, or network fields.

```kql
event.category:process and agent.type:"elastic-agent" and host.os.type:macos and process.name:(bash or sh or zsh) and process.command_line:("*/tmp/*" or "*/Users/Shared/*" or "*curl*|*sh*" or "*chmod +x*" or "*base64 -D*")
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:process AND agent.type:"elastic-agent" AND host.os.type:macos AND process.name:(bash OR sh OR zsh) AND process.command_line:("*/tmp/*" OR "*/Users/Shared/*" OR "*curl*|*sh*" OR "*chmod +x*" OR "*base64 -D*") | groupby host.name host.os.type user.name process.name process.parent.name destination.ip destination.port event.action | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line process.executable file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port destination.domain network.transport event.code rule.name
```

**Tuning ideas:** allowlist approved admin scripts, package managers, MDM activity, backup tools, deployment systems, developer workflows, and sanctioned remote administration.

---

## T1059.002 — Command and Scripting Interpreter: AppleScript

**Tactic:** Execution  
**Detection idea:** macOS Elastic Agent osascript executing shell commands, downloads, or automation payloads  
**Elastic implementation notes:** Host telemetry requires Elastic Agent with endpoint, system, Windows, macOS, Linux, or Elastic Defend integrations. Field availability varies by agent policy and event collection settings.

### Query 1 — Security Onion macOS Elastic Agent
**Security Onion specific:** Uses Elastic Agent telemetry in Security Onion 3.1.0 for macOS hosts. Requires Elastic Agent endpoint, system, Windows, macOS, Linux, or Elastic Defend data streams with ECS host, process, file, registry, authentication, or network fields.

```kql
event.category:process and agent.type:"elastic-agent" and host.os.type:macos and process.name:osascript and process.command_line:("*do shell script*" or "*curl*" or "*python*" or "*bash*" or "*osascript -e*")
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:process AND agent.type:"elastic-agent" AND host.os.type:macos AND process.name:osascript AND process.command_line:("*do shell script*" OR "*curl*" OR "*python*" OR "*bash*" OR "*osascript -e*") | groupby host.name host.os.type user.name process.name process.parent.name destination.ip destination.port event.action | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port network.transport network.community_id event.code rule.name
```


**Tuning ideas:** allowlist approved admin scripts, package managers, MDM/GPO activity, backup tools, EDR activity, deployment systems, developer workflows, and sanctioned remote administration.

---

## T1106 — Native API

**Tactic:** Execution  
**Detection idea:** Windows Elastic Agent suspicious rundll32 or PowerShell invocation of native API-oriented loaders  
**Elastic implementation notes:** Host telemetry requires Elastic Agent with endpoint, system, Windows, macOS, Linux, or Elastic Defend integrations. Field availability varies by agent policy and event collection settings.

### Query 1 — Security Onion Windows Elastic Agent
**Security Onion specific:** Uses Elastic Agent telemetry in Security Onion 3.1.0 for Windows hosts. Requires Elastic Agent endpoint, system, Windows, macOS, Linux, or Elastic Defend data streams with ECS host, process, file, registry, authentication, or network fields.

```kql
event.category:process and agent.type:"elastic-agent" and host.os.type:windows and process.command_line:("*VirtualAlloc*" or "*CreateRemoteThread*" or "*WriteProcessMemory*" or "*LoadLibrary*" or "*GetProcAddress*" or "*NtCreateThreadEx*")
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:process AND agent.type:"elastic-agent" AND host.os.type:windows AND process.command_line:("*VirtualAlloc*" OR "*CreateRemoteThread*" OR "*WriteProcessMemory*" OR "*LoadLibrary*" OR "*GetProcAddress*" OR "*NtCreateThreadEx*") | groupby host.name host.os.type user.name process.name process.parent.name destination.ip destination.port event.action | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line process.executable file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port destination.domain network.transport event.code rule.name
```


**Tuning ideas:** allowlist approved admin scripts, package managers, MDM/GPO activity, backup tools, EDR activity, deployment systems, developer workflows, and sanctioned remote administration.

---

## T1127.001 — Trusted Developer Utilities Proxy Execution: MSBuild

**Tactic:** Execution  
**Detection idea:** Windows Elastic Agent MSBuild proxy execution from user-writable paths or inline tasks  
**Elastic implementation notes:** Host telemetry requires Elastic Agent with endpoint, system, Windows, macOS, Linux, or Elastic Defend integrations. Field availability varies by agent policy and event collection settings.

### Query 1 — Security Onion Windows Elastic Agent
**Security Onion specific:** Uses Elastic Agent telemetry in Security Onion 3.1.0 for Windows hosts. Requires Elastic Agent endpoint, system, Windows, macOS, Linux, or Elastic Defend data streams with ECS host, process, file, registry, authentication, or network fields.

```kql
event.category:process and agent.type:"elastic-agent" and host.os.type:windows and process.name:"MSBuild.exe" and process.command_line:("*\Users\*" or "*\AppData\*" or "*\Temp\*" or "*.xml*" or "*.proj*")
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:process AND agent.type:"elastic-agent" AND host.os.type:windows AND process.name:"MSBuild.exe" AND process.command_line:("*\Users\*" OR "*\AppData\*" OR "*\Temp\*" OR "*.xml*" OR "*.proj*") | groupby host.name host.os.type user.name process.name process.parent.name destination.ip destination.port event.action | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line process.executable file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port destination.domain network.transport event.code rule.name
```


**Tuning ideas:** allowlist approved admin scripts, package managers, MDM/GPO activity, backup tools, EDR activity, deployment systems, developer workflows, and sanctioned remote administration.

---

## T1218.007 — System Binary Proxy Execution: Msiexec

**Tactic:** Execution / Defense Evasion  
**Detection idea:** Windows Elastic Agent msiexec installing from remote URLs or user-writable locations  
**Elastic implementation notes:** Host telemetry requires Elastic Agent with endpoint, system, Windows, macOS, Linux, or Elastic Defend integrations. Field availability varies by agent policy and event collection settings.

### Query 1 — Security Onion Windows Elastic Agent
**Security Onion specific:** Uses Elastic Agent telemetry in Security Onion 3.1.0 for Windows hosts. Requires Elastic Agent endpoint, system, Windows, macOS, Linux, or Elastic Defend data streams with ECS host, process, file, registry, authentication, or network fields.

```kql
event.category:process and agent.type:"elastic-agent" and host.os.type:windows and process.name:"msiexec.exe" and process.command_line:("*http*" or "*\AppData\*" or "*\Temp\*" or "*/quiet*" or "*/qn*")
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:process AND agent.type:"elastic-agent" AND host.os.type:windows AND process.name:"msiexec.exe" AND process.command_line:("*http*" OR "*\AppData\*" OR "*\Temp\*" OR "*/quiet*" OR "*/qn*") | groupby host.name host.os.type user.name process.name process.parent.name destination.ip destination.port event.action | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line process.executable file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port destination.domain network.transport event.code rule.name
```


**Tuning ideas:** allowlist approved admin scripts, package managers, MDM/GPO activity, backup tools, EDR activity, deployment systems, developer workflows, and sanctioned remote administration.

---

## T1059.008 — Command and Scripting Interpreter: Network Device CLI

**Tactic:** Execution  
**Detection idea:** Linux Elastic Agent execution of network administration CLIs from servers or jump hosts  
**Elastic implementation notes:** Host telemetry requires Elastic Agent with endpoint, system, Windows, macOS, Linux, or Elastic Defend integrations. Field availability varies by agent policy and event collection settings.

### Query 1 — Security Onion Linux Elastic Agent
**Security Onion specific:** Uses Elastic Agent telemetry in Security Onion 3.1.0 for Linux hosts. Requires Elastic Agent endpoint, system, Windows, macOS, Linux, or Elastic Defend data streams with ECS host, process, file, registry, authentication, or network fields.

```kql
event.category:process and agent.type:"elastic-agent" and host.os.type:linux and process.name:(ssh or telnet or screen or minicom) and process.command_line:("*admin*" or "*enable*" or "*configure terminal*" or "*telnet*")
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:process AND agent.type:"elastic-agent" AND host.os.type:linux AND process.name:(ssh OR telnet OR screen OR minicom) AND process.command_line:("*admin*" OR "*enable*" OR "*configure terminal*" OR "*telnet*") | groupby host.name host.os.type user.name process.name process.parent.name destination.ip destination.port event.action | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line process.executable file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port destination.domain network.transport event.code rule.name
```


**Tuning ideas:** allowlist approved admin scripts, package managers, MDM/GPO activity, backup tools, EDR activity, deployment systems, developer workflows, and sanctioned remote administration.

---

---

## T1197 — BITS Jobs

**Tactic:** Execution  
**Detection idea:** Windows BITS job creation or invocation used to download, execute, or trigger payloads in the background.  
**Elastic implementation notes:** These filters use ECS-style fields commonly present in Elastic Agent, Elastic Defend, Windows, Linux, macOS, Zeek, and Suricata data streams. Tune command-line patterns and administrative allowlists before production use.

### Query 1 — Security Onion Windows Elastic Agent
**Security Onion specific:** Uses Elastic Agent or Security Onion network telemetry in Security Onion 3.1.0. Requires the relevant endpoint, Zeek, Suricata, Windows, Linux, macOS, system, or Elastic Defend data streams with ECS-compatible fields.

```kql
event.category:process and agent.type:"elastic-agent" and host.os.type:windows and process.name:("bitsadmin.exe" or "powershell.exe" or "pwsh.exe") and process.command_line:("*/create*" or "*Start-BitsTransfer*" or "*Add-BitsFile*" or "*/transfer*") and process.command_line:("*http*" or "*ftp*" or "*\AppData\*" or "*\Temp\*")
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:process AND agent.type:"elastic-agent" AND host.os.type:windows AND process.name:("bitsadmin.exe" OR "powershell.exe" OR "pwsh.exe") AND process.command_line:("*/create*" OR "*Start-BitsTransfer*" OR "*Add-BitsFile*" OR "*/transfer*") AND process.command_line:("*http*" OR "*ftp*" OR "*\AppData\*" OR "*\Temp\*") | groupby host.name host.os.type user.name process.name process.parent.name event.action destination.ip destination.port | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line process.executable file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port destination.domain network.transport network.community_id event.code rule.name
```
### Query 2 — Security Onion Windows Elastic Agent
**Security Onion specific:** Uses Elastic Agent or Security Onion network telemetry in Security Onion 3.1.0. Requires the relevant endpoint, Zeek, Suricata, Windows, Linux, macOS, system, or Elastic Defend data streams with ECS-compatible fields.

```kql
event.category:process and agent.type:"elastic-agent" and host.os.type:windows and process.name:"bitsadmin.exe" and process.command_line:("*/resume*" or "*/complete*" or "*/setnotifycmdline*" or "*/SetNotifyCmdLine*")
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:process AND agent.type:"elastic-agent" AND host.os.type:windows AND process.name:"bitsadmin.exe" AND process.command_line:("*/resume*" OR "*/complete*" OR "*/setnotifycmdline*" OR "*/SetNotifyCmdLine*") | groupby host.name host.os.type user.name process.name process.parent.name event.action destination.ip destination.port | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line process.executable file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port destination.domain network.transport network.community_id event.code rule.name
```
### Query 3 — Security Onion Windows Elastic Agent
**Security Onion specific:** Uses Elastic Agent or Security Onion network telemetry in Security Onion 3.1.0. Requires the relevant endpoint, Zeek, Suricata, Windows, Linux, macOS, system, or Elastic Defend data streams with ECS-compatible fields.

```kql
event.category:network and agent.type:"elastic-agent" and host.os.type:windows and process.name:("bitsadmin.exe" or "svchost.exe") and destination.ip:* and destination.port:(80 or 443 or 8080 or 8443)
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:network AND agent.type:"elastic-agent" AND host.os.type:windows AND process.name:("bitsadmin.exe" OR "svchost.exe") AND destination.ip:* AND destination.port:(80 OR 443 OR 8080 OR 8443) | groupby host.name host.os.type user.name process.name process.parent.name event.action destination.ip destination.port | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line process.executable file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port destination.domain network.transport network.community_id event.code rule.name
```

**Tuning ideas:** allowlist known administrators, software deployment tools, EDR activity, inventory systems, vulnerability scanners, patching tools, and sanctioned management workflows before alerting.

---

## T1129 — Shared Modules

**Tactic:** Execution  
**Detection idea:** Suspicious module or shared-library loading through native loaders and interpreter preload mechanisms.  
**Elastic implementation notes:** These filters use ECS-style fields commonly present in Elastic Agent, Elastic Defend, Windows, Linux, macOS, Zeek, Suricata, cloud, and SaaS data streams. Tune command-line patterns, data views, and administrative allowlists before production use.

### Query 1 — Security Onion Windows Elastic Agent
**Security Onion specific:** Uses Elastic Agent or Security Onion telemetry in Security Onion 3.1.0. Requires the relevant endpoint, Zeek, Suricata, cloud, SaaS, Windows, Linux, macOS, system, or Elastic Defend data streams with ECS-compatible fields.

```kql
event.category:process and agent.type:"elastic-agent" and host.os.type:windows and process.name:("rundll32.exe" or "regsvr32.exe" or "powershell.exe") and process.command_line:("*.dll*" or "*LoadLibrary*" or "*DllRegisterServer*" or "*Start-Process*rundll32*")
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:process AND agent.type:"elastic-agent" AND host.os.type:windows AND process.name:("rundll32.exe" OR "regsvr32.exe" OR "powershell.exe") AND process.command_line:("*.dll*" OR "*LoadLibrary*" OR "*DllRegisterServer*" OR "*Start-Process*rundll32*") | groupby host.name host.os.type user.name process.name process.parent.name event.action destination.ip destination.port | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line process.executable file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port destination.domain network.transport network.community_id event.code rule.name
```
### Query 2 — Security Onion Linux/macOS Elastic Agent
**Security Onion specific:** Uses Elastic Agent or Security Onion telemetry in Security Onion 3.1.0. Requires the relevant endpoint, Zeek, Suricata, cloud, SaaS, Windows, Linux, macOS, system, or Elastic Defend data streams with ECS-compatible fields.

```kql
event.category:process and agent.type:"elastic-agent" and host.os.type:(linux or macos) and process.command_line:("*LD_PRELOAD*" or "*DYLD_INSERT_LIBRARIES*" or "*dlopen*" or "*.so*" or "*.dylib*")
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:process AND agent.type:"elastic-agent" AND host.os.type:(linux OR macos) AND process.command_line:("*LD_PRELOAD*" OR "*DYLD_INSERT_LIBRARIES*" OR "*dlopen*" OR "*.so*" OR "*.dylib*") | groupby host.name host.os.type user.name process.name process.parent.name event.action destination.ip destination.port | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line process.executable file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port destination.domain network.transport network.community_id event.code rule.name
```

**Tuning ideas:** allowlist known administrators, software deployment tools, EDR activity, backup agents, inventory systems, vulnerability scanners, patching tools, and sanctioned management workflows before alerting.

---

## T1559.001 — Inter-Process Communication: Component Object Model

**Tactic:** Execution  
**Detection idea:** Windows COM object execution and scripting through COM automation surfaces.  
**Elastic implementation notes:** These filters use ECS-style fields commonly present in Elastic Agent, Elastic Defend, Windows, Linux, macOS, Zeek, Suricata, cloud, and SaaS data streams. Tune command-line patterns, data views, and administrative allowlists before production use.

### Query 1 — Security Onion Windows Elastic Agent
**Security Onion specific:** Uses Elastic Agent or Security Onion telemetry in Security Onion 3.1.0. Requires the relevant endpoint, Zeek, Suricata, cloud, SaaS, Windows, Linux, macOS, system, or Elastic Defend data streams with ECS-compatible fields.

```kql
event.category:process and agent.type:"elastic-agent" and host.os.type:windows and process.name:("powershell.exe" or "wscript.exe" or "cscript.exe" or "mshta.exe") and process.command_line:("*New-Object -ComObject*" or "*CreateObject*" or "*Shell.Application*" or "*WScript.Shell*" or "*MMC20.Application*")
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:process AND agent.type:"elastic-agent" AND host.os.type:windows AND process.name:("powershell.exe" OR "wscript.exe" OR "cscript.exe" OR "mshta.exe") AND process.command_line:("*New-Object -ComObject*" OR "*CreateObject*" OR "*Shell.Application*" OR "*WScript.Shell*" OR "*MMC20.Application*") | groupby host.name host.os.type user.name process.name process.parent.name event.action destination.ip destination.port | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line process.executable file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port destination.domain network.transport network.community_id event.code rule.name
```
### Query 2 — Security Onion Windows Elastic Agent
**Security Onion specific:** Uses Elastic Agent or Security Onion telemetry in Security Onion 3.1.0. Requires the relevant endpoint, Zeek, Suricata, cloud, SaaS, Windows, Linux, macOS, system, or Elastic Defend data streams with ECS-compatible fields.

```kql
event.category:process and agent.type:"elastic-agent" and host.os.type:windows and process.name:("dllhost.exe" or "rundll32.exe") and process.parent.name:("wscript.exe" or "cscript.exe" or "powershell.exe" or "mshta.exe")
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:process AND agent.type:"elastic-agent" AND host.os.type:windows AND process.name:("dllhost.exe" OR "rundll32.exe") AND process.parent.name:("wscript.exe" OR "cscript.exe" OR "powershell.exe" OR "mshta.exe") | groupby host.name host.os.type user.name process.name process.parent.name event.action destination.ip destination.port | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line process.executable file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port destination.domain network.transport network.community_id event.code rule.name
```

**Tuning ideas:** allowlist known administrators, software deployment tools, EDR activity, backup agents, inventory systems, vulnerability scanners, patching tools, and sanctioned management workflows before alerting.

---

## T1559.002 — Inter-Process Communication: Dynamic Data Exchange

**Tactic:** Execution  
**Detection idea:** Office DDE execution chains and command invocation through document-triggered DDE fields.  
**Elastic implementation notes:** These filters use ECS-style fields commonly present in Elastic Agent, Elastic Defend, Windows, Linux, macOS, Zeek, Suricata, cloud, and SaaS data streams. Tune command-line patterns, data views, and administrative allowlists before production use.

### Query 1 — Security Onion Windows Elastic Agent
**Security Onion specific:** Uses Elastic Agent or Security Onion telemetry in Security Onion 3.1.0. Requires the relevant endpoint, Zeek, Suricata, cloud, SaaS, Windows, Linux, macOS, system, or Elastic Defend data streams with ECS-compatible fields.

```kql
event.category:process and agent.type:"elastic-agent" and host.os.type:windows and process.parent.name:("winword.exe" or "excel.exe" or "powerpnt.exe" or "outlook.exe") and process.name:("cmd.exe" or "powershell.exe" or "wscript.exe" or "mshta.exe") and process.command_line:("*/c*" or "*-EncodedCommand*" or "*DDE*" or "*http*")
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:process AND agent.type:"elastic-agent" AND host.os.type:windows AND process.parent.name:("winword.exe" OR "excel.exe" OR "powerpnt.exe" OR "outlook.exe") AND process.name:("cmd.exe" OR "powershell.exe" OR "wscript.exe" OR "mshta.exe") AND process.command_line:("*/c*" OR "*-EncodedCommand*" OR "*DDE*" OR "*http*") | groupby host.name host.os.type user.name process.name process.parent.name event.action destination.ip destination.port | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line process.executable file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port destination.domain network.transport network.community_id event.code rule.name
```
### Query 2 — Security Onion Windows Elastic Agent
**Security Onion specific:** Uses Elastic Agent or Security Onion telemetry in Security Onion 3.1.0. Requires the relevant endpoint, Zeek, Suricata, cloud, SaaS, Windows, Linux, macOS, system, or Elastic Defend data streams with ECS-compatible fields.

```kql
event.category:process and agent.type:"elastic-agent" and host.os.type:windows and process.name:("winword.exe" or "excel.exe") and process.command_line:("*/dde*" or "*ddeexec*" or "*DDEAUTO*")
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:process AND agent.type:"elastic-agent" AND host.os.type:windows AND process.name:("winword.exe" OR "excel.exe") AND process.command_line:("*/dde*" OR "*ddeexec*" OR "*DDEAUTO*") | groupby host.name host.os.type user.name process.name process.parent.name event.action destination.ip destination.port | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line process.executable file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port destination.domain network.transport network.community_id event.code rule.name
```

**Tuning ideas:** allowlist known administrators, software deployment tools, EDR activity, backup agents, inventory systems, vulnerability scanners, patching tools, and sanctioned management workflows before alerting.

---

## T1218.004 — System Binary Proxy Execution: InstallUtil

**Tactic:** Execution / Defense Evasion  
**Detection idea:** InstallUtil proxy execution of .NET assemblies from user-writable or remote-looking paths.  
**Elastic implementation notes:** These filters use ECS-style fields commonly present in Elastic Agent, Elastic Defend, Windows, Linux, macOS, Zeek, Suricata, cloud, and SaaS data streams. Tune command-line patterns, data views, and administrative allowlists before production use.

### Query 1 — Security Onion Windows Elastic Agent
**Security Onion specific:** Uses Elastic Agent or Security Onion telemetry in Security Onion 3.1.0. Requires the relevant endpoint, Zeek, Suricata, cloud, SaaS, Windows, Linux, macOS, system, or Elastic Defend data streams with ECS-compatible fields.

```kql
event.category:process and agent.type:"elastic-agent" and host.os.type:windows and process.name:"InstallUtil.exe" and process.command_line:("*/logfile=*" or "*/LogToConsole=false*" or "*/U*" or "*.dll*" or "*.exe*")
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:process AND agent.type:"elastic-agent" AND host.os.type:windows AND process.name:"InstallUtil.exe" AND process.command_line:("*/logfile=*" OR "*/LogToConsole=false*" OR "*/U*" OR "*.dll*" OR "*.exe*") | groupby host.name host.os.type user.name process.name process.parent.name event.action destination.ip destination.port | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line process.executable file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port destination.domain network.transport network.community_id event.code rule.name
```
### Query 2 — Security Onion Windows Elastic Agent
**Security Onion specific:** Uses Elastic Agent or Security Onion telemetry in Security Onion 3.1.0. Requires the relevant endpoint, Zeek, Suricata, cloud, SaaS, Windows, Linux, macOS, system, or Elastic Defend data streams with ECS-compatible fields.

```kql
event.category:process and agent.type:"elastic-agent" and host.os.type:windows and process.name:"InstallUtil.exe" and process.command_line:("*\Users\*" or "*\AppData\*" or "*\Temp\*" or "*http*" or "*\ProgramData\*")
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:process AND agent.type:"elastic-agent" AND host.os.type:windows AND process.name:"InstallUtil.exe" AND process.command_line:("*\Users\*" OR "*\AppData\*" OR "*\Temp\*" OR "*http*" OR "*\ProgramData\*") | groupby host.name host.os.type user.name process.name process.parent.name event.action destination.ip destination.port | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line process.executable file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port destination.domain network.transport network.community_id event.code rule.name
```

**Tuning ideas:** allowlist known administrators, software deployment tools, EDR activity, backup agents, inventory systems, vulnerability scanners, patching tools, and sanctioned management workflows before alerting.

---

## T1218.013 — System Binary Proxy Execution: Mavinject

**Tactic:** Execution / Defense Evasion  
**Detection idea:** Mavinject DLL injection or package injection abuse on Windows hosts.  
**Elastic implementation notes:** These filters use ECS-style fields commonly present in Elastic Agent, Elastic Defend, Windows, Linux, macOS, Zeek, Suricata, cloud, and SaaS data streams. Tune command-line patterns, data views, and administrative allowlists before production use.

### Query 1 — Security Onion Windows Elastic Agent
**Security Onion specific:** Uses Elastic Agent or Security Onion telemetry in Security Onion 3.1.0. Requires the relevant endpoint, Zeek, Suricata, cloud, SaaS, Windows, Linux, macOS, system, or Elastic Defend data streams with ECS-compatible fields.

```kql
event.category:process and agent.type:"elastic-agent" and host.os.type:windows and process.name:"mavinject.exe" and process.command_line:("*/INJECTRUNNING*" or "*/INJECTRUNNING64*" or "*.dll*")
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:process AND agent.type:"elastic-agent" AND host.os.type:windows AND process.name:"mavinject.exe" AND process.command_line:("*/INJECTRUNNING*" OR "*/INJECTRUNNING64*" OR "*.dll*") | groupby host.name host.os.type user.name process.name process.parent.name event.action destination.ip destination.port | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line process.executable file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port destination.domain network.transport network.community_id event.code rule.name
```
### Query 2 — Security Onion Windows Elastic Agent
**Security Onion specific:** Uses Elastic Agent or Security Onion telemetry in Security Onion 3.1.0. Requires the relevant endpoint, Zeek, Suricata, cloud, SaaS, Windows, Linux, macOS, system, or Elastic Defend data streams with ECS-compatible fields.

```kql
event.category:process and agent.type:"elastic-agent" and host.os.type:windows and process.parent.name:("cmd.exe" or "powershell.exe" or "wscript.exe") and process.name:"mavinject.exe"
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:process AND agent.type:"elastic-agent" AND host.os.type:windows AND process.parent.name:("cmd.exe" OR "powershell.exe" OR "wscript.exe") AND process.name:"mavinject.exe" | groupby host.name host.os.type user.name process.name process.parent.name event.action destination.ip destination.port | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line process.executable file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port destination.domain network.transport network.community_id event.code rule.name
```

**Tuning ideas:** allowlist known administrators, software deployment tools, EDR activity, backup agents, inventory systems, vulnerability scanners, patching tools, and sanctioned management workflows before alerting.

