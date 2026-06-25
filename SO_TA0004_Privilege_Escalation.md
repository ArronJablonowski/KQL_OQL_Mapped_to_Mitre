# TA0004 — Privilege Escalation

> Query dialect: Elastic Kibana Query Language (**Elastic KQL**) using ECS-style fields. These are hunting-grade filters intended for Kibana Discover, Timeline, and Elastic Security rules. Tune fields, data views, and allowlists to your environment.

**Coverage count:** 6 technique sections / 17 KQL queries

## Techniques in this tactic

- [T1098 — Account Manipulation](SO_TA0004_Privilege_Escalation.md#t1098-account-manipulation) — 2 queries
- [T1548.002 — Abuse Elevation Control Mechanism: Bypass User Account Control](SO_TA0004_Privilege_Escalation.md#t1548.002-abuse-elevation-control-mechanism-bypass-user-account-control) — 3 queries
- [T1068 — Exploitation for Privilege Escalation](SO_TA0004_Privilege_Escalation.md#t1068-exploitation-for-privilege-escalation) — 4 queries
- [T1134.001 — Access Token Manipulation: Token Impersonation/Theft](SO_TA0004_Privilege_Escalation.md#t1134.001-access-token-manipulation-token-impersonationtheft) — 3 queries
- [T1548.001 — Abuse Elevation Control Mechanism: Setuid and Setgid](SO_TA0004_Privilege_Escalation.md#t1548.001-abuse-elevation-control-mechanism-setuid-and-setgid) — 3 queries
- [T1548.003 — Abuse Elevation Control Mechanism: Sudo and Sudo Caching](SO_TA0004_Privilege_Escalation.md#t1548.003-abuse-elevation-control-mechanism-sudo-and-sudo-caching) — 2 queries

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

**Tuning ideas:** allowlist known admin scripts, software deployment tools, scanners, EDR activity, patch management, and sanctioned cloud apps before alerting.

---

## T1548.002 — Abuse Elevation Control Mechanism: Bypass User Account Control

**Tactic:** Privilege Escalation  
**Detection idea:** UAC bypass registry modifications or suspicious auto-elevated binaries  
**Elastic implementation notes:** ECS field names vary by integration. Start with the KQL below, then tune for your Elastic Agent, Elastic Defend, Windows, System, Sysmon, cloud, and email data streams.

### Query 1
```kql
event.category:registry and registry.path:("*\\Software\\Classes\\ms-settings\\Shell\\Open\\command*" or "*\\Software\\Classes\\mscfile\\shell\\open\\command*" or "*\\Software\\Classes\\exefile\\shell\\runas\\command*")
```

### Query 2
```kql
event.category:process and process.name:("fodhelper.exe" or "computerdefaults.exe" or "sdclt.exe" or "eventvwr.exe") and process.parent.name:("cmd.exe" or "powershell.exe" or "pwsh.exe" or "wscript.exe" or "cscript.exe")
```

### Query 3 — Security Onion Windows Elastic Agent
**Security Onion specific:** Uses Elastic Agent telemetry in Security Onion 3.1.0 for Windows hosts. Requires Elastic Agent endpoint, system, Windows, macOS, Linux, or Elastic Defend data streams with ECS host, process, file, registry, authentication, or network fields.

```kql
event.category:(process or registry) and agent.type:"elastic-agent" and host.os.type:windows and (registry.path:("*\Software\Classes\ms-settings\Shell\Open\command*" or "*\Software\Classes\mscfile\shell\open\command*") or (process.name:("fodhelper.exe" or "computerdefaults.exe" or "eventvwr.exe") and process.parent.name:("cmd.exe" or "powershell.exe" or "pwsh.exe")))
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:(process OR registry) AND agent.type:"elastic-agent" AND host.os.type:windows AND (registry.path:("*\Software\Classes\ms-settings\Shell\Open\command*" OR "*\Software\Classes\mscfile\shell\open\command*") OR (process.name:("fodhelper.exe" OR "computerdefaults.exe" OR "eventvwr.exe") AND process.parent.name:("cmd.exe" OR "powershell.exe" OR "pwsh.exe"))) | groupby host.name host.os.type user.name process.name process.parent.name destination.ip destination.port event.action | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line process.executable file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port destination.domain network.transport event.code rule.name
```

**Tuning ideas:** allowlist known admin scripts, software deployment tools, scanners, EDR activity, patch management, and sanctioned cloud apps before alerting.

---

## T1068 — Exploitation for Privilege Escalation

**Tactic:** Privilege Escalation  
**Detection idea:** Exploit-like privilege escalation commands or suspicious child processes from services  
**Elastic implementation notes:** ECS field names vary by integration. Start with the KQL below, then tune for your Elastic Agent, Elastic Defend, Windows, System, Sysmon, cloud, and email data streams.

### Query 1
```kql
event.category:process and process.command_line:("*PrintSpoofer*" or "*JuicyPotato*" or "*RoguePotato*" or "*GodPotato*" or "*CVE-2021-1675*" or "*CVE-2021-34527*")
```

### Query 2
```kql
event.category:process and process.parent.name:("services.exe" or "spoolsv.exe" or "lsass.exe") and process.name:("cmd.exe" or "powershell.exe" or "pwsh.exe" or "rundll32.exe")
```

### Query 3 — Security Onion Linux Elastic Agent
**Security Onion specific:** Uses Elastic Agent telemetry in Security Onion 3.1.0 for Linux hosts. Requires Elastic Agent endpoint, system, Windows, macOS, Linux, or Elastic Defend data streams with ECS host, process, file, registry, authentication, or network fields.

```kql
event.category:process and agent.type:"elastic-agent" and host.os.type:linux and process.command_line:("*dirtycow*" or "*CVE-2021-4034*" or "*pwnkit*" or "*CVE-2022-0847*" or "*dirtypipe*" or "*overlayfs*")
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:process AND agent.type:"elastic-agent" AND host.os.type:linux AND process.command_line:("*dirtycow*" OR "*CVE-2021-4034*" OR "*pwnkit*" OR "*CVE-2022-0847*" OR "*dirtypipe*" OR "*overlayfs*") | groupby host.name host.os.type user.name process.name process.parent.name destination.ip destination.port event.action | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port network.transport network.community_id event.code rule.name
```

### Query 4 — Security Onion Windows Elastic Agent
**Security Onion specific:** Uses Elastic Agent telemetry in Security Onion 3.1.0 for Windows hosts. Requires Elastic Agent endpoint, system, Windows, macOS, Linux, or Elastic Defend data streams with ECS host, process, file, registry, authentication, or network fields.

```kql
event.category:process and agent.type:"elastic-agent" and host.os.type:windows and process.command_line:("*CVE-2021-1675*" or "*CVE-2021-34527*" or "*PrintNightmare*" or "*PetitPotam*" or "*EfsRpc*" or "*SpoolSample*")
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:process AND agent.type:"elastic-agent" AND host.os.type:windows AND process.command_line:("*CVE-2021-1675*" OR "*CVE-2021-34527*" OR "*PrintNightmare*" OR "*PetitPotam*" OR "*EfsRpc*" OR "*SpoolSample*") | groupby host.name host.os.type user.name process.name process.parent.name destination.ip destination.port event.action | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line process.executable file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port destination.domain network.transport event.code rule.name
```

**Tuning ideas:** allowlist known admin scripts, software deployment tools, scanners, EDR activity, patch management, and sanctioned cloud apps before alerting.

---

## T1134.001 — Access Token Manipulation: Token Impersonation/Theft

**Tactic:** Privilege Escalation  
**Detection idea:** Token impersonation tooling or named-pipe privilege escalation indicators  
**Elastic implementation notes:** ECS field names vary by integration. Start with the KQL below, then tune for your Elastic Agent, Elastic Defend, Windows, System, Sysmon, cloud, and email data streams.

### Query 1
```kql
event.category:process and process.command_line:("*incognito*" or "*steal_token*" or "*make_token*" or "*rev2self*" or "*token::elevate*" or "*SeImpersonatePrivilege*")
```

### Query 2
```kql
event.category:process and process.name:("cmd.exe" or "powershell.exe" or "pwsh.exe") and process.parent.name:("spoolsv.exe" or "services.exe" or "w3wp.exe")
```

### Query 3 — Security Onion Windows Elastic Agent
**Security Onion specific:** Uses Elastic Agent telemetry in Security Onion 3.1.0 for Windows hosts. Requires Elastic Agent endpoint, system, Windows, macOS, Linux, or Elastic Defend data streams with ECS host, process, file, registry, authentication, or network fields.

```kql
event.category:process and agent.type:"elastic-agent" and host.os.type:windows and process.command_line:("*SeImpersonatePrivilege*" or "*PrintSpoofer*" or "*RoguePotato*" or "*JuicyPotato*" or "*GodPotato*" or "*token::elevate*" or "*incognito*")
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:process AND agent.type:"elastic-agent" AND host.os.type:windows AND process.command_line:("*SeImpersonatePrivilege*" OR "*PrintSpoofer*" OR "*RoguePotato*" OR "*JuicyPotato*" OR "*GodPotato*" OR "*token::elevate*" OR "*incognito*") | groupby host.name host.os.type user.name process.name process.parent.name destination.ip destination.port event.action | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line process.executable file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port destination.domain network.transport event.code rule.name
```

**Tuning ideas:** allowlist known admin scripts, software deployment tools, scanners, EDR activity, patch management, and sanctioned cloud apps before alerting.

---

## T1548.001 — Abuse Elevation Control Mechanism: Setuid and Setgid

**Tactic:** Privilege Escalation  
**Detection idea:** Setuid or setgid bit changes on Linux/macOS binaries from Elastic Agent process telemetry  
**Elastic implementation notes:** Linux/macOS host telemetry requires Elastic Agent with endpoint, system, or Elastic Defend integrations. Field availability varies by policy and event collection settings.

### Query 1 — Security Onion Linux/macOS Elastic Agent
**Security Onion specific:** Uses Elastic Agent telemetry in Security Onion 3.1.0 for Linux/macOS hosts. Requires Elastic Agent endpoint, system, or Elastic Defend data streams with ECS host, process, file, or network fields.

```kql
event.category:process and agent.type:"elastic-agent" and host.os.type:(linux or macos) and process.name:chmod and process.command_line:("*u+s*" or "*g+s*" or "* 4[0-9][0-9][0-9]*" or "* 2[0-9][0-9][0-9]*")
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:process AND agent.type:"elastic-agent" AND host.os.type:(linux OR macos) AND process.name:chmod AND process.command_line:("*u+s*" OR "*g+s*" OR "* 4[0-9][0-9][0-9]*" OR "* 2[0-9][0-9][0-9]*") | groupby host.name host.os.type user.name process.name source.ip destination.ip destination.port | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line file.path file.name file.extension source.ip source.port destination.ip destination.port network.transport network.community_id rule.name
```


### Query 2 — Security Onion Linux Elastic Agent
**Security Onion specific:** Uses Elastic Agent telemetry in Security Onion 3.1.0 for Linux hosts. Requires Elastic Agent endpoint, system, Windows, macOS, Linux, or Elastic Defend data streams with ECS host, process, file, registry, authentication, or network fields.

```kql
event.category:process and agent.type:"elastic-agent" and host.os.type:linux and process.name:(chmod or chown) and process.command_line:("*u+s*" or "*g+s*" or "* /bin/*" or "* /usr/bin/*" or "* /tmp/*")
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:process AND agent.type:"elastic-agent" AND host.os.type:linux AND process.name:(chmod OR chown) AND process.command_line:("*u+s*" OR "*g+s*" OR "* /bin/*" OR "* /usr/bin/*" OR "* /tmp/*") | groupby host.name host.os.type user.name process.name process.parent.name destination.ip destination.port event.action | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line process.executable file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port destination.domain network.transport event.code rule.name
```

### Query 3 — Security Onion macOS Elastic Agent
**Security Onion specific:** Uses Elastic Agent telemetry in Security Onion 3.1.0 for macOS hosts. Requires Elastic Agent endpoint, system, Windows, macOS, Linux, or Elastic Defend data streams with ECS host, process, file, registry, authentication, or network fields.

```kql
event.category:process and agent.type:"elastic-agent" and host.os.type:macos and process.name:chmod and process.command_line:("*u+s*" or "*g+s*" or "* 4[0-9][0-9][0-9]*" or "* 2[0-9][0-9][0-9]*")
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:process AND agent.type:"elastic-agent" AND host.os.type:macos AND process.name:chmod AND process.command_line:("*u+s*" OR "*g+s*" OR "* 4[0-9][0-9][0-9]*" OR "* 2[0-9][0-9][0-9]*") | groupby host.name host.os.type user.name process.name process.parent.name destination.ip destination.port event.action | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line process.executable file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port destination.domain network.transport event.code rule.name
```

**Tuning ideas:** allowlist approved admin scripts, package managers, MDM activity, backup tools, deployment systems, developer workflows, and sanctioned remote administration.

---

## T1548.003 — Abuse Elevation Control Mechanism: Sudo and Sudo Caching

**Tactic:** Privilege Escalation  
**Detection idea:** Suspicious sudo or su usage on Linux/macOS hosts with Elastic Agent process telemetry  
**Elastic implementation notes:** Linux/macOS host telemetry requires Elastic Agent with endpoint, system, or Elastic Defend integrations. Field availability varies by policy and event collection settings.

### Query 1 — Security Onion Linux/macOS Elastic Agent
**Security Onion specific:** Uses Elastic Agent telemetry in Security Onion 3.1.0 for Linux/macOS hosts. Requires Elastic Agent endpoint, system, or Elastic Defend data streams with ECS host, process, file, or network fields.

```kql
event.category:process and agent.type:"elastic-agent" and host.os.type:(linux or macos) and process.name:(sudo or su) and process.command_line:("* -u root*" or "*sudo -S*" or "*su -*" or "* /bin/bash*" or "* /bin/sh*" or "*python*" or "*perl*")
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:process AND agent.type:"elastic-agent" AND host.os.type:(linux OR macos) AND process.name:(sudo OR su) AND process.command_line:("* -u root*" OR "*sudo -S*" OR "*su -*" OR "* /bin/bash*" OR "* /bin/sh*" OR "*python*" OR "*perl*") | groupby host.name host.os.type user.name process.name source.ip destination.ip destination.port | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line file.path file.name file.extension source.ip source.port destination.ip destination.port network.transport network.community_id rule.name
```


### Query 2 — Security Onion macOS Elastic Agent
**Security Onion specific:** Uses Elastic Agent telemetry in Security Onion 3.1.0 for macOS hosts. Requires Elastic Agent endpoint, system, Windows, macOS, Linux, or Elastic Defend data streams with ECS host, process, file, registry, authentication, or network fields.

```kql
event.category:process and agent.type:"elastic-agent" and host.os.type:macos and process.name:(sudo or security or dseditgroup) and process.command_line:("* -s*" or "* -u root*" or "*authorizationdb*" or "*admin*" or "*wheel*")
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:process AND agent.type:"elastic-agent" AND host.os.type:macos AND process.name:(sudo OR security OR dseditgroup) AND process.command_line:("* -s*" OR "* -u root*" OR "*authorizationdb*" OR "*admin*" OR "*wheel*") | groupby host.name host.os.type user.name process.name process.parent.name destination.ip destination.port event.action | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port network.transport network.community_id event.code rule.name
```

**Tuning ideas:** allowlist approved admin scripts, package managers, MDM activity, backup tools, deployment systems, developer workflows, and sanctioned remote administration.

---
