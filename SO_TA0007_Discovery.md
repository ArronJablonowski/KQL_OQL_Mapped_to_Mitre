# TA0007 — Discovery

> Query dialect: Elastic Kibana Query Language (**Elastic KQL**) using ECS-style fields. These are hunting-grade filters intended for Kibana Discover, Timeline, and Elastic Security rules. Tune fields, data views, and allowlists to your environment.

**Coverage count:** 29 technique sections / 88 KQL queries

## Techniques in this tactic

- [T1087.002 — Account Discovery: Domain Account](SO_TA0007_Discovery.md#t1087.002-account-discovery-domain-account) — 3 queries
- [T1018 — Remote System Discovery](SO_TA0007_Discovery.md#t1018-remote-system-discovery) — 5 queries
- [T1046 — Network Service Discovery](SO_TA0007_Discovery.md#t1046-network-service-discovery) — 5 queries
- [T1082 — System Information Discovery](SO_TA0007_Discovery.md#t1082-system-information-discovery) — 4 queries
- [T1057 — Process Discovery](SO_TA0007_Discovery.md#t1057-process-discovery) — 4 queries
- [T1083 — File and Directory Discovery](SO_TA0007_Discovery.md#t1083-file-and-directory-discovery) — 5 queries
- [T1016 — System Network Configuration Discovery](SO_TA0007_Discovery.md#t1016-system-network-configuration-discovery) — 6 queries
- [T1033 — System Owner/User Discovery](SO_TA0007_Discovery.md#t1033-system-owneruser-discovery) — 2 queries
- [T1069.002 — Permission Groups Discovery: Domain Groups](SO_TA0007_Discovery.md#t1069.002-permission-groups-discovery-domain-groups) — 2 queries
- [T1482 — Domain Trust Discovery](SO_TA0007_Discovery.md#t1482-domain-trust-discovery) — 4 queries
- [T1012 — Query Registry](SO_TA0007_Discovery.md#t1012-query-registry) — 3 queries
- [T1049 — System Network Connections Discovery](SO_TA0007_Discovery.md#t1049-system-network-connections-discovery) — 2 queries
- [T1087.001 — Account Discovery: Local Account](SO_TA0007_Discovery.md#t1087.001-account-discovery-local-account) — 2 queries
- [T1069.001 — Permission Groups Discovery: Local Groups](SO_TA0007_Discovery.md#t1069.001-permission-groups-discovery-local-groups) — 1 query
- [T1615 — Group Policy Discovery](SO_TA0007_Discovery.md#t1615-group-policy-discovery) — 3 queries
- [T1680 — Local Storage Discovery](SO_TA0007_Discovery.md#t1680-local-storage-discovery) — 3 queries
- [T1654 — Log Enumeration](SO_TA0007_Discovery.md#t1654-log-enumeration) — 3 queries
- [T1135 — Network Share Discovery](SO_TA0007_Discovery.md#t1135-network-share-discovery) — 3 queries
- [T1201 — Password Policy Discovery](SO_TA0007_Discovery.md#t1201-password-policy-discovery) — 3 queries
- [T1518 — Software Discovery](SO_TA0007_Discovery.md#t1518-software-discovery) — 3 queries
- [T1614 — System Location Discovery](SO_TA0007_Discovery.md#t1614-system-location-discovery) — 3 queries
- [T1007 — System Service Discovery](SO_TA0007_Discovery.md#t1007-system-service-discovery) — 3 queries
- [T1124 — System Time Discovery](SO_TA0007_Discovery.md#t1124-system-time-discovery) — 3 queries
- [T1673 — Virtual Machine Discovery](SO_TA0007_Discovery.md#t1673-virtual-machine-discovery) — 3 queries
- [T1016.001 — System Network Configuration Discovery: Internet Connection Discovery](SO_TA0007_Discovery.md#t1016.001-system-network-configuration-discovery-internet-connection-discovery) — 2 queries
- [T1069.003 — Permission Groups Discovery: Cloud Groups](SO_TA0007_Discovery.md#t1069.003-permission-groups-discovery-cloud-groups) — 2 queries
- [T1120 — Peripheral Device Discovery](SO_TA0007_Discovery.md#t1120-peripheral-device-discovery) — 2 queries
- [T1652 — Device Driver Discovery](SO_TA0007_Discovery.md#t1652-device-driver-discovery) — 2 queries
- [T1619 — Cloud Storage Object Discovery](SO_TA0007_Discovery.md#t1619-cloud-storage-object-discovery) — 2 queries

---

## T1087.002 — Account Discovery: Domain Account

**Tactic:** Discovery  
**Detection idea:** Domain account, group, and privileged user enumeration  
**Elastic implementation notes:** ECS field names vary by integration. Start with the KQL below, then tune for your Elastic Agent, Elastic Defend, Windows, System, Sysmon, cloud, and email data streams.

### Query 1
```kql
event.category:process and process.name:("net.exe" or "net1.exe" or "dsquery.exe" or "nltest.exe" or "powershell.exe" or "pwsh.exe") and process.command_line:("*domain*" or "*group*" or "*user*" or "*admin*" or "*Get-ADUser*" or "*Get-ADGroupMember*")
```

### Query 2
```kql
event.category:process and process.command_line:("*\"net group\"*" or "*\"net user\"*" or "*Domain Admins*" or "*Enterprise Admins*")
```

### Query 3 — Security Onion Windows Elastic Agent
**Security Onion specific:** Uses Elastic Agent telemetry in Security Onion 3.1.0 for Windows hosts. Requires Elastic Agent endpoint, system, Windows, macOS, Linux, or Elastic Defend data streams with ECS host, process, file, registry, authentication, or network fields.

```kql
event.category:process and agent.type:"elastic-agent" and host.os.type:windows and process.name:("net.exe" or "net1.exe" or "nltest.exe" or "dsquery.exe" or "powershell.exe") and process.command_line:("* user /domain*" or "* group /domain*" or "*domain admins*" or "*/dclist*" or "*Get-ADUser*" or "*Get-ADGroup*")
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:process AND agent.type:"elastic-agent" AND host.os.type:windows AND process.name:("net.exe" OR "net1.exe" OR "nltest.exe" OR "dsquery.exe" OR "powershell.exe") AND process.command_line:("* user /domain*" OR "* group /domain*" OR "*domain admins*" OR "*/dclist*" OR "*Get-ADUser*" OR "*Get-ADGroup*") | groupby host.name host.os.type user.name process.name process.parent.name destination.ip destination.port event.action | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port network.transport network.community_id event.code rule.name
```

**Tuning ideas:** allowlist known admin scripts, software deployment tools, scanners, EDR activity, patch management, and sanctioned cloud apps before alerting.

---

## T1018 — Remote System Discovery

**Tactic:** Discovery  
**Detection idea:** Remote host discovery through native tools  
**Elastic implementation notes:** ECS field names vary by integration. Start with the KQL below, then tune for your Elastic Agent, Elastic Defend, Windows, System, Sysmon, cloud, and email data streams.

### Query 1
```kql
event.category:process and process.name:("net.exe" or "net1.exe" or "nltest.exe" or "ping.exe" or "arp.exe" or "nbtstat.exe" or "powershell.exe") and process.command_line:("*view*" or "*/domain_trusts*" or "*Get-ADComputer*" or "*Test-Connection*" or "*Resolve-DnsName*")
```

### Query 2
```kql
event.category:process and process.name:("cmd.exe" or "powershell.exe" or "pwsh.exe") and process.command_line:("*for /l*" or "*1,1,254*" or "*ping -n*" or "*arp -a*")
```

**Tuning ideas:** allowlist known admin scripts, software deployment tools, scanners, EDR activity, patch management, and sanctioned cloud apps before alerting.

---

### Query 3 — Security Onion
**Security Onion specific:** Uses Security Onion Zeek DNS metadata for host discovery-style queries.

```kql
event.dataset:dns and dns.question.name:("*.local" or "*.lan" or "*.internal" or "*.corp") and source.ip:*
```

**Security Onion Hunt dashboard (OQL):** Uses Security Onion 3.1 Hunt syntax. The filter uses Lucene/OQL boolean operators and adds Hunt-friendly grouping, sorting, and event-table columns.

```oql
event.dataset:dns AND dns.question.name:("*.local" OR "*.lan" OR "*.internal" OR "*.corp") AND source.ip:* | groupby event.dataset source.ip destination.ip destination.port rule.name | sortby @timestamp | table event.module event.dataset source.ip source.port destination.ip destination.port network.transport network.community_id log.id.uid rule.name dns.question.name url.domain tls.server.name http.request.method file.name file.path host.name user.name event.code event.action
```

### Query 4 — Security Onion
**Security Onion specific:** Uses Security Onion Zeek connection metadata for SMB/RPC/NetBIOS discovery traffic.

```kql
event.dataset:conn and destination.port:(135 or 137 or 138 or 139 or 445) and source.ip:* and destination.ip:*
```

**Security Onion Hunt dashboard (OQL):** Uses Security Onion 3.1 Hunt syntax. The filter uses Lucene/OQL boolean operators and adds Hunt-friendly grouping, sorting, and event-table columns.

```oql
event.dataset:conn AND destination.port:(135 OR 137 OR 138 OR 139 OR 445) AND source.ip:* AND destination.ip:* | groupby event.dataset source.ip destination.ip destination.port rule.name | sortby @timestamp | table event.module event.dataset source.ip source.port destination.ip destination.port network.transport network.community_id log.id.uid rule.name dns.question.name url.domain tls.server.name http.request.method file.name file.path host.name user.name event.code event.action
```
### Query 5 — Security Onion Windows Elastic Agent
**Security Onion specific:** Uses Elastic Agent telemetry in Security Onion 3.1.0 for Windows hosts. Requires Elastic Agent endpoint, system, Windows, macOS, Linux, or Elastic Defend data streams with ECS host, process, file, registry, authentication, or network fields.

```kql
event.category:process and agent.type:"elastic-agent" and host.os.type:windows and process.name:("net.exe" or "net1.exe" or "nltest.exe" or "arp.exe" or "ping.exe" or "powershell.exe") and process.command_line:("* view*" or "*/domain_trusts*" or "*/dclist*" or "*Test-Connection*" or "*Get-ADComputer*")
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:process AND agent.type:"elastic-agent" AND host.os.type:windows AND process.name:("net.exe" OR "net1.exe" OR "nltest.exe" OR "arp.exe" OR "ping.exe" OR "powershell.exe") AND process.command_line:("* view*" OR "*/domain_trusts*" OR "*/dclist*" OR "*Test-Connection*" OR "*Get-ADComputer*") | groupby host.name host.os.type user.name process.name process.parent.name destination.ip destination.port event.action | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port network.transport network.community_id event.code rule.name
```

## T1046 — Network Service Discovery

**Tactic:** Discovery  
**Detection idea:** Port scanning and service enumeration  
**Elastic implementation notes:** ECS field names vary by integration. Start with the KQL below, then tune for your Elastic Agent, Elastic Defend, Windows, System, Sysmon, cloud, and email data streams.

### Query 1
```kql
event.category:process and process.name:("nmap.exe" or "masscan.exe" or "powershell.exe" or "pwsh.exe" or "nc.exe" or "netcat.exe") and process.command_line:("*-p*" or "*port*" or "*Test-NetConnection*" or "*TcpClient*" or "*scan*")
```

### Query 2
```kql
event.category:network and source.ip:* and destination.port:(21 or 22 or 23 or 80 or 135 or 139 or 443 or 445 or 3389 or 5985 or 5986)
```

**Tuning ideas:** allowlist known admin scripts, software deployment tools, scanners, EDR activity, patch management, and sanctioned cloud apps before alerting.

---

### Query 3 — Security Onion
**Security Onion specific:** Uses Security Onion Suricata scan signatures for network service discovery.

```kql
event.module:"Suricata" and event.dataset:"alert" and rule.name:("*SCAN*" or "*Port Scan*" or "*Nmap*" or "*Masscan*" or "*Zmap*") and source.ip:* and destination.ip:*
```

**Security Onion Hunt dashboard (OQL):** Uses Security Onion 3.1 Hunt syntax. The filter uses Lucene/OQL boolean operators and adds Hunt-friendly grouping, sorting, and event-table columns.

```oql
event.module:"Suricata" AND event.dataset:"alert" AND rule.name:("*SCAN*" OR "*Port Scan*" OR "*Nmap*" OR "*Masscan*" OR "*Zmap*") AND source.ip:* AND destination.ip:* | groupby event.dataset source.ip destination.ip destination.port rule.name | sortby @timestamp | table event.module event.dataset source.ip source.port destination.ip destination.port network.transport network.community_id log.id.uid rule.name dns.question.name url.domain tls.server.name http.request.method file.name file.path host.name user.name event.code event.action
```

### Query 4 — Security Onion
**Security Onion specific:** Uses Security Onion Zeek connection metadata for many common service probes from monitored sources.

```kql
event.dataset:conn and destination.port:(21 or 22 or 23 or 25 or 53 or 80 or 110 or 135 or 139 or 143 or 443 or 445 or 1433 or 1521 or 3306 or 3389 or 5432 or 5900 or 5985 or 5986) and source.ip:* and destination.ip:*
```

**Security Onion Hunt dashboard (OQL):** Uses Security Onion 3.1 Hunt syntax. The filter uses Lucene/OQL boolean operators and adds Hunt-friendly grouping, sorting, and event-table columns.

```oql
event.dataset:conn AND destination.port:(21 OR 22 OR 23 OR 25 OR 53 OR 80 OR 110 OR 135 OR 139 OR 143 OR 443 OR 445 OR 1433 OR 1521 OR 3306 OR 3389 OR 5432 OR 5900 OR 5985 OR 5986) AND source.ip:* AND destination.ip:* | groupby event.dataset source.ip destination.ip destination.port rule.name | sortby @timestamp | table event.module event.dataset source.ip source.port destination.ip destination.port network.transport network.community_id log.id.uid rule.name dns.question.name url.domain tls.server.name http.request.method file.name file.path host.name user.name event.code event.action
```
### Query 5 — Security Onion Linux Elastic Agent
**Security Onion specific:** Uses Elastic Agent telemetry in Security Onion 3.1.0 for Linux hosts. Requires Elastic Agent endpoint, system, Windows, macOS, Linux, or Elastic Defend data streams with ECS host, process, file, registry, authentication, or network fields.

```kql
event.category:process and agent.type:"elastic-agent" and host.os.type:linux and process.name:(nmap or masscan or zmap or nc or ncat) and process.command_line:("*-sS*" or "*-sV*" or "*-p*" or "*--top-ports*" or "* -zv*")
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:process AND agent.type:"elastic-agent" AND host.os.type:linux AND process.name:(nmap OR masscan OR zmap OR nc OR ncat) AND process.command_line:("*-sS*" OR "*-sV*" OR "*-p*" OR "*--top-ports*" OR "* -zv*") | groupby host.name host.os.type user.name process.name process.parent.name destination.ip destination.port event.action | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line process.executable file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port destination.domain network.transport event.code rule.name
```

## T1082 — System Information Discovery

**Tactic:** Discovery  
**Detection idea:** System, domain, OS, and patch discovery commands  
**Elastic implementation notes:** ECS field names vary by integration. Start with the KQL below, then tune for your Elastic Agent, Elastic Defend, Windows, System, Sysmon, cloud, and email data streams.

### Query 1
```kql
event.category:process and process.name:("systeminfo.exe" or "hostname.exe" or "whoami.exe" or "ipconfig.exe" or "wmic.exe")
```

### Query 2
```kql
event.category:process and process.command_line:("*systeminfo*" or "*whoami /all*" or "*wmic qfe*" or "*Get-ComputerInfo*" or "*Get-HotFix*")
```

### Query 3 — Security Onion Linux/macOS Elastic Agent
**Security Onion specific:** Uses Elastic Agent telemetry in Security Onion 3.1.0 for Linux/macOS hosts. Requires Elastic Agent endpoint, system, or Elastic Defend data streams with ECS host, process, file, or network fields.

```kql
event.category:process and agent.type:"elastic-agent" and host.os.type:(linux or macos) and process.name:(uname or hostname or whoami or id or sw_vers or system_profiler or dscl) and process.command_line:*
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:process AND agent.type:"elastic-agent" AND host.os.type:(linux OR macos) AND process.name:(uname OR hostname OR whoami OR id OR sw_vers OR system_profiler OR dscl) AND process.command_line:* | groupby host.name host.os.type user.name process.name source.ip destination.ip destination.port | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line file.path file.name file.extension source.ip source.port destination.ip destination.port network.transport network.community_id rule.name
```

### Query 4 — Security Onion macOS Elastic Agent
**Security Onion specific:** Uses Elastic Agent telemetry in Security Onion 3.1.0 for macOS hosts. Requires Elastic Agent endpoint, system, Windows, macOS, Linux, or Elastic Defend data streams with ECS host, process, file, registry, authentication, or network fields.

```kql
event.category:process and agent.type:"elastic-agent" and host.os.type:macos and process.name:(sw_vers or system_profiler or uname or profiles or dscl) and process.command_line:*
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:process AND agent.type:"elastic-agent" AND host.os.type:macos AND process.name:(sw_vers OR system_profiler OR uname OR profiles OR dscl) AND process.command_line:* | groupby host.name host.os.type user.name process.name process.parent.name destination.ip destination.port event.action | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port network.transport network.community_id event.code rule.name
```

**Tuning ideas:** allowlist known admin scripts, software deployment tools, scanners, EDR activity, patch management, and sanctioned cloud apps before alerting.

---

## T1057 — Process Discovery

**Tactic:** Discovery  
**Detection idea:** Process listing commands and tooling  
**Elastic implementation notes:** ECS field names vary by integration. Start with the KQL below, then tune for your Elastic Agent, Elastic Defend, Windows, System, Sysmon, cloud, and email data streams.

### Query 1
```kql
event.category:process and process.name:("tasklist.exe" or "wmic.exe" or "powershell.exe" or "pwsh.exe" or "ps.exe") and process.command_line:("*process*" or "*Get-Process*" or "*tasklist*" or "*ps *")
```

### Query 2
```kql
event.category:process and process.command_line:("*Get-Process*" or "*gwmi win32_process*" or "*wmic process list*" or "*tasklist /v*")
```

### Query 3 — Security Onion Windows Elastic Agent
**Security Onion specific:** Uses Elastic Agent telemetry in Security Onion 3.1.0 for Windows hosts. Requires Elastic Agent endpoint, system, Windows, macOS, Linux, or Elastic Defend data streams with ECS host, process, file, registry, authentication, or network fields.

```kql
event.category:process and agent.type:"elastic-agent" and host.os.type:windows and process.name:("tasklist.exe" or "wmic.exe" or "powershell.exe" or "pwsh.exe") and process.command_line:("*process*" or "*Get-Process*" or "*Win32_Process*")
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:process AND agent.type:"elastic-agent" AND host.os.type:windows AND process.name:("tasklist.exe" OR "wmic.exe" OR "powershell.exe" OR "pwsh.exe") AND process.command_line:("*process*" OR "*Get-Process*" OR "*Win32_Process*") | groupby host.name host.os.type user.name process.name process.parent.name destination.ip destination.port event.action | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line process.executable file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port destination.domain network.transport event.code rule.name
```

### Query 4 — Security Onion macOS Elastic Agent
**Security Onion specific:** Uses Elastic Agent telemetry in Security Onion 3.1.0 for macOS hosts. Requires Elastic Agent endpoint, system, Windows, macOS, Linux, or Elastic Defend data streams with ECS host, process, file, registry, authentication, or network fields.

```kql
event.category:process and agent.type:"elastic-agent" and host.os.type:macos and process.name:(ps or top or pgrep or launchctl) and process.command_line:("* aux*" or "* list*" or "* -ef*" or "* -axo*")
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:process AND agent.type:"elastic-agent" AND host.os.type:macos AND process.name:(ps OR top OR pgrep OR launchctl) AND process.command_line:("* aux*" OR "* list*" OR "* -ef*" OR "* -axo*") | groupby host.name host.os.type user.name process.name process.parent.name destination.ip destination.port event.action | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line process.executable file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port destination.domain network.transport event.code rule.name
```

**Tuning ideas:** allowlist known admin scripts, software deployment tools, scanners, EDR activity, patch management, and sanctioned cloud apps before alerting.

---

## T1083 — File and Directory Discovery

**Tactic:** Discovery  
**Detection idea:** File system enumeration through shell or PowerShell  
**Elastic implementation notes:** ECS field names vary by integration. Start with the KQL below, then tune for your Elastic Agent, Elastic Defend, Windows, System, Sysmon, cloud, and email data streams.

### Query 1
```kql
event.category:process and process.name:("cmd.exe" or "powershell.exe" or "pwsh.exe") and process.command_line:("* dir *" or "* tree *" or "*Get-ChildItem*" or "* gci *" or "*ls -la*")
```

### Query 2
```kql
event.category:process and process.command_line:("*\Users\*" or "*\ProgramData\*" or "*\Documents*" or "*\Desktop*") and process.command_line:("*dir*" or "*Get-ChildItem*" or "*findstr*")
```

### Query 3 — Security Onion Windows Elastic Agent
**Security Onion specific:** Uses Elastic Agent telemetry in Security Onion 3.1.0 for Windows hosts. Requires Elastic Agent endpoint, system, Windows, macOS, Linux, or Elastic Defend data streams with ECS host, process, file, registry, authentication, or network fields.

```kql
event.category:process and agent.type:"elastic-agent" and host.os.type:windows and process.name:("cmd.exe" or "powershell.exe" or "dir.exe") and process.command_line:("* /s *" or "*Get-ChildItem*" or "*\Users\*" or "*\Shares\*" or "*\Documents\*")
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:process AND agent.type:"elastic-agent" AND host.os.type:windows AND process.name:("cmd.exe" OR "powershell.exe" OR "dir.exe") AND process.command_line:("* /s *" OR "*Get-ChildItem*" OR "*\Users\*" OR "*\Shares\*" OR "*\Documents\*") | groupby host.name host.os.type user.name process.name process.parent.name destination.ip destination.port event.action | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line process.executable file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port destination.domain network.transport event.code rule.name
```

### Query 4 — Security Onion Linux Elastic Agent
**Security Onion specific:** Uses Elastic Agent telemetry in Security Onion 3.1.0 for Linux hosts. Requires Elastic Agent endpoint, system, Windows, macOS, Linux, or Elastic Defend data streams with ECS host, process, file, registry, authentication, or network fields.

```kql
event.category:process and agent.type:"elastic-agent" and host.os.type:linux and process.name:(find or ls or tree) and process.command_line:("*/home*" or "*/root*" or "*/mnt*" or "*/media*" or "*-name*")
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:process AND agent.type:"elastic-agent" AND host.os.type:linux AND process.name:(find OR ls OR tree) AND process.command_line:("*/home*" OR "*/root*" OR "*/mnt*" OR "*/media*" OR "*-name*") | groupby host.name host.os.type user.name process.name process.parent.name destination.ip destination.port event.action | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line process.executable file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port destination.domain network.transport event.code rule.name
```

### Query 5 — Security Onion macOS Elastic Agent
**Security Onion specific:** Uses Elastic Agent telemetry in Security Onion 3.1.0 for macOS hosts. Requires Elastic Agent endpoint, system, Windows, macOS, Linux, or Elastic Defend data streams with ECS host, process, file, registry, authentication, or network fields.

```kql
event.category:process and agent.type:"elastic-agent" and host.os.type:macos and process.name:(find or ls or mdfind) and process.command_line:("*/Users/*" or "*/Volumes/*" or "*.doc*" or "*.pdf*" or "*.key*")
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:process AND agent.type:"elastic-agent" AND host.os.type:macos AND process.name:(find OR ls OR mdfind) AND process.command_line:("*/Users/*" OR "*/Volumes/*" OR "*.doc*" OR "*.pdf*" OR "*.key*") | groupby host.name host.os.type user.name process.name process.parent.name destination.ip destination.port event.action | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line process.executable file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port destination.domain network.transport event.code rule.name
```

**Tuning ideas:** allowlist known admin scripts, software deployment tools, scanners, EDR activity, patch management, and sanctioned cloud apps before alerting.

---

## T1016 — System Network Configuration Discovery

**Tactic:** Discovery  
**Detection idea:** Network interface, route, DNS, or firewall configuration discovery  
**Elastic implementation notes:** ECS field names vary by integration. Start with the KQL below, then tune for your Elastic Agent, Elastic Defend, Windows, System, Sysmon, cloud, and email data streams.

### Query 1
```kql
event.category:process and process.name:("ipconfig.exe" or "route.exe" or "netsh.exe" or "powershell.exe" or "pwsh.exe") and process.command_line:("*all*" or "*route*" or "*interface*" or "*Get-NetIPConfiguration*" or "*Get-DnsClientServerAddress*")
```

### Query 2
```kql
event.category:process and process.command_line:("*ipconfig /all*" or "*route print*" or "*netsh advfirewall show*" or "*Get-NetRoute*" or "*Get-NetAdapter*")
```

**Tuning ideas:** allowlist known admin scripts, software deployment tools, scanners, EDR activity, patch management, and sanctioned cloud apps before alerting.

---

### Query 3 — Security Onion
**Security Onion specific:** Uses Security Onion Zeek DHCP metadata for network configuration discovery context.

```kql
event.dataset:dhcp and (client.ip:* or source.ip:* or host.name:*)
```

**Security Onion Hunt dashboard (OQL):** Uses Security Onion 3.1 Hunt syntax. The filter uses Lucene/OQL boolean operators and adds Hunt-friendly grouping, sorting, and event-table columns.

```oql
event.dataset:dhcp AND (client.ip:* OR source.ip:* OR host.name:*) | groupby event.dataset source.ip destination.ip destination.port rule.name | sortby @timestamp | table event.module event.dataset source.ip source.port destination.ip destination.port network.transport network.community_id log.id.uid rule.name dns.question.name url.domain tls.server.name http.request.method file.name file.path host.name user.name event.code event.action
```

### Query 4 — Security Onion
**Security Onion specific:** Uses Security Onion Zeek DNS metadata for resolver and domain-discovery activity.

```kql
event.dataset:dns and dns.question.name:* and source.ip:*
```

**Security Onion Hunt dashboard (OQL):** Uses Security Onion 3.1 Hunt syntax. The filter uses Lucene/OQL boolean operators and adds Hunt-friendly grouping, sorting, and event-table columns.

```oql
event.dataset:dns AND dns.question.name:* AND source.ip:* | groupby event.dataset source.ip destination.ip destination.port rule.name | sortby @timestamp | table event.module event.dataset source.ip source.port destination.ip destination.port network.transport network.community_id log.id.uid rule.name dns.question.name url.domain tls.server.name http.request.method file.name file.path host.name user.name event.code event.action
```
### Query 5 — Security Onion macOS Elastic Agent
**Security Onion specific:** Uses Elastic Agent telemetry in Security Onion 3.1.0 for macOS hosts. Requires Elastic Agent endpoint, system, Windows, macOS, Linux, or Elastic Defend data streams with ECS host, process, file, registry, authentication, or network fields.

```kql
event.category:process and agent.type:"elastic-agent" and host.os.type:macos and process.name:(ifconfig or networksetup or route or scutil or netstat) and process.command_line:*
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:process AND agent.type:"elastic-agent" AND host.os.type:macos AND process.name:(ifconfig OR networksetup OR route OR scutil OR netstat) AND process.command_line:* | groupby host.name host.os.type user.name process.name process.parent.name destination.ip destination.port event.action | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port network.transport network.community_id event.code rule.name
```
### Query 6 — Security Onion Linux Elastic Agent
**Security Onion specific:** Uses Elastic Agent telemetry in Security Onion 3.1.0 for Linux hosts. Requires Elastic Agent endpoint, system, Windows, macOS, Linux, or Elastic Defend data streams with ECS host, process, file, registry, authentication, or network fields.

```kql
event.category:process and agent.type:"elastic-agent" and host.os.type:linux and process.name:(ip or ifconfig or route or resolvectl or nmcli) and process.command_line:("* addr*" or "* route*" or "* link*" or "*dns*" or "*connection show*")
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:process AND agent.type:"elastic-agent" AND host.os.type:linux AND process.name:(ip OR ifconfig OR route OR resolvectl OR nmcli) AND process.command_line:("* addr*" OR "* route*" OR "* link*" OR "*dns*" OR "*connection show*") | groupby host.name host.os.type user.name process.name process.parent.name destination.ip destination.port event.action | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line process.executable file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port destination.domain network.transport event.code rule.name
```

## T1033 — System Owner/User Discovery

**Tactic:** Discovery  
**Detection idea:** Current user and privilege discovery commands  
**Elastic implementation notes:** ECS field names vary by integration. Start with the KQL below, then tune for your Elastic Agent, Elastic Defend, Windows, System, Sysmon, cloud, and email data streams.

### Query 1
```kql
event.category:process and process.name:("whoami.exe" or "cmd.exe" or "powershell.exe" or "pwsh.exe") and process.command_line:("*whoami*" or "*query user*" or "*quser*" or "*Get-LocalUser*" or "*Get-ADUser*")
```

### Query 2
```kql
event.category:process and process.command_line:("*whoami /all*" or "*echo %USERNAME%*" or "*$env:USERNAME*" or "*net user %USERNAME%*")
```

**Tuning ideas:** allowlist known admin scripts, software deployment tools, scanners, EDR activity, patch management, and sanctioned cloud apps before alerting.

---

## T1069.002 — Permission Groups Discovery: Domain Groups

**Tactic:** Discovery  
**Detection idea:** Domain group and privileged group enumeration  
**Elastic implementation notes:** ECS field names vary by integration. Start with the KQL below, then tune for your Elastic Agent, Elastic Defend, Windows, System, Sysmon, cloud, and email data streams.

### Query 1
```kql
event.category:process and process.name:("net.exe" or "net1.exe" or "dsquery.exe" or "powershell.exe" or "pwsh.exe") and process.command_line:("*domain admins*" or "*enterprise admins*" or "*net group* /domain*" or "*Get-ADGroupMember*")
```

### Query 2
```kql
event.category:process and process.command_line:("*Get-ADGroup*" or "*Get-ADPrincipalGroupMembership*" or "*dsquery group*" or "*nltest /domain_trusts*")
```

**Tuning ideas:** allowlist known admin scripts, software deployment tools, scanners, EDR activity, patch management, and sanctioned cloud apps before alerting.

---

## T1482 — Domain Trust Discovery

**Tactic:** Discovery  
**Detection idea:** Domain trust enumeration commands  
**Elastic implementation notes:** ECS field names vary by integration. Start with the KQL below, then tune for your Elastic Agent, Elastic Defend, Windows, System, Sysmon, cloud, and email data streams.

### Query 1
```kql
event.category:process and process.name:("nltest.exe" or "net.exe" or "netdom.exe" or "powershell.exe" or "pwsh.exe") and process.command_line:("*/domain_trusts*" or "*trust*" or "*Get-ADTrust*" or "*Get-DomainTrust*")
```

### Query 2
```kql
event.category:process and process.command_line:("*nltest /domain_trusts*" or "*netdom trust*" or "*Get-ADForest*" or "*Get-DomainTrustMapping*")
```

### Query 3 — Security Onion Windows Elastic Agent
**Security Onion specific:** Uses Elastic Agent telemetry in Security Onion 3.1.0 for Windows hosts. Requires Elastic Agent endpoint, system, Windows, macOS, Linux, or Elastic Defend data streams with ECS host, process, file, registry, authentication, or network fields.

```kql
event.category:process and agent.type:"elastic-agent" and host.os.type:windows and process.name:("nltest.exe" or "netdom.exe" or "powershell.exe" or "cmd.exe") and process.command_line:("*/domain_trusts*" or "*trust*" or "*Get-ADTrust*" or "*nltest*")
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:process AND agent.type:"elastic-agent" AND host.os.type:windows AND process.name:("nltest.exe" OR "netdom.exe" OR "powershell.exe" OR "cmd.exe") AND process.command_line:("*/domain_trusts*" OR "*trust*" OR "*Get-ADTrust*" OR "*nltest*") | groupby host.name host.os.type user.name process.name process.parent.name destination.ip destination.port event.action | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line process.executable file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port destination.domain network.transport event.code rule.name
```

### Query 4 — Security Onion Linux Elastic Agent
**Security Onion specific:** Uses Elastic Agent telemetry in Security Onion 3.1.0 for Linux hosts. Requires Elastic Agent endpoint, system, Windows, macOS, Linux, or Elastic Defend data streams with ECS host, process, file, registry, authentication, or network fields.

```kql
event.category:process and agent.type:"elastic-agent" and host.os.type:linux and process.name:(realm or adcli or klist or net or ldapsearch) and process.command_line:("*discover*" or "*trust*" or "*domain*" or "*ldap*" or "*krb5*")
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:process AND agent.type:"elastic-agent" AND host.os.type:linux AND process.name:(realm OR adcli OR klist OR net OR ldapsearch) AND process.command_line:("*discover*" OR "*trust*" OR "*domain*" OR "*ldap*" OR "*krb5*") | groupby host.name host.os.type user.name process.name process.parent.name destination.ip destination.port event.action | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line process.executable file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port destination.domain network.transport event.code rule.name
```

**Tuning ideas:** allowlist known admin scripts, software deployment tools, scanners, EDR activity, patch management, and sanctioned cloud apps before alerting.

---

## T1012 — Query Registry

**Tactic:** Discovery  
**Detection idea:** Registry query commands used for host and software discovery  
**Elastic implementation notes:** ECS field names vary by integration. Start with the KQL below, then tune for your Elastic Agent, Elastic Defend, Windows, System, Sysmon, cloud, and email data streams.

### Query 1
```kql
event.category:process and process.name:("reg.exe" or "powershell.exe" or "pwsh.exe") and process.command_line:("* query *" or "*Get-ItemProperty*" or "*HKLM\Software*" or "*HKCU\Software*")
```

### Query 2
```kql
event.category:process and process.command_line:("*CurrentVersion\Uninstall*" or "*Run\*" or "*Windows Defender*" or "*Terminal Server Client*")
```

### Query 3 — Security Onion Windows Elastic Agent
**Security Onion specific:** Uses Elastic Agent telemetry in Security Onion 3.1.0 for Windows hosts. Requires Elastic Agent endpoint, system, Windows, macOS, Linux, or Elastic Defend data streams with ECS host, process, file, registry, authentication, or network fields.

```kql
event.category:process and agent.type:"elastic-agent" and host.os.type:windows and process.name:"reg.exe" and process.command_line:("* query *" or "*HKLM\Software*" or "*HKCU\Software*" or "*CurrentVersion\Run*" or "*Uninstall*")
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:process AND agent.type:"elastic-agent" AND host.os.type:windows AND process.name:"reg.exe" AND process.command_line:("* query *" OR "*HKLM\Software*" OR "*HKCU\Software*" OR "*CurrentVersion\Run*" OR "*Uninstall*") | groupby host.name host.os.type user.name process.name process.parent.name destination.ip destination.port event.action | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line process.executable file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port destination.domain network.transport event.code rule.name
```

**Tuning ideas:** allowlist known admin scripts, software deployment tools, scanners, EDR activity, patch management, and sanctioned cloud apps before alerting.

---

## T1049 — System Network Connections Discovery

**Tactic:** Discovery  
**Detection idea:** Linux Elastic Agent network connection discovery commands  
**Elastic implementation notes:** Host telemetry requires Elastic Agent with endpoint, system, Windows, macOS, Linux, or Elastic Defend integrations. Field availability varies by agent policy and event collection settings.

### Query 1 — Security Onion Linux Elastic Agent
**Security Onion specific:** Uses Elastic Agent telemetry in Security Onion 3.1.0 for Linux hosts. Requires Elastic Agent endpoint, system, Windows, macOS, Linux, or Elastic Defend data streams with ECS host, process, file, registry, authentication, or network fields.

```kql
event.category:process and agent.type:"elastic-agent" and host.os.type:linux and process.name:(ss or netstat or lsof or ip or route) and process.command_line:("*-tul*" or "*-an*" or "* addr*" or "* route*")
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:process AND agent.type:"elastic-agent" AND host.os.type:linux AND process.name:(ss OR netstat OR lsof OR ip OR route) AND process.command_line:("*-tul*" OR "*-an*" OR "* addr*" OR "* route*") | groupby host.name host.os.type user.name process.name process.parent.name destination.ip destination.port event.action | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port network.transport network.community_id event.code rule.name
```


### Query 2 — Security Onion macOS Elastic Agent
**Security Onion specific:** Uses Elastic Agent telemetry in Security Onion 3.1.0 for macOS hosts. Requires Elastic Agent endpoint, system, Windows, macOS, Linux, or Elastic Defend data streams with ECS host, process, file, registry, authentication, or network fields.

```kql
event.category:process and agent.type:"elastic-agent" and host.os.type:macos and process.name:(netstat or lsof or scutil or networksetup) and process.command_line:("*-an*" or "*-iTCP*" or "*--dns*" or "*-listallhardwareports*")
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:process AND agent.type:"elastic-agent" AND host.os.type:macos AND process.name:(netstat OR lsof OR scutil OR networksetup) AND process.command_line:("*-an*" OR "*-iTCP*" OR "*--dns*" OR "*-listallhardwareports*") | groupby host.name host.os.type user.name process.name process.parent.name destination.ip destination.port event.action | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line process.executable file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port destination.domain network.transport event.code rule.name
```

**Tuning ideas:** allowlist approved admin scripts, package managers, MDM/GPO activity, backup tools, EDR activity, deployment systems, developer workflows, and sanctioned remote administration.

---

## T1087.001 — Account Discovery: Local Account

**Tactic:** Discovery  
**Detection idea:** Linux Elastic Agent local account discovery through passwd, id, getent, or who commands  
**Elastic implementation notes:** Host telemetry requires Elastic Agent with endpoint, system, Windows, macOS, Linux, or Elastic Defend integrations. Field availability varies by agent policy and event collection settings.

### Query 1 — Security Onion Linux Elastic Agent
**Security Onion specific:** Uses Elastic Agent telemetry in Security Onion 3.1.0 for Linux hosts. Requires Elastic Agent endpoint, system, Windows, macOS, Linux, or Elastic Defend data streams with ECS host, process, file, registry, authentication, or network fields.

```kql
event.category:process and agent.type:"elastic-agent" and host.os.type:linux and process.name:(cat or getent or id or who or w) and process.command_line:("*/etc/passwd*" or "* passwd*" or "* shadow*" or "* group*")
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:process AND agent.type:"elastic-agent" AND host.os.type:linux AND process.name:(cat OR getent OR id OR who OR w) AND process.command_line:("*/etc/passwd*" OR "* passwd*" OR "* shadow*" OR "* group*") | groupby host.name host.os.type user.name process.name process.parent.name destination.ip destination.port event.action | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port network.transport network.community_id event.code rule.name
```


### Query 2 — Security Onion macOS Elastic Agent
**Security Onion specific:** Uses Elastic Agent telemetry in Security Onion 3.1.0 for macOS hosts. Requires Elastic Agent endpoint, system, Windows, macOS, Linux, or Elastic Defend data streams with ECS host, process, file, registry, authentication, or network fields.

```kql
event.category:process and agent.type:"elastic-agent" and host.os.type:macos and process.name:(dscl or id or groups or who or dscacheutil) and process.command_line:("*. -list /Users*" or "*. -read /Groups*" or "*GroupMembership*" or "* -q user*")
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:process AND agent.type:"elastic-agent" AND host.os.type:macos AND process.name:(dscl OR id OR groups OR who OR dscacheutil) AND process.command_line:("*. -list /Users*" OR "*. -read /Groups*" OR "*GroupMembership*" OR "* -q user*") | groupby host.name host.os.type user.name process.name process.parent.name destination.ip destination.port event.action | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line process.executable file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port destination.domain network.transport event.code rule.name
```

**Tuning ideas:** allowlist approved admin scripts, package managers, MDM/GPO activity, backup tools, EDR activity, deployment systems, developer workflows, and sanctioned remote administration.

---

## T1069.001 — Permission Groups Discovery: Local Groups

**Tactic:** Discovery  
**Detection idea:** Linux Elastic Agent local group and sudo/wheel membership discovery  
**Elastic implementation notes:** Host telemetry requires Elastic Agent with endpoint, system, Windows, macOS, Linux, or Elastic Defend integrations. Field availability varies by agent policy and event collection settings.

### Query 1 — Security Onion Linux Elastic Agent
**Security Onion specific:** Uses Elastic Agent telemetry in Security Onion 3.1.0 for Linux hosts. Requires Elastic Agent endpoint, system, Windows, macOS, Linux, or Elastic Defend data streams with ECS host, process, file, registry, authentication, or network fields.

```kql
event.category:process and agent.type:"elastic-agent" and host.os.type:linux and process.name:(id or groups or getent or cat) and process.command_line:("* group*" or "*/etc/group*" or "*sudo*" or "*wheel*")
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:process AND agent.type:"elastic-agent" AND host.os.type:linux AND process.name:(id OR groups OR getent OR cat) AND process.command_line:("* group*" OR "*/etc/group*" OR "*sudo*" OR "*wheel*") | groupby host.name host.os.type user.name process.name process.parent.name destination.ip destination.port event.action | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line process.executable file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port destination.domain network.transport event.code rule.name
```


**Tuning ideas:** allowlist approved admin scripts, package managers, MDM/GPO activity, backup tools, EDR activity, deployment systems, developer workflows, and sanctioned remote administration.

---

---

## T1615 — Group Policy Discovery

**Tactic:** Discovery  
**Detection idea:** Group Policy setting and SYSVOL policy discovery through Windows domain tooling.  
**Elastic implementation notes:** These filters use ECS-style fields commonly present in Elastic Agent, Elastic Defend, Windows, Linux, macOS, Zeek, and Suricata data streams. Tune command-line patterns and administrative allowlists before production use.

### Query 1 — Security Onion Windows Elastic Agent
**Security Onion specific:** Uses Elastic Agent or Security Onion network telemetry in Security Onion 3.1.0. Requires the relevant endpoint, Zeek, Suricata, Windows, Linux, macOS, system, or Elastic Defend data streams with ECS-compatible fields.

```kql
event.category:process and agent.type:"elastic-agent" and host.os.type:windows and process.name:("gpresult.exe" or "gpupdate.exe" or "powershell.exe" or "cmd.exe") and process.command_line:("*/r*" or "*/scope*" or "*Get-GPO*" or "*Get-GPResultantSetOfPolicy*" or "*RSOP*")
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:process AND agent.type:"elastic-agent" AND host.os.type:windows AND process.name:("gpresult.exe" OR "gpupdate.exe" OR "powershell.exe" OR "cmd.exe") AND process.command_line:("*/r*" OR "*/scope*" OR "*Get-GPO*" OR "*Get-GPResultantSetOfPolicy*" OR "*RSOP*") | groupby host.name host.os.type user.name process.name process.parent.name event.action destination.ip destination.port | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line process.executable file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port destination.domain network.transport network.community_id event.code rule.name
```
### Query 2 — Security Onion Windows Elastic Agent
**Security Onion specific:** Uses Elastic Agent or Security Onion network telemetry in Security Onion 3.1.0. Requires the relevant endpoint, Zeek, Suricata, Windows, Linux, macOS, system, or Elastic Defend data streams with ECS-compatible fields.

```kql
event.category:process and agent.type:"elastic-agent" and host.os.type:windows and process.name:("dir.exe" or "cmd.exe" or "powershell.exe") and process.command_line:("*SYSVOL*" or "*\Policies\*" or "*Groups.xml*" or "*Registry.pol*")
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:process AND agent.type:"elastic-agent" AND host.os.type:windows AND process.name:("dir.exe" OR "cmd.exe" OR "powershell.exe") AND process.command_line:("*SYSVOL*" OR "*\Policies\*" OR "*Groups.xml*" OR "*Registry.pol*") | groupby host.name host.os.type user.name process.name process.parent.name event.action destination.ip destination.port | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line process.executable file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port destination.domain network.transport network.community_id event.code rule.name
```
### Query 3 — Security Onion Windows Elastic Agent
**Security Onion specific:** Uses Elastic Agent or Security Onion network telemetry in Security Onion 3.1.0. Requires the relevant endpoint, Zeek, Suricata, Windows, Linux, macOS, system, or Elastic Defend data streams with ECS-compatible fields.

```kql
event.category:network and agent.type:"elastic-agent" and host.os.type:windows and destination.port:(445 or 389 or 636) and process.name:("gpresult.exe" or "powershell.exe" or "cmd.exe" or "explorer.exe") and destination.ip:*
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:network AND agent.type:"elastic-agent" AND host.os.type:windows AND destination.port:(445 OR 389 OR 636) AND process.name:("gpresult.exe" OR "powershell.exe" OR "cmd.exe" OR "explorer.exe") AND destination.ip:* | groupby host.name host.os.type user.name process.name process.parent.name event.action destination.ip destination.port | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line process.executable file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port destination.domain network.transport network.community_id event.code rule.name
```

**Tuning ideas:** allowlist known administrators, software deployment tools, EDR activity, inventory systems, vulnerability scanners, patching tools, and sanctioned management workflows before alerting.

---

## T1680 — Local Storage Discovery

**Tactic:** Discovery  
**Detection idea:** Drive, disk, mounted volume, partition, and free-space enumeration across Windows, Linux, and macOS.  
**Elastic implementation notes:** These filters use ECS-style fields commonly present in Elastic Agent, Elastic Defend, Windows, Linux, macOS, Zeek, and Suricata data streams. Tune command-line patterns and administrative allowlists before production use.

### Query 1 — Security Onion Windows Elastic Agent
**Security Onion specific:** Uses Elastic Agent or Security Onion network telemetry in Security Onion 3.1.0. Requires the relevant endpoint, Zeek, Suricata, Windows, Linux, macOS, system, or Elastic Defend data streams with ECS-compatible fields.

```kql
event.category:process and agent.type:"elastic-agent" and host.os.type:windows and process.name:("wmic.exe" or "powershell.exe" or "fsutil.exe" or "diskpart.exe") and process.command_line:("*logicaldisk*" or "*Win32_LogicalDisk*" or "*Get-Volume*" or "*Get-PSDrive*" or "*volume list*" or "*drives*")
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:process AND agent.type:"elastic-agent" AND host.os.type:windows AND process.name:("wmic.exe" OR "powershell.exe" OR "fsutil.exe" OR "diskpart.exe") AND process.command_line:("*logicaldisk*" OR "*Win32_LogicalDisk*" OR "*Get-Volume*" OR "*Get-PSDrive*" OR "*volume list*" OR "*drives*") | groupby host.name host.os.type user.name process.name process.parent.name event.action destination.ip destination.port | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line process.executable file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port destination.domain network.transport network.community_id event.code rule.name
```
### Query 2 — Security Onion Linux Elastic Agent
**Security Onion specific:** Uses Elastic Agent or Security Onion network telemetry in Security Onion 3.1.0. Requires the relevant endpoint, Zeek, Suricata, Windows, Linux, macOS, system, or Elastic Defend data streams with ECS-compatible fields.

```kql
event.category:process and agent.type:"elastic-agent" and host.os.type:linux and process.name:(lsblk or df or blkid or fdisk or findmnt or mount) and process.command_line:*
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:process AND agent.type:"elastic-agent" AND host.os.type:linux AND process.name:(lsblk OR df OR blkid OR fdisk OR findmnt OR mount) AND process.command_line:* | groupby host.name host.os.type user.name process.name process.parent.name event.action destination.ip destination.port | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line process.executable file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port destination.domain network.transport network.community_id event.code rule.name
```
### Query 3 — Security Onion macOS Elastic Agent
**Security Onion specific:** Uses Elastic Agent or Security Onion network telemetry in Security Onion 3.1.0. Requires the relevant endpoint, Zeek, Suricata, Windows, Linux, macOS, system, or Elastic Defend data streams with ECS-compatible fields.

```kql
event.category:process and agent.type:"elastic-agent" and host.os.type:macos and process.name:(diskutil or df or mount or system_profiler) and process.command_line:("*list*" or "*SPStorageDataType*" or "*APFS*" or "*volume*")
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:process AND agent.type:"elastic-agent" AND host.os.type:macos AND process.name:(diskutil OR df OR mount OR system_profiler) AND process.command_line:("*list*" OR "*SPStorageDataType*" OR "*APFS*" OR "*volume*") | groupby host.name host.os.type user.name process.name process.parent.name event.action destination.ip destination.port | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line process.executable file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port destination.domain network.transport network.community_id event.code rule.name
```

**Tuning ideas:** allowlist known administrators, software deployment tools, EDR activity, inventory systems, vulnerability scanners, patching tools, and sanctioned management workflows before alerting.

---

## T1654 — Log Enumeration

**Tactic:** Discovery  
**Detection idea:** Local security, audit, system, and application log enumeration used to understand detection coverage or find evidence.  
**Elastic implementation notes:** These filters use ECS-style fields commonly present in Elastic Agent, Elastic Defend, Windows, Linux, macOS, Zeek, and Suricata data streams. Tune command-line patterns and administrative allowlists before production use.

### Query 1 — Security Onion Windows Elastic Agent
**Security Onion specific:** Uses Elastic Agent or Security Onion network telemetry in Security Onion 3.1.0. Requires the relevant endpoint, Zeek, Suricata, Windows, Linux, macOS, system, or Elastic Defend data streams with ECS-compatible fields.

```kql
event.category:process and agent.type:"elastic-agent" and host.os.type:windows and process.name:("wevtutil.exe" or "powershell.exe" or "cmd.exe") and process.command_line:("* el*" or "* qe*" or "*Get-WinEvent*" or "*Get-EventLog*" or "*Security*" or "*Sysmon*")
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:process AND agent.type:"elastic-agent" AND host.os.type:windows AND process.name:("wevtutil.exe" OR "powershell.exe" OR "cmd.exe") AND process.command_line:("* el*" OR "* qe*" OR "*Get-WinEvent*" OR "*Get-EventLog*" OR "*Security*" OR "*Sysmon*") | groupby host.name host.os.type user.name process.name process.parent.name event.action destination.ip destination.port | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line process.executable file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port destination.domain network.transport network.community_id event.code rule.name
```
### Query 2 — Security Onion Linux Elastic Agent
**Security Onion specific:** Uses Elastic Agent or Security Onion network telemetry in Security Onion 3.1.0. Requires the relevant endpoint, Zeek, Suricata, Windows, Linux, macOS, system, or Elastic Defend data streams with ECS-compatible fields.

```kql
event.category:process and agent.type:"elastic-agent" and host.os.type:linux and process.name:(journalctl or ausearch or grep or find or ls) and process.command_line:("*/var/log/*" or "*auth.log*" or "*secure*" or "*audit.log*" or "*journalctl*")
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:process AND agent.type:"elastic-agent" AND host.os.type:linux AND process.name:(journalctl OR ausearch OR grep OR find OR ls) AND process.command_line:("*/var/log/*" OR "*auth.log*" OR "*secure*" OR "*audit.log*" OR "*journalctl*") | groupby host.name host.os.type user.name process.name process.parent.name event.action destination.ip destination.port | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line process.executable file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port destination.domain network.transport network.community_id event.code rule.name
```
### Query 3 — Security Onion macOS Elastic Agent
**Security Onion specific:** Uses Elastic Agent or Security Onion network telemetry in Security Onion 3.1.0. Requires the relevant endpoint, Zeek, Suricata, Windows, Linux, macOS, system, or Elastic Defend data streams with ECS-compatible fields.

```kql
event.category:process and agent.type:"elastic-agent" and host.os.type:macos and process.name:(log or syslog or grep or find or ls) and process.command_line:("*show*" or "*stream*" or "*/var/log/*" or "*system.log*" or "*predicate*")
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:process AND agent.type:"elastic-agent" AND host.os.type:macos AND process.name:(log OR syslog OR grep OR find OR ls) AND process.command_line:("*show*" OR "*stream*" OR "*/var/log/*" OR "*system.log*" OR "*predicate*") | groupby host.name host.os.type user.name process.name process.parent.name event.action destination.ip destination.port | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line process.executable file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port destination.domain network.transport network.community_id event.code rule.name
```

**Tuning ideas:** allowlist known administrators, software deployment tools, EDR activity, inventory systems, vulnerability scanners, patching tools, and sanctioned management workflows before alerting.

---

## T1135 — Network Share Discovery

**Tactic:** Discovery  
**Detection idea:** SMB, NetBIOS, NFS, and mounted-share enumeration from hosts or network telemetry.  
**Elastic implementation notes:** These filters use ECS-style fields commonly present in Elastic Agent, Elastic Defend, Windows, Linux, macOS, Zeek, and Suricata data streams. Tune command-line patterns and administrative allowlists before production use.

### Query 1 — Security Onion Windows Elastic Agent
**Security Onion specific:** Uses Elastic Agent or Security Onion network telemetry in Security Onion 3.1.0. Requires the relevant endpoint, Zeek, Suricata, Windows, Linux, macOS, system, or Elastic Defend data streams with ECS-compatible fields.

```kql
event.category:process and agent.type:"elastic-agent" and host.os.type:windows and process.name:("net.exe" or "net1.exe" or "powershell.exe" or "cmd.exe") and process.command_line:("* view*" or "* share*" or "*Get-SmbShare*" or "*Get-SmbMapping*" or "*\\*\*")
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:process AND agent.type:"elastic-agent" AND host.os.type:windows AND process.name:("net.exe" OR "net1.exe" OR "powershell.exe" OR "cmd.exe") AND process.command_line:("* view*" OR "* share*" OR "*Get-SmbShare*" OR "*Get-SmbMapping*" OR "*\\*\*") | groupby host.name host.os.type user.name process.name process.parent.name event.action destination.ip destination.port | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line process.executable file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port destination.domain network.transport network.community_id event.code rule.name
```
### Query 2 — Security Onion Linux Elastic Agent
**Security Onion specific:** Uses Elastic Agent or Security Onion network telemetry in Security Onion 3.1.0. Requires the relevant endpoint, Zeek, Suricata, Windows, Linux, macOS, system, or Elastic Defend data streams with ECS-compatible fields.

```kql
event.category:process and agent.type:"elastic-agent" and host.os.type:linux and process.name:(smbclient or showmount or mount or findmnt or rpcinfo) and process.command_line:("*-L*" or "*-e*" or "* -t cifs*" or "* -t nfs*" or "*//*")
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:process AND agent.type:"elastic-agent" AND host.os.type:linux AND process.name:(smbclient OR showmount OR mount OR findmnt OR rpcinfo) AND process.command_line:("*-L*" OR "*-e*" OR "* -t cifs*" OR "* -t nfs*" OR "*//*") | groupby host.name host.os.type user.name process.name process.parent.name event.action destination.ip destination.port | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line process.executable file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port destination.domain network.transport network.community_id event.code rule.name
```
### Query 3 — Security Onion Zeek/Security Onion Network
**Security Onion specific:** Uses Elastic Agent or Security Onion network telemetry in Security Onion 3.1.0. Requires the relevant endpoint, Zeek, Suricata, Windows, Linux, macOS, system, or Elastic Defend data streams with ECS-compatible fields.

```kql
event.dataset:conn and destination.port:(111 or 139 or 445 or 2049) and source.ip:* and destination.ip:*
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.dataset:conn AND destination.port:(111 OR 139 OR 445 OR 2049) AND source.ip:* AND destination.ip:* | groupby host.name host.os.type user.name process.name process.parent.name event.action destination.ip destination.port | sortby @timestamp | table @timestamp event.module event.dataset source.ip source.port destination.ip destination.port destination.domain network.transport network.protocol network.community_id log.id.uid rule.name dns.question.name url.domain tls.server.name http.request.method http.request.body.content file.name file.path host.name user.name process.name event.code event.action
```

**Tuning ideas:** allowlist known administrators, software deployment tools, EDR activity, inventory systems, vulnerability scanners, patching tools, and sanctioned management workflows before alerting.

---

## T1201 — Password Policy Discovery

**Tactic:** Discovery  
**Detection idea:** Password and account lockout policy discovery through Windows domain, Linux PAM, and macOS policy tooling.  
**Elastic implementation notes:** These filters use ECS-style fields commonly present in Elastic Agent, Elastic Defend, Windows, Linux, macOS, Zeek, and Suricata data streams. Tune command-line patterns and administrative allowlists before production use.

### Query 1 — Security Onion Windows Elastic Agent
**Security Onion specific:** Uses Elastic Agent or Security Onion network telemetry in Security Onion 3.1.0. Requires the relevant endpoint, Zeek, Suricata, Windows, Linux, macOS, system, or Elastic Defend data streams with ECS-compatible fields.

```kql
event.category:process and agent.type:"elastic-agent" and host.os.type:windows and process.name:("net.exe" or "net1.exe" or "powershell.exe" or "cmd.exe") and process.command_line:("*accounts*" or "*/domain*" or "*Get-ADDefaultDomainPasswordPolicy*" or "*FineGrainedPasswordPolicy*")
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:process AND agent.type:"elastic-agent" AND host.os.type:windows AND process.name:("net.exe" OR "net1.exe" OR "powershell.exe" OR "cmd.exe") AND process.command_line:("*accounts*" OR "*/domain*" OR "*Get-ADDefaultDomainPasswordPolicy*" OR "*FineGrainedPasswordPolicy*") | groupby host.name host.os.type user.name process.name process.parent.name event.action destination.ip destination.port | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line process.executable file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port destination.domain network.transport network.community_id event.code rule.name
```
### Query 2 — Security Onion Linux Elastic Agent
**Security Onion specific:** Uses Elastic Agent or Security Onion network telemetry in Security Onion 3.1.0. Requires the relevant endpoint, Zeek, Suricata, Windows, Linux, macOS, system, or Elastic Defend data streams with ECS-compatible fields.

```kql
event.category:process and agent.type:"elastic-agent" and host.os.type:linux and process.name:(cat or grep or authconfig or faillock or chage) and process.command_line:("*/etc/login.defs*" or "*/etc/pam.d/*" or "*pam_pwquality*" or "*faillock*" or "*PASS_MAX_DAYS*")
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:process AND agent.type:"elastic-agent" AND host.os.type:linux AND process.name:(cat OR grep OR authconfig OR faillock OR chage) AND process.command_line:("*/etc/login.defs*" OR "*/etc/pam.d/*" OR "*pam_pwquality*" OR "*faillock*" OR "*PASS_MAX_DAYS*") | groupby host.name host.os.type user.name process.name process.parent.name event.action destination.ip destination.port | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line process.executable file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port destination.domain network.transport network.community_id event.code rule.name
```
### Query 3 — Security Onion macOS Elastic Agent
**Security Onion specific:** Uses Elastic Agent or Security Onion network telemetry in Security Onion 3.1.0. Requires the relevant endpoint, Zeek, Suricata, Windows, Linux, macOS, system, or Elastic Defend data streams with ECS-compatible fields.

```kql
event.category:process and agent.type:"elastic-agent" and host.os.type:macos and process.name:(pwpolicy or dscl or profiles) and process.command_line:("*getaccountpolicies*" or "*getglobalpolicy*" or "*maxFailedLoginAttempts*" or "*policyCategoryPasswordContent*")
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:process AND agent.type:"elastic-agent" AND host.os.type:macos AND process.name:(pwpolicy OR dscl OR profiles) AND process.command_line:("*getaccountpolicies*" OR "*getglobalpolicy*" OR "*maxFailedLoginAttempts*" OR "*policyCategoryPasswordContent*") | groupby host.name host.os.type user.name process.name process.parent.name event.action destination.ip destination.port | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line process.executable file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port destination.domain network.transport network.community_id event.code rule.name
```

**Tuning ideas:** allowlist known administrators, software deployment tools, EDR activity, inventory systems, vulnerability scanners, patching tools, and sanctioned management workflows before alerting.

---

## T1518 — Software Discovery

**Tactic:** Discovery  
**Detection idea:** Installed application, package, service, browser, and security software inventory checks.  
**Elastic implementation notes:** These filters use ECS-style fields commonly present in Elastic Agent, Elastic Defend, Windows, Linux, macOS, Zeek, and Suricata data streams. Tune command-line patterns and administrative allowlists before production use.

### Query 1 — Security Onion Windows Elastic Agent
**Security Onion specific:** Uses Elastic Agent or Security Onion network telemetry in Security Onion 3.1.0. Requires the relevant endpoint, Zeek, Suricata, Windows, Linux, macOS, system, or Elastic Defend data streams with ECS-compatible fields.

```kql
event.category:process and agent.type:"elastic-agent" and host.os.type:windows and process.name:("wmic.exe" or "powershell.exe" or "reg.exe" or "cmd.exe") and process.command_line:("*product get*" or "*Get-ItemProperty*Uninstall*" or "*Win32_Product*" or "*Program Files*" or "*DisplayName*")
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:process AND agent.type:"elastic-agent" AND host.os.type:windows AND process.name:("wmic.exe" OR "powershell.exe" OR "reg.exe" OR "cmd.exe") AND process.command_line:("*product get*" OR "*Get-ItemProperty*Uninstall*" OR "*Win32_Product*" OR "*Program Files*" OR "*DisplayName*") | groupby host.name host.os.type user.name process.name process.parent.name event.action destination.ip destination.port | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line process.executable file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port destination.domain network.transport network.community_id event.code rule.name
```
### Query 2 — Security Onion Linux Elastic Agent
**Security Onion specific:** Uses Elastic Agent or Security Onion network telemetry in Security Onion 3.1.0. Requires the relevant endpoint, Zeek, Suricata, Windows, Linux, macOS, system, or Elastic Defend data streams with ECS-compatible fields.

```kql
event.category:process and agent.type:"elastic-agent" and host.os.type:linux and process.name:(rpm or dpkg or apt or yum or snap or flatpak) and process.command_line:("*-qa*" or "*-l*" or "*list --installed*" or "*history*" or "*search*")
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:process AND agent.type:"elastic-agent" AND host.os.type:linux AND process.name:(rpm OR dpkg OR apt OR yum OR snap OR flatpak) AND process.command_line:("*-qa*" OR "*-l*" OR "*list --installed*" OR "*history*" OR "*search*") | groupby host.name host.os.type user.name process.name process.parent.name event.action destination.ip destination.port | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line process.executable file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port destination.domain network.transport network.community_id event.code rule.name
```
### Query 3 — Security Onion macOS Elastic Agent
**Security Onion specific:** Uses Elastic Agent or Security Onion network telemetry in Security Onion 3.1.0. Requires the relevant endpoint, Zeek, Suricata, Windows, Linux, macOS, system, or Elastic Defend data streams with ECS-compatible fields.

```kql
event.category:process and agent.type:"elastic-agent" and host.os.type:macos and process.name:(system_profiler or mdfind or ls or find) and process.command_line:("*SPApplicationsDataType*" or "*/Applications*" or "*.app*" or "*kMDItemKind*")
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:process AND agent.type:"elastic-agent" AND host.os.type:macos AND process.name:(system_profiler OR mdfind OR ls OR find) AND process.command_line:("*SPApplicationsDataType*" OR "*/Applications*" OR "*.app*" OR "*kMDItemKind*") | groupby host.name host.os.type user.name process.name process.parent.name event.action destination.ip destination.port | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line process.executable file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port destination.domain network.transport network.community_id event.code rule.name
```

**Tuning ideas:** allowlist known administrators, software deployment tools, EDR activity, inventory systems, vulnerability scanners, patching tools, and sanctioned management workflows before alerting.

---

## T1614 — System Location Discovery

**Tactic:** Discovery  
**Detection idea:** Language, locale, region, timezone, keyboard, or cloud availability-zone checks used to infer host location.  
**Elastic implementation notes:** These filters use ECS-style fields commonly present in Elastic Agent, Elastic Defend, Windows, Linux, macOS, Zeek, and Suricata data streams. Tune command-line patterns and administrative allowlists before production use.

### Query 1 — Security Onion Windows Elastic Agent
**Security Onion specific:** Uses Elastic Agent or Security Onion network telemetry in Security Onion 3.1.0. Requires the relevant endpoint, Zeek, Suricata, Windows, Linux, macOS, system, or Elastic Defend data streams with ECS-compatible fields.

```kql
event.category:process and agent.type:"elastic-agent" and host.os.type:windows and process.name:("tzutil.exe" or "w32tm.exe" or "powershell.exe" or "reg.exe") and process.command_line:("*/g*" or "*/tz*" or "*Get-TimeZone*" or "*Get-Culture*" or "*International*" or "*TimeZoneInformation*")
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:process AND agent.type:"elastic-agent" AND host.os.type:windows AND process.name:("tzutil.exe" OR "w32tm.exe" OR "powershell.exe" OR "reg.exe") AND process.command_line:("*/g*" OR "*/tz*" OR "*Get-TimeZone*" OR "*Get-Culture*" OR "*International*" OR "*TimeZoneInformation*") | groupby host.name host.os.type user.name process.name process.parent.name event.action destination.ip destination.port | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line process.executable file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port destination.domain network.transport network.community_id event.code rule.name
```
### Query 2 — Security Onion Linux Elastic Agent
**Security Onion specific:** Uses Elastic Agent or Security Onion network telemetry in Security Onion 3.1.0. Requires the relevant endpoint, Zeek, Suricata, Windows, Linux, macOS, system, or Elastic Defend data streams with ECS-compatible fields.

```kql
event.category:process and agent.type:"elastic-agent" and host.os.type:linux and process.name:(timedatectl or locale or date or cat or curl) and process.command_line:("*timezone*" or "*LANG*" or "*/etc/timezone*" or "*/etc/locale.conf*" or "*169.254.169.254*")
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:process AND agent.type:"elastic-agent" AND host.os.type:linux AND process.name:(timedatectl OR locale OR date OR cat OR curl) AND process.command_line:("*timezone*" OR "*LANG*" OR "*/etc/timezone*" OR "*/etc/locale.conf*" OR "*169.254.169.254*") | groupby host.name host.os.type user.name process.name process.parent.name event.action destination.ip destination.port | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line process.executable file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port destination.domain network.transport network.community_id event.code rule.name
```
### Query 3 — Security Onion macOS Elastic Agent
**Security Onion specific:** Uses Elastic Agent or Security Onion network telemetry in Security Onion 3.1.0. Requires the relevant endpoint, Zeek, Suricata, Windows, Linux, macOS, system, or Elastic Defend data streams with ECS-compatible fields.

```kql
event.category:process and agent.type:"elastic-agent" and host.os.type:macos and process.name:(systemsetup or defaults or locale or date) and process.command_line:("*gettimezone*" or "*AppleLocale*" or "*AppleLanguages*" or "*timezone*")
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:process AND agent.type:"elastic-agent" AND host.os.type:macos AND process.name:(systemsetup OR defaults OR locale OR date) AND process.command_line:("*gettimezone*" OR "*AppleLocale*" OR "*AppleLanguages*" OR "*timezone*") | groupby host.name host.os.type user.name process.name process.parent.name event.action destination.ip destination.port | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line process.executable file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port destination.domain network.transport network.community_id event.code rule.name
```

**Tuning ideas:** allowlist known administrators, software deployment tools, EDR activity, inventory systems, vulnerability scanners, patching tools, and sanctioned management workflows before alerting.

---

## T1007 — System Service Discovery

**Tactic:** Discovery  
**Detection idea:** Service and scheduled-service enumeration through native Windows, Linux, and macOS utilities.  
**Elastic implementation notes:** These filters use ECS-style fields commonly present in Elastic Agent, Elastic Defend, Windows, Linux, macOS, Zeek, and Suricata data streams. Tune command-line patterns and administrative allowlists before production use.

### Query 1 — Security Onion Windows Elastic Agent
**Security Onion specific:** Uses Elastic Agent or Security Onion network telemetry in Security Onion 3.1.0. Requires the relevant endpoint, Zeek, Suricata, Windows, Linux, macOS, system, or Elastic Defend data streams with ECS-compatible fields.

```kql
event.category:process and agent.type:"elastic-agent" and host.os.type:windows and process.name:("sc.exe" or "tasklist.exe" or "powershell.exe" or "wmic.exe") and process.command_line:("* query*" or "*/svc*" or "*Get-Service*" or "*Win32_Service*" or "*service list*")
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:process AND agent.type:"elastic-agent" AND host.os.type:windows AND process.name:("sc.exe" OR "tasklist.exe" OR "powershell.exe" OR "wmic.exe") AND process.command_line:("* query*" OR "*/svc*" OR "*Get-Service*" OR "*Win32_Service*" OR "*service list*") | groupby host.name host.os.type user.name process.name process.parent.name event.action destination.ip destination.port | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line process.executable file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port destination.domain network.transport network.community_id event.code rule.name
```
### Query 2 — Security Onion Linux Elastic Agent
**Security Onion specific:** Uses Elastic Agent or Security Onion network telemetry in Security Onion 3.1.0. Requires the relevant endpoint, Zeek, Suricata, Windows, Linux, macOS, system, or Elastic Defend data streams with ECS-compatible fields.

```kql
event.category:process and agent.type:"elastic-agent" and host.os.type:linux and process.name:(systemctl or service or chkconfig or ps) and process.command_line:("*list-units*" or "*--type=service*" or "*status*" or "*--list*" or "* aux*")
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:process AND agent.type:"elastic-agent" AND host.os.type:linux AND process.name:(systemctl OR service OR chkconfig OR ps) AND process.command_line:("*list-units*" OR "*--type=service*" OR "*status*" OR "*--list*" OR "* aux*") | groupby host.name host.os.type user.name process.name process.parent.name event.action destination.ip destination.port | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line process.executable file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port destination.domain network.transport network.community_id event.code rule.name
```
### Query 3 — Security Onion macOS Elastic Agent
**Security Onion specific:** Uses Elastic Agent or Security Onion network telemetry in Security Onion 3.1.0. Requires the relevant endpoint, Zeek, Suricata, Windows, Linux, macOS, system, or Elastic Defend data streams with ECS-compatible fields.

```kql
event.category:process and agent.type:"elastic-agent" and host.os.type:macos and process.name:(launchctl or ps or system_profiler) and process.command_line:("* list*" or "*print system*" or "*print gui*" or "*SPStartupItemDataType*")
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:process AND agent.type:"elastic-agent" AND host.os.type:macos AND process.name:(launchctl OR ps OR system_profiler) AND process.command_line:("* list*" OR "*print system*" OR "*print gui*" OR "*SPStartupItemDataType*") | groupby host.name host.os.type user.name process.name process.parent.name event.action destination.ip destination.port | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line process.executable file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port destination.domain network.transport network.community_id event.code rule.name
```

**Tuning ideas:** allowlist known administrators, software deployment tools, EDR activity, inventory systems, vulnerability scanners, patching tools, and sanctioned management workflows before alerting.

---

## T1124 — System Time Discovery

**Tactic:** Discovery  
**Detection idea:** System time, timezone, uptime, and time synchronization discovery.  
**Elastic implementation notes:** These filters use ECS-style fields commonly present in Elastic Agent, Elastic Defend, Windows, Linux, macOS, Zeek, and Suricata data streams. Tune command-line patterns and administrative allowlists before production use.

### Query 1 — Security Onion Windows Elastic Agent
**Security Onion specific:** Uses Elastic Agent or Security Onion network telemetry in Security Onion 3.1.0. Requires the relevant endpoint, Zeek, Suricata, Windows, Linux, macOS, system, or Elastic Defend data streams with ECS-compatible fields.

```kql
event.category:process and agent.type:"elastic-agent" and host.os.type:windows and process.name:("net.exe" or "net1.exe" or "w32tm.exe" or "tzutil.exe" or "powershell.exe") and process.command_line:("* time*" or "*/tz*" or "*/stripchart*" or "*Get-Date*" or "*Get-TimeZone*" or "*uptime*")
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:process AND agent.type:"elastic-agent" AND host.os.type:windows AND process.name:("net.exe" OR "net1.exe" OR "w32tm.exe" OR "tzutil.exe" OR "powershell.exe") AND process.command_line:("* time*" OR "*/tz*" OR "*/stripchart*" OR "*Get-Date*" OR "*Get-TimeZone*" OR "*uptime*") | groupby host.name host.os.type user.name process.name process.parent.name event.action destination.ip destination.port | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line process.executable file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port destination.domain network.transport network.community_id event.code rule.name
```
### Query 2 — Security Onion Linux Elastic Agent
**Security Onion specific:** Uses Elastic Agent or Security Onion network telemetry in Security Onion 3.1.0. Requires the relevant endpoint, Zeek, Suricata, Windows, Linux, macOS, system, or Elastic Defend data streams with ECS-compatible fields.

```kql
event.category:process and agent.type:"elastic-agent" and host.os.type:linux and process.name:(date or timedatectl or uptime or hwclock) and process.command_line:*
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:process AND agent.type:"elastic-agent" AND host.os.type:linux AND process.name:(date OR timedatectl OR uptime OR hwclock) AND process.command_line:* | groupby host.name host.os.type user.name process.name process.parent.name event.action destination.ip destination.port | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line process.executable file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port destination.domain network.transport network.community_id event.code rule.name
```
### Query 3 — Security Onion macOS Elastic Agent
**Security Onion specific:** Uses Elastic Agent or Security Onion network telemetry in Security Onion 3.1.0. Requires the relevant endpoint, Zeek, Suricata, Windows, Linux, macOS, system, or Elastic Defend data streams with ECS-compatible fields.

```kql
event.category:process and agent.type:"elastic-agent" and host.os.type:macos and process.name:(date or systemsetup or uptime) and process.command_line:("*gettimezone*" or "*getnetworktimeserver*" or "*getusingnetworktime*" or "*uptime*")
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:process AND agent.type:"elastic-agent" AND host.os.type:macos AND process.name:(date OR systemsetup OR uptime) AND process.command_line:("*gettimezone*" OR "*getnetworktimeserver*" OR "*getusingnetworktime*" OR "*uptime*") | groupby host.name host.os.type user.name process.name process.parent.name event.action destination.ip destination.port | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line process.executable file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port destination.domain network.transport network.community_id event.code rule.name
```

**Tuning ideas:** allowlist known administrators, software deployment tools, EDR activity, inventory systems, vulnerability scanners, patching tools, and sanctioned management workflows before alerting.

---

## T1673 — Virtual Machine Discovery

**Tactic:** Discovery  
**Detection idea:** Virtualization platform, hypervisor, guest tools, VM hardware, or ESXi-related discovery commands.  
**Elastic implementation notes:** These filters use ECS-style fields commonly present in Elastic Agent, Elastic Defend, Windows, Linux, macOS, Zeek, and Suricata data streams. Tune command-line patterns and administrative allowlists before production use.

### Query 1 — Security Onion Windows Elastic Agent
**Security Onion specific:** Uses Elastic Agent or Security Onion network telemetry in Security Onion 3.1.0. Requires the relevant endpoint, Zeek, Suricata, Windows, Linux, macOS, system, or Elastic Defend data streams with ECS-compatible fields.

```kql
event.category:process and agent.type:"elastic-agent" and host.os.type:windows and process.name:("wmic.exe" or "powershell.exe" or "systeminfo.exe" or "reg.exe") and process.command_line:("*Win32_ComputerSystem*" or "*Model*" or "*Manufacturer*" or "*VMware*" or "*VirtualBox*" or "*Hyper-V*" or "*QEMU*")
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:process AND agent.type:"elastic-agent" AND host.os.type:windows AND process.name:("wmic.exe" OR "powershell.exe" OR "systeminfo.exe" OR "reg.exe") AND process.command_line:("*Win32_ComputerSystem*" OR "*Model*" OR "*Manufacturer*" OR "*VMware*" OR "*VirtualBox*" OR "*Hyper-V*" OR "*QEMU*") | groupby host.name host.os.type user.name process.name process.parent.name event.action destination.ip destination.port | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line process.executable file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port destination.domain network.transport network.community_id event.code rule.name
```
### Query 2 — Security Onion Linux Elastic Agent
**Security Onion specific:** Uses Elastic Agent or Security Onion network telemetry in Security Onion 3.1.0. Requires the relevant endpoint, Zeek, Suricata, Windows, Linux, macOS, system, or Elastic Defend data streams with ECS-compatible fields.

```kql
event.category:process and agent.type:"elastic-agent" and host.os.type:linux and process.name:(systemd-detect-virt or dmidecode or lscpu or hostnamectl or cat) and process.command_line:("*--vm*" or "*product_name*" or "*sys_vendor*" or "*hypervisor*" or "*/sys/class/dmi/id/*")
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:process AND agent.type:"elastic-agent" AND host.os.type:linux AND process.name:(systemd-detect-virt OR dmidecode OR lscpu OR hostnamectl OR cat) AND process.command_line:("*--vm*" OR "*product_name*" OR "*sys_vendor*" OR "*hypervisor*" OR "*/sys/class/dmi/id/*") | groupby host.name host.os.type user.name process.name process.parent.name event.action destination.ip destination.port | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line process.executable file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port destination.domain network.transport network.community_id event.code rule.name
```
### Query 3 — Security Onion macOS Elastic Agent
**Security Onion specific:** Uses Elastic Agent or Security Onion network telemetry in Security Onion 3.1.0. Requires the relevant endpoint, Zeek, Suricata, Windows, Linux, macOS, system, or Elastic Defend data streams with ECS-compatible fields.

```kql
event.category:process and agent.type:"elastic-agent" and host.os.type:macos and process.name:(system_profiler or sysctl or ioreg) and process.command_line:("*SPHardwareDataType*" or "*machdep.cpu.features*" or "*VirtualBox*" or "*VMware*" or "*Parallels*")
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:process AND agent.type:"elastic-agent" AND host.os.type:macos AND process.name:(system_profiler OR sysctl OR ioreg) AND process.command_line:("*SPHardwareDataType*" OR "*machdep.cpu.features*" OR "*VirtualBox*" OR "*VMware*" OR "*Parallels*") | groupby host.name host.os.type user.name process.name process.parent.name event.action destination.ip destination.port | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line process.executable file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port destination.domain network.transport network.community_id event.code rule.name
```

**Tuning ideas:** allowlist known administrators, software deployment tools, EDR activity, inventory systems, vulnerability scanners, patching tools, and sanctioned management workflows before alerting.

---

## T1016.001 — System Network Configuration Discovery: Internet Connection Discovery

**Tactic:** Discovery  
**Detection idea:** Internet reachability checks and public IP discovery from command-line utilities.  
**Elastic implementation notes:** These filters use ECS-style fields commonly present in Elastic Agent, Elastic Defend, Windows, Linux, macOS, Zeek, Suricata, cloud, and SaaS data streams. Tune command-line patterns, data views, and administrative allowlists before production use.

### Query 1 — Security Onion Windows Elastic Agent
**Security Onion specific:** Uses Elastic Agent or Security Onion telemetry in Security Onion 3.1.0. Requires the relevant endpoint, Zeek, Suricata, cloud, SaaS, Windows, Linux, macOS, system, or Elastic Defend data streams with ECS-compatible fields.

```kql
event.category:process and agent.type:"elastic-agent" and host.os.type:windows and process.name:("powershell.exe" or "curl.exe" or "nslookup.exe" or "ping.exe") and process.command_line:("*ifconfig.me*" or "*api.ipify.org*" or "*icanhazip*" or "*Test-NetConnection*" or "*8.8.8.8*")
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:process AND agent.type:"elastic-agent" AND host.os.type:windows AND process.name:("powershell.exe" OR "curl.exe" OR "nslookup.exe" OR "ping.exe") AND process.command_line:("*ifconfig.me*" OR "*api.ipify.org*" OR "*icanhazip*" OR "*Test-NetConnection*" OR "*8.8.8.8*") | groupby host.name host.os.type user.name process.name process.parent.name event.action destination.ip destination.port | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line process.executable file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port destination.domain network.transport network.community_id event.code rule.name
```
### Query 2 — Security Onion Linux/macOS Elastic Agent
**Security Onion specific:** Uses Elastic Agent or Security Onion telemetry in Security Onion 3.1.0. Requires the relevant endpoint, Zeek, Suricata, cloud, SaaS, Windows, Linux, macOS, system, or Elastic Defend data streams with ECS-compatible fields.

```kql
event.category:process and agent.type:"elastic-agent" and host.os.type:(linux or macos) and process.name:(curl or wget or dig or nslookup or ping) and process.command_line:("*ifconfig.me*" or "*api.ipify.org*" or "*icanhazip*" or "*8.8.8.8*" or "*1.1.1.1*")
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:process AND agent.type:"elastic-agent" AND host.os.type:(linux OR macos) AND process.name:(curl OR wget OR dig OR nslookup OR ping) AND process.command_line:("*ifconfig.me*" OR "*api.ipify.org*" OR "*icanhazip*" OR "*8.8.8.8*" OR "*1.1.1.1*") | groupby host.name host.os.type user.name process.name process.parent.name event.action destination.ip destination.port | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line process.executable file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port destination.domain network.transport network.community_id event.code rule.name
```

**Tuning ideas:** allowlist known administrators, software deployment tools, EDR activity, backup agents, inventory systems, vulnerability scanners, patching tools, and sanctioned management workflows before alerting.

---

## T1069.003 — Permission Groups Discovery: Cloud Groups

**Tactic:** Discovery  
**Detection idea:** Cloud, SaaS, or identity-provider group and role enumeration.  
**Elastic implementation notes:** These filters use ECS-style fields commonly present in Elastic Agent, Elastic Defend, Windows, Linux, macOS, Zeek, Suricata, cloud, and SaaS data streams. Tune command-line patterns, data views, and administrative allowlists before production use.

### Query 1 — Security Onion Cloud/SaaS
**Security Onion specific:** Uses Elastic Agent or Security Onion telemetry in Security Onion 3.1.0. Requires the relevant endpoint, Zeek, Suricata, cloud, SaaS, Windows, Linux, macOS, system, or Elastic Defend data streams with ECS-compatible fields.

```kql
event.category:iam and event.action:("*ListGroups*" or "*GetGroup*" or "*ListRoles*" or "*GetRole*" or "*memberOf*" or "*groups.list*") and user.name:*
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:iam AND event.action:("*ListGroups*" OR "*GetGroup*" OR "*ListRoles*" OR "*GetRole*" OR "*memberOf*" OR "*groups.list*") AND user.name:* | groupby host.name host.os.type user.name process.name process.parent.name event.action destination.ip destination.port | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line process.executable file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port destination.domain network.transport network.community_id event.code rule.name
```
### Query 2 — Security Onion Elastic Agent CLI
**Security Onion specific:** Uses Elastic Agent or Security Onion telemetry in Security Onion 3.1.0. Requires the relevant endpoint, Zeek, Suricata, cloud, SaaS, Windows, Linux, macOS, system, or Elastic Defend data streams with ECS-compatible fields.

```kql
event.category:process and agent.type:"elastic-agent" and process.name:(aws or az or gcloud or powershell) and process.command_line:("* iam list-groups*" or "* iam list-roles*" or "* ad group list*" or "*Get-MgGroup*" or "*gcloud identity groups*")
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:process AND agent.type:"elastic-agent" AND process.name:(aws OR az OR gcloud OR powershell) AND process.command_line:("* iam list-groups*" OR "* iam list-roles*" OR "* ad group list*" OR "*Get-MgGroup*" OR "*gcloud identity groups*") | groupby host.name host.os.type user.name process.name process.parent.name event.action destination.ip destination.port | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line process.executable file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port destination.domain network.transport network.community_id event.code rule.name
```

**Tuning ideas:** allowlist known administrators, software deployment tools, EDR activity, backup agents, inventory systems, vulnerability scanners, patching tools, and sanctioned management workflows before alerting.

---

## T1120 — Peripheral Device Discovery

**Tactic:** Discovery  
**Detection idea:** Enumeration of USB, Bluetooth, camera, audio, printer, or other peripheral devices.  
**Elastic implementation notes:** These filters use ECS-style fields commonly present in Elastic Agent, Elastic Defend, Windows, Linux, macOS, Zeek, Suricata, cloud, and SaaS data streams. Tune command-line patterns, data views, and administrative allowlists before production use.

### Query 1 — Security Onion Windows Elastic Agent
**Security Onion specific:** Uses Elastic Agent or Security Onion telemetry in Security Onion 3.1.0. Requires the relevant endpoint, Zeek, Suricata, cloud, SaaS, Windows, Linux, macOS, system, or Elastic Defend data streams with ECS-compatible fields.

```kql
event.category:process and agent.type:"elastic-agent" and host.os.type:windows and process.name:("powershell.exe" or "wmic.exe" or "pnputil.exe") and process.command_line:("*Win32_USBControllerDevice*" or "*Get-PnpDevice*" or "*USB*" or "*Bluetooth*" or "*Printer*")
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:process AND agent.type:"elastic-agent" AND host.os.type:windows AND process.name:("powershell.exe" OR "wmic.exe" OR "pnputil.exe") AND process.command_line:("*Win32_USBControllerDevice*" OR "*Get-PnpDevice*" OR "*USB*" OR "*Bluetooth*" OR "*Printer*") | groupby host.name host.os.type user.name process.name process.parent.name event.action destination.ip destination.port | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line process.executable file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port destination.domain network.transport network.community_id event.code rule.name
```
### Query 2 — Security Onion Linux/macOS Elastic Agent
**Security Onion specific:** Uses Elastic Agent or Security Onion telemetry in Security Onion 3.1.0. Requires the relevant endpoint, Zeek, Suricata, cloud, SaaS, Windows, Linux, macOS, system, or Elastic Defend data streams with ECS-compatible fields.

```kql
event.category:process and agent.type:"elastic-agent" and host.os.type:(linux or macos) and process.name:(lsusb or lspci or system_profiler or ioreg or lpstat) and process.command_line:("*USB*" or "*Bluetooth*" or "*SPUSBDataType*" or "*SPBluetoothDataType*" or "*-p*")
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:process AND agent.type:"elastic-agent" AND host.os.type:(linux OR macos) AND process.name:(lsusb OR lspci OR system_profiler OR ioreg OR lpstat) AND process.command_line:("*USB*" OR "*Bluetooth*" OR "*SPUSBDataType*" OR "*SPBluetoothDataType*" OR "*-p*") | groupby host.name host.os.type user.name process.name process.parent.name event.action destination.ip destination.port | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line process.executable file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port destination.domain network.transport network.community_id event.code rule.name
```

**Tuning ideas:** allowlist known administrators, software deployment tools, EDR activity, backup agents, inventory systems, vulnerability scanners, patching tools, and sanctioned management workflows before alerting.

---

## T1652 — Device Driver Discovery

**Tactic:** Discovery  
**Detection idea:** Driver, kernel extension, or loaded module discovery across endpoints.  
**Elastic implementation notes:** These filters use ECS-style fields commonly present in Elastic Agent, Elastic Defend, Windows, Linux, macOS, Zeek, Suricata, cloud, and SaaS data streams. Tune command-line patterns, data views, and administrative allowlists before production use.

### Query 1 — Security Onion Windows Elastic Agent
**Security Onion specific:** Uses Elastic Agent or Security Onion telemetry in Security Onion 3.1.0. Requires the relevant endpoint, Zeek, Suricata, cloud, SaaS, Windows, Linux, macOS, system, or Elastic Defend data streams with ECS-compatible fields.

```kql
event.category:process and agent.type:"elastic-agent" and host.os.type:windows and process.name:("driverquery.exe" or "powershell.exe" or "sc.exe") and process.command_line:("*/v*" or "*Get-WindowsDriver*" or "*Win32_SystemDriver*" or "*type= driver*")
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:process AND agent.type:"elastic-agent" AND host.os.type:windows AND process.name:("driverquery.exe" OR "powershell.exe" OR "sc.exe") AND process.command_line:("*/v*" OR "*Get-WindowsDriver*" OR "*Win32_SystemDriver*" OR "*type= driver*") | groupby host.name host.os.type user.name process.name process.parent.name event.action destination.ip destination.port | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line process.executable file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port destination.domain network.transport network.community_id event.code rule.name
```
### Query 2 — Security Onion Linux/macOS Elastic Agent
**Security Onion specific:** Uses Elastic Agent or Security Onion telemetry in Security Onion 3.1.0. Requires the relevant endpoint, Zeek, Suricata, cloud, SaaS, Windows, Linux, macOS, system, or Elastic Defend data streams with ECS-compatible fields.

```kql
event.category:process and agent.type:"elastic-agent" and host.os.type:(linux or macos) and process.name:(lsmod or modinfo or kextstat or kmutil or system_profiler) and process.command_line:("*kext*" or "*SPKernelExtensionDataType*" or "*loaded*" or "*showloaded*")
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:process AND agent.type:"elastic-agent" AND host.os.type:(linux OR macos) AND process.name:(lsmod OR modinfo OR kextstat OR kmutil OR system_profiler) AND process.command_line:("*kext*" OR "*SPKernelExtensionDataType*" OR "*loaded*" OR "*showloaded*") | groupby host.name host.os.type user.name process.name process.parent.name event.action destination.ip destination.port | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line process.executable file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port destination.domain network.transport network.community_id event.code rule.name
```

**Tuning ideas:** allowlist known administrators, software deployment tools, EDR activity, backup agents, inventory systems, vulnerability scanners, patching tools, and sanctioned management workflows before alerting.

---

## T1619 — Cloud Storage Object Discovery

**Tactic:** Discovery  
**Detection idea:** Cloud storage bucket, blob, drive, or object listing from CLI and SaaS audit telemetry.  
**Elastic implementation notes:** These filters use ECS-style fields commonly present in Elastic Agent, Elastic Defend, Windows, Linux, macOS, Zeek, Suricata, cloud, and SaaS data streams. Tune command-line patterns, data views, and administrative allowlists before production use.

### Query 1 — Security Onion Cloud/SaaS
**Security Onion specific:** Uses Elastic Agent or Security Onion telemetry in Security Onion 3.1.0. Requires the relevant endpoint, Zeek, Suricata, cloud, SaaS, Windows, Linux, macOS, system, or Elastic Defend data streams with ECS-compatible fields.

```kql
event.dataset:("aws.cloudtrail" or "azure.auditlogs" or "google_workspace.admin" or "google_workspace.drive") and event.action:("*ListBucket*" or "*ListObjects*" or "*List Blobs*" or "*storage.objects.list*" or "*FileAccessed*")
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.dataset:("aws.cloudtrail" OR "azure.auditlogs" OR "google_workspace.admin" OR "google_workspace.drive") AND event.action:("*ListBucket*" OR "*ListObjects*" OR "*List Blobs*" OR "*storage.objects.list*" OR "*FileAccessed*") | groupby host.name host.os.type user.name process.name process.parent.name event.action destination.ip destination.port | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line process.executable file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port destination.domain network.transport network.community_id event.code rule.name
```
### Query 2 — Security Onion Elastic Agent CLI
**Security Onion specific:** Uses Elastic Agent or Security Onion telemetry in Security Onion 3.1.0. Requires the relevant endpoint, Zeek, Suricata, cloud, SaaS, Windows, Linux, macOS, system, or Elastic Defend data streams with ECS-compatible fields.

```kql
event.category:process and agent.type:"elastic-agent" and process.name:(aws or az or gcloud or rclone) and process.command_line:("* s3 ls*" or "* storage blob list*" or "* storage objects list*" or "* lsd *" or "* lsjson *")
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:process AND agent.type:"elastic-agent" AND process.name:(aws OR az OR gcloud OR rclone) AND process.command_line:("* s3 ls*" OR "* storage blob list*" OR "* storage objects list*" OR "* lsd *" OR "* lsjson *") | groupby host.name host.os.type user.name process.name process.parent.name event.action destination.ip destination.port | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line process.executable file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port destination.domain network.transport network.community_id event.code rule.name
```

**Tuning ideas:** allowlist known administrators, software deployment tools, EDR activity, backup agents, inventory systems, vulnerability scanners, patching tools, and sanctioned management workflows before alerting.

