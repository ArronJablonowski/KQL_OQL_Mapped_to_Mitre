# TA0006 — Credential Access

> Query dialect: Elastic Kibana Query Language (**Elastic KQL**) using ECS-style fields. These are hunting-grade filters intended for Kibana Discover, Timeline, and Elastic Security rules. Tune fields, data views, and allowlists to your environment.

**Coverage count:** 24 technique sections / 62 KQL queries

## Techniques in this tactic

- [T1003.001 — OS Credential Dumping: LSASS Memory](SO_TA0006_Credential_Access.md#t1003.001-os-credential-dumping-lsass-memory) — 3 queries
- [T1003.003 — OS Credential Dumping: NTDS](SO_TA0006_Credential_Access.md#t1003.003-os-credential-dumping-ntds) — 3 queries
- [T1552.001 — Credentials in Files](SO_TA0006_Credential_Access.md#t1552.001-credentials-in-files) — 4 queries
- [T1555.003 — Credentials from Web Browsers](SO_TA0006_Credential_Access.md#t1555.003-credentials-from-web-browsers) — 4 queries
- [T1110.003 — Password Spraying](SO_TA0006_Credential_Access.md#t1110.003-password-spraying) — 2 queries
- [T1528 — Steal Application Access Token](SO_TA0006_Credential_Access.md#t1528-steal-application-access-token) — 4 queries
- [T1003.002 — OS Credential Dumping: Security Account Manager](SO_TA0006_Credential_Access.md#t1003.002-os-credential-dumping-security-account-manager) — 3 queries
- [T1003.004 — OS Credential Dumping: LSA Secrets](SO_TA0006_Credential_Access.md#t1003.004-os-credential-dumping-lsa-secrets) — 2 queries
- [T1003.005 — OS Credential Dumping: Cached Domain Credentials](SO_TA0006_Credential_Access.md#t1003.005-os-credential-dumping-cached-domain-credentials) — 2 queries
- [T1558.003 — Steal or Forge Kerberos Tickets: Kerberoasting](SO_TA0006_Credential_Access.md#t1558.003-steal-or-forge-kerberos-tickets-kerberoasting) — 3 queries
- [T1558.004 — Steal or Forge Kerberos Tickets: AS-REP Roasting](SO_TA0006_Credential_Access.md#t1558.004-steal-or-forge-kerberos-tickets-as-rep-roasting) — 2 queries
- [T1110.001 — Brute Force: Password Guessing](SO_TA0006_Credential_Access.md#t1110.001-brute-force-password-guessing) — 5 queries
- [T1110.004 — Brute Force: Credential Stuffing](SO_TA0006_Credential_Access.md#t1110.004-brute-force-credential-stuffing) — 2 queries
- [T1552.006 — Unsecured Credentials: Group Policy Preferences](SO_TA0006_Credential_Access.md#t1552.006-unsecured-credentials-group-policy-preferences) — 5 queries
- [T1003.008 — OS Credential Dumping: /etc/passwd and /etc/shadow](SO_TA0006_Credential_Access.md#t1003.008-os-credential-dumping-etcpasswd-and-etcshadow) — 2 queries
- [T1552.004 — Unsecured Credentials: Private Keys](SO_TA0006_Credential_Access.md#t1552.004-unsecured-credentials-private-keys) — 2 queries
- [T1552.003 — Unsecured Credentials: Bash History](SO_TA0006_Credential_Access.md#t1552.003-unsecured-credentials-bash-history) — 1 query
- [T1555.001 — Credentials from Password Stores: Keychain](SO_TA0006_Credential_Access.md#t1555.001-credentials-from-password-stores-keychain) — 1 query
- [T1556.003 — Modify Authentication Process: Pluggable Authentication Modules](SO_TA0006_Credential_Access.md#t1556.003-modify-authentication-process-pluggable-authentication-modules) — 1 query
- [T1040 — Network Sniffing](SO_TA0006_Credential_Access.md#t1040-network-sniffing) — 3 queries
- [T1056.001 — Input Capture: Keylogging](SO_TA0006_Credential_Access.md#t1056.001-input-capture-keylogging) — 2 queries
- [T1552.005 — Unsecured Credentials: Cloud Instance Metadata API](SO_TA0006_Credential_Access.md#t1552.005-unsecured-credentials-cloud-instance-metadata-api) — 2 queries
- [T1555.005 — Credentials from Password Stores: Password Managers](SO_TA0006_Credential_Access.md#t1555.005-credentials-from-password-stores-password-managers) — 2 queries
- [T1110.002 — Brute Force: Password Cracking](SO_TA0006_Credential_Access.md#t1110.002-brute-force-password-cracking) — 2 queries

---

## T1003.001 — OS Credential Dumping: LSASS Memory

**Tactic:** Credential Access  
**Detection idea:** LSASS dumping through comsvcs, procdump, task manager, or suspicious access  
**Elastic implementation notes:** ECS field names vary by integration. Start with the KQL below, then tune for your Elastic Agent, Elastic Defend, Windows, System, Sysmon, cloud, and email data streams.

### Query 1
```kql
event.category:process and process.command_line:(*lsass* and (*comsvcs.dll* or *MiniDump* or *procdump* or *rundll32* or *nanodump* or *sekurlsa*))
```

### Query 2
```kql
event.category:file and file.name:(*lsass*.dmp or *lsass*.dump or *debug*.bin)
```

### Query 3 — Security Onion Windows Elastic Agent
**Security Onion specific:** Uses Elastic Agent telemetry in Security Onion 3.1.0 for Windows hosts. Requires Elastic Agent endpoint, system, Windows, macOS, Linux, or Elastic Defend data streams with ECS host, process, file, registry, authentication, or network fields.

```kql
event.category:process and agent.type:"elastic-agent" and host.os.type:windows and process.command_line:(*lsass* or *comsvcs.dll* or *MiniDump* or *procdump* or *nanodump* or *sekurlsa*)
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:process AND agent.type:"elastic-agent" AND host.os.type:windows AND process.command_line:(*lsass* OR *comsvcs.dll* OR *MiniDump* OR *procdump* OR *nanodump* OR *sekurlsa*) | groupby host.name host.os.type user.name process.name process.parent.name destination.ip destination.port event.action | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port network.transport network.community_id event.code rule.name
```

**Tuning ideas:** allowlist known admin scripts, software deployment tools, scanners, EDR activity, patch management, and sanctioned cloud apps before alerting.

---

## T1003.003 — OS Credential Dumping: NTDS

**Tactic:** Credential Access  
**Detection idea:** NTDS.dit extraction and volume shadow copy staging  
**Elastic implementation notes:** ECS field names vary by integration. Start with the KQL below, then tune for your Elastic Agent, Elastic Defend, Windows, System, Sysmon, cloud, and email data streams.

### Query 1
```kql
event.category:process and process.command_line:(*ntds.dit* or *vssadmin* or *wbadmin* or *ntdsutil* or *esentutl*)
```

### Query 2
```kql
event.category:file and file.name:("ntds.dit" or "SYSTEM" or "SECURITY") and file.path:(*\\\\Temp\\\\* or *\\\\Users\\\\Public\\\\* or *\\\\Windows\\\\Temp\\\\*)
```

### Query 3 — Security Onion Windows Elastic Agent
**Security Onion specific:** Uses Elastic Agent telemetry in Security Onion 3.1.0 for Windows hosts. Requires Elastic Agent endpoint, system, Windows, macOS, Linux, or Elastic Defend data streams with ECS host, process, file, registry, authentication, or network fields.

```kql
event.category:process and agent.type:"elastic-agent" and host.os.type:windows and process.command_line:(*ntds.dit* or *vssadmin\ create\ shadow* or *ntdsutil* or *ifm* or *diskshadow* or *copy*SYSTEM*)
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:process AND agent.type:"elastic-agent" AND host.os.type:windows AND process.command_line:(*ntds.dit* OR *vssadmin\ create\ shadow* OR *ntdsutil* OR *ifm* OR *diskshadow* OR *copy*SYSTEM*) | groupby host.name host.os.type user.name process.name process.parent.name destination.ip destination.port event.action | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line process.executable file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port destination.domain network.transport event.code rule.name
```

**Tuning ideas:** allowlist known admin scripts, software deployment tools, scanners, EDR activity, patch management, and sanctioned cloud apps before alerting.

---

## T1552.001 — Credentials in Files

**Tactic:** Credential Access  
**Detection idea:** Searches for secrets, passwords, keys, and config files  
**Elastic implementation notes:** ECS field names vary by integration. Start with the KQL below, then tune for your Elastic Agent, Elastic Defend, Windows, System, Sysmon, cloud, and email data streams.

### Query 1
```kql
event.category:process and process.name:("findstr.exe" or "cmd.exe" or "powershell.exe" or "pwsh.exe") and process.command_line:(*password* or *passwd* or *pwd* or *credential* or *secret* or *token* or *apikey* or *connectionstring*)
```

### Query 2
```kql
event.category:file and file.extension:(kdbx or pfx or p12 or pem or key or config or ini or yml or yaml or json) and file.path:(*\\\\Users\\\\* or *\\\\ProgramData\\\\*)
```

### Query 3 — Security Onion Linux Elastic Agent
**Security Onion specific:** Uses Elastic Agent telemetry in Security Onion 3.1.0 for Linux hosts. Requires Elastic Agent endpoint, system, Windows, macOS, Linux, or Elastic Defend data streams with ECS host, process, file, registry, authentication, or network fields.

```kql
event.category:process and agent.type:"elastic-agent" and host.os.type:linux and process.name:(grep or find or rg or awk) and process.command_line:(*password* or *passwd* or *secret* or *token* or *aws_access_key* or *private_key*)
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:process AND agent.type:"elastic-agent" AND host.os.type:linux AND process.name:(grep OR find OR rg OR awk) AND process.command_line:(*password* OR *passwd* OR *secret* OR *token* OR *aws_access_key* OR *private_key*) | groupby host.name host.os.type user.name process.name process.parent.name destination.ip destination.port event.action | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line process.executable file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port destination.domain network.transport event.code rule.name
```

### Query 4 — Security Onion macOS Elastic Agent
**Security Onion specific:** Uses Elastic Agent telemetry in Security Onion 3.1.0 for macOS hosts. Requires Elastic Agent endpoint, system, Windows, macOS, Linux, or Elastic Defend data streams with ECS host, process, file, registry, authentication, or network fields.

```kql
event.category:process and agent.type:"elastic-agent" and host.os.type:macos and process.name:(grep or find or mdfind) and process.command_line:(*password* or *secret* or *token* or *.pem* or *.key* or *id_rsa*)
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:process AND agent.type:"elastic-agent" AND host.os.type:macos AND process.name:(grep OR find OR mdfind) AND process.command_line:(*password* OR *secret* OR *token* OR *.pem* OR *.key* OR *id_rsa*) | groupby host.name host.os.type user.name process.name process.parent.name destination.ip destination.port event.action | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line process.executable file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port destination.domain network.transport event.code rule.name
```

**Tuning ideas:** allowlist known admin scripts, software deployment tools, scanners, EDR activity, patch management, and sanctioned cloud apps before alerting.

---

## T1555.003 — Credentials from Web Browsers

**Tactic:** Credential Access  
**Detection idea:** Access to browser credential stores  
**Elastic implementation notes:** ECS field names vary by integration. Start with the KQL below, then tune for your Elastic Agent, Elastic Defend, Windows, System, Sysmon, cloud, and email data streams.

### Query 1
```kql
event.category:file and file.path:(*\\\\AppData\\\\Local\\\\Google\\\\Chrome\\\\User\ Data\\\\*\\\\Login\ Data* or *\\\\AppData\\\\Local\\\\Microsoft\\\\Edge\\\\User\ Data\\\\*\\\\Login\ Data* or *\\\\AppData\\\\Roaming\\\\Mozilla\\\\Firefox\\\\Profiles\\\\*\\\\logins.json*)
```

### Query 2
```kql
event.category:process and process.command_line:(*Login\ Data* or *Cookies* or *Local\ State* or *logins.json* or *key4.db*) and not process.name:("chrome.exe" or "msedge.exe" or "firefox.exe")
```

### Query 3 — Security Onion Windows Elastic Agent
**Security Onion specific:** Uses Elastic Agent telemetry in Security Onion 3.1.0 for Windows hosts. Requires Elastic Agent endpoint, system, Windows, macOS, Linux, or Elastic Defend data streams with ECS host, process, file, registry, authentication, or network fields.

```kql
event.category:file and agent.type:"elastic-agent" and host.os.type:windows and file.path:(*\\Chrome\\User\ Data\\* or *\\Edge\\User\ Data\\* or *\\Firefox\\Profiles\\*) and file.name:("Login Data" or "logins.json" or "key4.db" or "Cookies") and event.action:(access or open or read or copy)
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:file AND agent.type:"elastic-agent" AND host.os.type:windows AND file.path:(*\\Chrome\\User\ Data\\* OR *\\Edge\\User\ Data\\* OR *\\Firefox\\Profiles\\*) AND file.name:("Login Data" OR "logins.json" OR "key4.db" OR "Cookies") AND event.action:(access OR open OR read OR copy) | groupby host.name host.os.type user.name process.name process.parent.name destination.ip destination.port event.action | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line process.executable file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port destination.domain network.transport event.code rule.name
```

### Query 4 — Security Onion macOS Elastic Agent
**Security Onion specific:** Uses Elastic Agent telemetry in Security Onion 3.1.0 for macOS hosts. Requires Elastic Agent endpoint, system, Windows, macOS, Linux, or Elastic Defend data streams with ECS host, process, file, registry, authentication, or network fields.

```kql
event.category:file and agent.type:"elastic-agent" and host.os.type:macos and file.path:(/Users/*/Library/Application\ Support/Google/Chrome/* or /Users/*/Library/Application\ Support/Firefox/Profiles/* or /Users/*/Library/Application\ Support/Microsoft\ Edge/*) and file.name:("Login Data" or "logins.json" or "key4.db" or "Cookies") and event.action:(access or open or read or copy)
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:file AND agent.type:"elastic-agent" AND host.os.type:macos AND file.path:(\/Users\/*\/Library\/Application\ Support\/Google\/Chrome\/* OR \/Users\/*\/Library\/Application\ Support\/Firefox\/Profiles\/* OR \/Users\/*\/Library\/Application\ Support\/Microsoft\ Edge\/*) AND file.name:("Login Data" OR "logins.json" OR "key4.db" OR "Cookies") AND event.action:(access OR open OR read OR copy) | groupby host.name host.os.type user.name process.name process.parent.name destination.ip destination.port event.action | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line process.executable file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port destination.domain network.transport event.code rule.name
```

**Tuning ideas:** allowlist known admin scripts, software deployment tools, scanners, EDR activity, patch management, and sanctioned cloud apps before alerting.

---

## T1110.003 — Password Spraying

**Tactic:** Credential Access  
**Detection idea:** Multiple failed logons across many users from one source  
**Elastic implementation notes:** ECS field names vary by integration. Start with the KQL below, then tune for your Elastic Agent, Elastic Defend, Windows, System, Sysmon, cloud, and email data streams.

### Query 1
```kql
event.category:authentication and event.outcome:failure and source.ip:* and user.name:* and event.action:(logon-failed or user-login-failed or authentication_failed)
```

### Query 2
```kql
event.dataset:("windows.security" or "o365.audit" or "azure.signinlogs") and event.outcome:failure and event.code:(4625 or 50053 or 50126 or 50055)
```

**Tuning ideas:** allowlist known admin scripts, software deployment tools, scanners, EDR activity, patch management, and sanctioned cloud apps before alerting.

---

## T1528 — Steal Application Access Token

**Tactic:** Credential Access  
**Detection idea:** OAuth consent, app credential, or token theft indicators  
**Elastic implementation notes:** ECS field names vary by integration. Start with the KQL below, then tune for your Elastic Agent, Elastic Defend, Windows, System, Sysmon, cloud, and email data streams.

### Query 1
```kql
event.category:iam and event.action:(app-consent or service-principal-credential-add or oauth-grant or token-issue) and user.name:*
```

### Query 2
```kql
event.dataset:("azure.auditlogs" or "o365.audit") and event.action:(*Consent* or *Add\ service\ principal\ credentials* or *Add\ delegated\ permission\ grant* or *Update\ application*)
```

### Query 3 — Security Onion Linux Elastic Agent
**Security Onion specific:** Uses Elastic Agent telemetry in Security Onion 3.1.0 for Linux hosts. Requires Elastic Agent endpoint, system, Windows, macOS, Linux, or Elastic Defend data streams with ECS host, process, file, registry, authentication, or network fields.

```kql
event.category:file and agent.type:"elastic-agent" and host.os.type:linux and file.path:(/home/*/.aws/credentials or "/root/.aws/credentials" or /home/*/.config/gcloud/* or /home/*/.azure/* or /home/*/.docker/config.json) and event.action:(access or open or read or copy)
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:file AND agent.type:"elastic-agent" AND host.os.type:linux AND file.path:(\/home\/*\/.aws\/credentials OR "/root/.aws/credentials" OR \/home\/*\/.config\/gcloud\/* OR \/home\/*\/.azure\/* OR \/home\/*\/.docker\/config.json) AND event.action:(access OR open OR read OR copy) | groupby host.name host.os.type user.name process.name process.parent.name destination.ip destination.port event.action | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line process.executable file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port destination.domain network.transport event.code rule.name
```

### Query 4 — Security Onion macOS Elastic Agent
**Security Onion specific:** Uses Elastic Agent telemetry in Security Onion 3.1.0 for macOS hosts. Requires Elastic Agent endpoint, system, Windows, macOS, Linux, or Elastic Defend data streams with ECS host, process, file, registry, authentication, or network fields.

```kql
event.category:file and agent.type:"elastic-agent" and host.os.type:macos and file.path:(/Users/*/.aws/credentials or /Users/*/.config/gcloud/* or /Users/*/.azure/* or /Users/*/.docker/config.json or /Users/*/.kube/config) and event.action:(access or open or read or copy)
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:file AND agent.type:"elastic-agent" AND host.os.type:macos AND file.path:(\/Users\/*\/.aws\/credentials OR \/Users\/*\/.config\/gcloud\/* OR \/Users\/*\/.azure\/* OR \/Users\/*\/.docker\/config.json OR \/Users\/*\/.kube\/config) AND event.action:(access OR open OR read OR copy) | groupby host.name host.os.type user.name process.name process.parent.name destination.ip destination.port event.action | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line process.executable file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port destination.domain network.transport event.code rule.name
```

**Tuning ideas:** allowlist known admin scripts, software deployment tools, scanners, EDR activity, patch management, and sanctioned cloud apps before alerting.

---

## T1003.002 — OS Credential Dumping: Security Account Manager

**Tactic:** Credential Access  
**Detection idea:** SAM, SYSTEM, or SECURITY hive export activity  
**Elastic implementation notes:** ECS field names vary by integration. Start with the KQL below, then tune for your Elastic Agent, Elastic Defend, Windows, System, Sysmon, cloud, and email data streams.

### Query 1
```kql
event.category:process and process.name:("reg.exe" or "powershell.exe" or "pwsh.exe") and process.command_line:(*save\ hklm\\sam* or *save\ hklm\\system* or *save\ hklm\\security* or *reg\ save*)
```

### Query 2
```kql
event.category:file and file.name:("SAM" or "SYSTEM" or "SECURITY") and file.path:(*\\\\Temp\\\\* or *\\\\Users\\\\Public\\\\* or *\\\\Windows\\\\Temp\\\\*)
```

### Query 3 — Security Onion Windows Elastic Agent
**Security Onion specific:** Uses Elastic Agent telemetry in Security Onion 3.1.0 for Windows hosts. Requires Elastic Agent endpoint, system, Windows, macOS, Linux, or Elastic Defend data streams with ECS host, process, file, registry, authentication, or network fields.

```kql
event.category:process and agent.type:"elastic-agent" and host.os.type:windows and process.name:("reg.exe" or "powershell.exe" or "cmd.exe") and process.command_line:(*\ save\ HKLM\\SAM* or *\ save\ HKLM\\SYSTEM* or *\ save\ HKLM\\SECURITY* or *\\config\\SAM* or *\\config\\SYSTEM*)
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:process AND agent.type:"elastic-agent" AND host.os.type:windows AND process.name:("reg.exe" OR "powershell.exe" OR "cmd.exe") AND process.command_line:(*\ save\ HKLM\\SAM* OR *\ save\ HKLM\\SYSTEM* OR *\ save\ HKLM\\SECURITY* OR *\\config\\SAM* OR *\\config\\SYSTEM*) | groupby host.name host.os.type user.name process.name process.parent.name destination.ip destination.port event.action | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line process.executable file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port destination.domain network.transport event.code rule.name
```

**Tuning ideas:** allowlist known admin scripts, software deployment tools, scanners, EDR activity, patch management, and sanctioned cloud apps before alerting.

---

## T1003.004 — OS Credential Dumping: LSA Secrets

**Tactic:** Credential Access  
**Detection idea:** LSA secret dump commands or SECURITY hive access  
**Elastic implementation notes:** ECS field names vary by integration. Start with the KQL below, then tune for your Elastic Agent, Elastic Defend, Windows, System, Sysmon, cloud, and email data streams.

### Query 1
```kql
event.category:process and process.command_line:(*lsadump\:\:secrets* or *secretsdump* or *cachedump* or *mimikatz*)
```

### Query 2
```kql
event.category:process and process.name:("reg.exe" or "powershell.exe" or "pwsh.exe") and process.command_line:(*HKLM\\SECURITY* or *Policy\\Secrets* or *reg\ save\ hklm\\security*)
```

**Tuning ideas:** allowlist known admin scripts, software deployment tools, scanners, EDR activity, patch management, and sanctioned cloud apps before alerting.

---

## T1003.005 — OS Credential Dumping: Cached Domain Credentials

**Tactic:** Credential Access  
**Detection idea:** Cached credential dump tooling or registry access  
**Elastic implementation notes:** ECS field names vary by integration. Start with the KQL below, then tune for your Elastic Agent, Elastic Defend, Windows, System, Sysmon, cloud, and email data streams.

### Query 1
```kql
event.category:process and process.command_line:(*lsadump\:\:cache* or *cachedump* or *MSCache* or *DCC2* or *secretsdump*)
```

### Query 2
```kql
event.category:registry and registry.path:(*\\\\Security\\\\Cache\\\\* or *\\\\SECURITY\\\\Cache\\\\*) and event.action:(access or query or modification)
```

**Tuning ideas:** allowlist known admin scripts, software deployment tools, scanners, EDR activity, patch management, and sanctioned cloud apps before alerting.

---

## T1558.003 — Steal or Forge Kerberos Tickets: Kerberoasting

**Tactic:** Credential Access  
**Detection idea:** Kerberoasting tool use or service ticket requests  
**Elastic implementation notes:** ECS field names vary by integration. Start with the KQL below, then tune for your Elastic Agent, Elastic Defend, Windows, System, Sysmon, cloud, and email data streams.

### Query 1
```kql
event.category:process and process.command_line:(*kerberoast* or *GetUserSPNs* or *Invoke-Kerberoast* or *Rubeus*\ kerberoast* or */service\:*)
```

### Query 2
```kql
event.dataset:"windows.security" and event.code:4769 and winlog.event_data.TicketEncryptionType:("0x17" or "0x18")
```

### Query 3 — Security Onion Windows Elastic Agent
**Security Onion specific:** Uses Elastic Agent telemetry in Security Onion 3.1.0 for Windows hosts. Requires Elastic Agent endpoint, system, Windows, macOS, Linux, or Elastic Defend data streams with ECS host, process, file, registry, authentication, or network fields.

```kql
event.category:(process or authentication) and agent.type:"elastic-agent" and host.os.type:windows and (process.command_line:(*Invoke-Kerberoast* or *Rubeus*\ kerberoast* or *GetUserSPNs.py*) or (event.code:4769 and winlog.event_data.TicketEncryptionType:("0x17" or "0x18")))
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:(process OR authentication) AND agent.type:"elastic-agent" AND host.os.type:windows AND (process.command_line:(*Invoke\-Kerberoast* OR *Rubeus*\ kerberoast* OR *GetUserSPNs.py*) OR (event.code:4769 AND winlog.event_data.TicketEncryptionType:("0x17" OR "0x18"))) | groupby host.name host.os.type user.name process.name process.parent.name destination.ip destination.port event.action | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line process.executable file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port destination.domain network.transport event.code rule.name
```

**Tuning ideas:** allowlist known admin scripts, software deployment tools, scanners, EDR activity, patch management, and sanctioned cloud apps before alerting.

---

## T1558.004 — Steal or Forge Kerberos Tickets: AS-REP Roasting

**Tactic:** Credential Access  
**Detection idea:** AS-REP roasting tool use or pre-authentication-not-required requests  
**Elastic implementation notes:** ECS field names vary by integration. Start with the KQL below, then tune for your Elastic Agent, Elastic Defend, Windows, System, Sysmon, cloud, and email data streams.

### Query 1
```kql
event.category:process and process.command_line:(*asreproast* or *GetNPUsers* or *Invoke-ASREPRoast* or *Rubeus*\ asreproast*)
```

### Query 2
```kql
event.dataset:"windows.security" and event.code:4768 and winlog.event_data.PreAuthType:"0"
```

**Tuning ideas:** allowlist known admin scripts, software deployment tools, scanners, EDR activity, patch management, and sanctioned cloud apps before alerting.

---

## T1110.001 — Brute Force: Password Guessing

**Tactic:** Credential Access  
**Detection idea:** Repeated authentication failures from a single source or account  
**Elastic implementation notes:** ECS field names vary by integration. Start with the KQL below, then tune for your Elastic Agent, Elastic Defend, Windows, System, Sysmon, cloud, and email data streams.

### Query 1
```kql
event.category:authentication and event.outcome:failure and source.ip:* and user.name:* and event.action:(logon-failed or user-login-failed or authentication_failed)
```

### Query 2
```kql
event.dataset:("windows.security" or "azure.signinlogs" or "o365.audit") and event.outcome:failure and event.code:(4625 or 50053 or 50126)
```

**Tuning ideas:** allowlist known admin scripts, software deployment tools, scanners, EDR activity, patch management, and sanctioned cloud apps before alerting.

---

### Query 3 — Security Onion
**Security Onion specific:** Uses Security Onion Suricata alert data for brute force signatures.

```kql
event.module:"Suricata" and event.dataset:"alert" and rule.name:(*Brute\ Force* or *BRUTEFORCE* or *SSH\ Login\ Attempt* or *FTP\ Login\ Attempt* or *RDP\ Brute*) and source.ip:* and destination.ip:*
```

**Security Onion Hunt dashboard (OQL):** Uses Security Onion 3.1 Hunt syntax. The filter uses Lucene/OQL boolean operators and adds Hunt-friendly grouping, sorting, and event-table columns.

```oql
event.module:"Suricata" AND event.dataset:"alert" AND rule.name:(*Brute\ Force* OR *BRUTEFORCE* OR *SSH\ Login\ Attempt* OR *FTP\ Login\ Attempt* OR *RDP\ Brute*) AND source.ip:* AND destination.ip:* | groupby event.dataset source.ip destination.ip destination.port rule.name | sortby @timestamp | table event.module event.dataset source.ip source.port destination.ip destination.port network.transport network.community_id log.id.uid rule.name dns.question.name url.domain tls.server.name http.request.method file.name file.path host.name user.name event.code event.action
```

### Query 4 — Security Onion
**Security Onion specific:** Uses Security Onion Zeek connection metadata for remote login service guessing candidates.

```kql
event.dataset:conn and destination.port:(21 or 22 or 23 or 3389) and source.ip:* and destination.ip:*
```

**Security Onion Hunt dashboard (OQL):** Uses Security Onion 3.1 Hunt syntax. The filter uses Lucene/OQL boolean operators and adds Hunt-friendly grouping, sorting, and event-table columns.

```oql
event.dataset:conn AND destination.port:(21 OR 22 OR 23 OR 3389) AND source.ip:* AND destination.ip:* | groupby event.dataset source.ip destination.ip destination.port rule.name | sortby @timestamp | table event.module event.dataset source.ip source.port destination.ip destination.port network.transport network.community_id log.id.uid rule.name dns.question.name url.domain tls.server.name http.request.method file.name file.path host.name user.name event.code event.action
```
### Query 5 — Security Onion Windows Elastic Agent
**Security Onion specific:** Uses Elastic Agent telemetry in Security Onion 3.1.0 for Windows hosts. Requires Elastic Agent endpoint, system, Windows, macOS, Linux, or Elastic Defend data streams with ECS host, process, file, registry, authentication, or network fields.

```kql
event.category:authentication and agent.type:"elastic-agent" and host.os.type:windows and event.outcome:failure and event.code:(4625 or 4771 or 4776) and user.name:* and source.ip:*
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:authentication AND agent.type:"elastic-agent" AND host.os.type:windows AND event.outcome:failure AND event.code:(4625 OR 4771 OR 4776) AND user.name:* AND source.ip:* | groupby host.name host.os.type user.name process.name process.parent.name destination.ip destination.port event.action | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port network.transport network.community_id event.code rule.name
```

## T1110.004 — Brute Force: Credential Stuffing

**Tactic:** Credential Access  
**Detection idea:** Cloud or SaaS authentication failures across many users from one source  
**Elastic implementation notes:** ECS field names vary by integration. Start with the KQL below, then tune for your Elastic Agent, Elastic Defend, Windows, System, Sysmon, cloud, and email data streams.

### Query 1
```kql
event.dataset:("azure.signinlogs" or "o365.audit" or "okta.system" or "google_workspace.login") and event.outcome:failure and source.ip:* and user.name:*
```

### Query 2
```kql
event.category:authentication and event.outcome:failure and source.ip:* and user.email:* and user_agent.original:*
```

**Tuning ideas:** allowlist known admin scripts, software deployment tools, scanners, EDR activity, patch management, and sanctioned cloud apps before alerting.

---

## T1552.006 — Unsecured Credentials: Group Policy Preferences

**Tactic:** Credential Access  
**Detection idea:** Access or discovery of Group Policy Preference credential artifacts  
**Elastic implementation notes:** ECS field names vary by integration. Start with the KQL below, then tune for your Elastic Agent, Elastic Defend, Windows, System, Sysmon, cloud, and email data streams.

### Query 1
```kql
event.category:process and process.command_line:(*Groups.xml* or *cpassword* or *SYSVOL* or *Get-GPPPassword*)
```

### Query 2
```kql
event.category:file and file.name:("Groups.xml" or "Services.xml" or "Scheduledtasks.xml" or "DataSources.xml") and file.path:*\\\\SYSVOL\\\\*
```

**Tuning ideas:** allowlist known admin scripts, software deployment tools, scanners, EDR activity, patch management, and sanctioned cloud apps before alerting.

---

### Query 3 — Security Onion
**Security Onion specific:** Uses Security Onion Zeek SMB file metadata to hunt access to Group Policy Preference credential artifacts.

```kql
event.dataset:(smb_files or files) and file.name:("Groups.xml" or "Services.xml" or "Scheduledtasks.xml" or "DataSources.xml") and file.path:*SYSVOL*
```

**Security Onion Hunt dashboard (OQL):** Uses Security Onion 3.1 Hunt syntax. The filter uses Lucene/OQL boolean operators and adds Hunt-friendly grouping, sorting, and event-table columns.

```oql
event.dataset:(smb_files OR files) AND file.name:("Groups.xml" OR "Services.xml" OR "Scheduledtasks.xml" OR "DataSources.xml") AND file.path:*SYSVOL* | groupby event.dataset source.ip destination.ip destination.port rule.name | sortby @timestamp | table event.module event.dataset source.ip source.port destination.ip destination.port network.transport network.community_id log.id.uid rule.name dns.question.name url.domain tls.server.name http.request.method file.name file.path host.name user.name event.code event.action
```

### Query 4 — Security Onion
**Security Onion specific:** Uses Security Onion Zeek connection metadata for SYSVOL/SMB access context.

```kql
event.dataset:conn and destination.port:445 and source.ip:* and destination.ip:*
```

**Security Onion Hunt dashboard (OQL):** Uses Security Onion 3.1 Hunt syntax. The filter uses Lucene/OQL boolean operators and adds Hunt-friendly grouping, sorting, and event-table columns.

```oql
event.dataset:conn AND destination.port:445 AND source.ip:* AND destination.ip:* | groupby event.dataset source.ip destination.ip destination.port rule.name | sortby @timestamp | table event.module event.dataset source.ip source.port destination.ip destination.port network.transport network.community_id log.id.uid rule.name dns.question.name url.domain tls.server.name http.request.method file.name file.path host.name user.name event.code event.action
```
### Query 5 — Security Onion Windows Elastic Agent
**Security Onion specific:** Uses Elastic Agent telemetry in Security Onion 3.1.0 for Windows hosts. Requires Elastic Agent endpoint, system, Windows, macOS, Linux, or Elastic Defend data streams with ECS host, process, file, registry, authentication, or network fields.

```kql
event.category:file and agent.type:"elastic-agent" and host.os.type:windows and file.name:("Groups.xml" or "Services.xml" or "Scheduledtasks.xml" or "DataSources.xml") and file.path:*SYSVOL*
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:file AND agent.type:"elastic-agent" AND host.os.type:windows AND file.name:("Groups.xml" OR "Services.xml" OR "Scheduledtasks.xml" OR "DataSources.xml") AND file.path:*SYSVOL* | groupby host.name host.os.type user.name process.name process.parent.name destination.ip destination.port event.action | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line process.executable file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port destination.domain network.transport event.code rule.name
```

## T1003.008 — OS Credential Dumping: /etc/passwd and /etc/shadow

**Tactic:** Credential Access  
**Detection idea:** Access, copy, or modification of Linux/macOS local credential stores from Elastic Agent file telemetry  
**Elastic implementation notes:** Linux/macOS host telemetry requires Elastic Agent with endpoint, system, or Elastic Defend integrations. Field availability varies by policy and event collection settings.

### Query 1 — Security Onion Linux/macOS Elastic Agent
**Security Onion specific:** Uses Elastic Agent telemetry in Security Onion 3.1.0 for Linux/macOS hosts. Requires Elastic Agent endpoint, system, or Elastic Defend data streams with ECS host, process, file, or network fields.

```kql
event.category:file and agent.type:"elastic-agent" and host.os.type:(linux or macos) and file.path:("/etc/shadow" or "/etc/passwd" or "/etc/master.passwd" or "/private/etc/master.passwd") and event.action:(access or open or read or creation or modification)
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:file AND agent.type:"elastic-agent" AND host.os.type:(linux OR macos) AND file.path:("/etc/shadow" OR "/etc/passwd" OR "/etc/master.passwd" OR "/private/etc/master.passwd") AND event.action:(access OR open OR read OR creation OR modification) | groupby host.name host.os.type user.name process.name source.ip destination.ip destination.port | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line file.path file.name file.extension source.ip source.port destination.ip destination.port network.transport network.community_id rule.name
```


### Query 2 — Security Onion Linux Elastic Agent
**Security Onion specific:** Uses Elastic Agent telemetry in Security Onion 3.1.0 for Linux hosts. Requires Elastic Agent endpoint, system, Windows, macOS, Linux, or Elastic Defend data streams with ECS host, process, file, registry, authentication, or network fields.

```kql
event.category:(process or file) and agent.type:"elastic-agent" and host.os.type:linux and (file.path:("/etc/shadow" or "/etc/passwd") or process.command_line:(*/etc/shadow* or */etc/passwd*))
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:(process OR file) AND agent.type:"elastic-agent" AND host.os.type:linux AND (file.path:("/etc/shadow" OR "/etc/passwd") OR process.command_line:(*\/etc\/shadow* OR *\/etc\/passwd*)) | groupby host.name host.os.type user.name process.name process.parent.name destination.ip destination.port event.action | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line process.executable file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port destination.domain network.transport event.code rule.name
```

**Tuning ideas:** allowlist approved admin scripts, package managers, MDM activity, backup tools, deployment systems, developer workflows, and sanctioned remote administration.

---

## T1552.004 — Unsecured Credentials: Private Keys

**Tactic:** Credential Access  
**Detection idea:** Access to SSH private keys, PEM files, or local key material on Linux/macOS hosts  
**Elastic implementation notes:** Linux/macOS host telemetry requires Elastic Agent with endpoint, system, or Elastic Defend integrations. Field availability varies by policy and event collection settings.

### Query 1 — Security Onion Linux/macOS Elastic Agent
**Security Onion specific:** Uses Elastic Agent telemetry in Security Onion 3.1.0 for Linux/macOS hosts. Requires Elastic Agent endpoint, system, or Elastic Defend data streams with ECS host, process, file, or network fields.

```kql
event.category:file and agent.type:"elastic-agent" and host.os.type:(linux or macos) and file.path:(/home/*/.ssh/* or /Users/*/.ssh/* or /root/.ssh/* or /etc/ssh/*) and file.name:("id_rsa" or "id_dsa" or "id_ecdsa" or "id_ed25519" or *.pem or *.key) and event.action:(access or open or read or creation or modification)
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:file AND agent.type:"elastic-agent" AND host.os.type:(linux OR macos) AND file.path:(\/home\/*\/.ssh\/* OR \/Users\/*\/.ssh\/* OR \/root\/.ssh\/* OR \/etc\/ssh\/*) AND file.name:("id_rsa" OR "id_dsa" OR "id_ecdsa" OR "id_ed25519" OR *.pem OR *.key) AND event.action:(access OR open OR read OR creation OR modification) | groupby host.name host.os.type user.name process.name source.ip destination.ip destination.port | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line file.path file.name file.extension source.ip source.port destination.ip destination.port network.transport network.community_id rule.name
```


### Query 2 — Security Onion macOS Elastic Agent
**Security Onion specific:** Uses Elastic Agent telemetry in Security Onion 3.1.0 for macOS hosts. Requires Elastic Agent endpoint, system, Windows, macOS, Linux, or Elastic Defend data streams with ECS host, process, file, registry, authentication, or network fields.

```kql
event.category:file and agent.type:"elastic-agent" and host.os.type:macos and file.path:(/Users/*/.ssh/* or /Users/*/Library/Application\ Support/* or /private/etc/ssh/*) and file.name:("id_rsa" or "id_ed25519" or *.pem or *.key) and event.action:(access or open or read or copy)
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:file AND agent.type:"elastic-agent" AND host.os.type:macos AND file.path:(\/Users\/*\/.ssh\/* OR \/Users\/*\/Library\/Application\ Support\/* OR \/private\/etc\/ssh\/*) AND file.name:("id_rsa" OR "id_ed25519" OR *.pem OR *.key) AND event.action:(access OR open OR read OR copy) | groupby host.name host.os.type user.name process.name process.parent.name destination.ip destination.port event.action | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port network.transport network.community_id event.code rule.name
```

**Tuning ideas:** allowlist approved admin scripts, package managers, MDM activity, backup tools, deployment systems, developer workflows, and sanctioned remote administration.

---

## T1552.003 — Unsecured Credentials: Bash History

**Tactic:** Credential Access  
**Detection idea:** Linux Elastic Agent access to shell history files that may contain secrets  
**Elastic implementation notes:** Host telemetry requires Elastic Agent with endpoint, system, Windows, macOS, Linux, or Elastic Defend integrations. Field availability varies by agent policy and event collection settings.

### Query 1 — Security Onion Linux Elastic Agent
**Security Onion specific:** Uses Elastic Agent telemetry in Security Onion 3.1.0 for Linux hosts. Requires Elastic Agent endpoint, system, Windows, macOS, Linux, or Elastic Defend data streams with ECS host, process, file, registry, authentication, or network fields.

```kql
event.category:file and agent.type:"elastic-agent" and host.os.type:linux and file.name:(".bash_history" or ".zsh_history" or ".mysql_history" or ".psql_history" or ".python_history") and event.action:(access or open or read or copy)
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:file AND agent.type:"elastic-agent" AND host.os.type:linux AND file.name:(".bash_history" OR ".zsh_history" OR ".mysql_history" OR ".psql_history" OR ".python_history") AND event.action:(access OR open OR read OR copy) | groupby host.name host.os.type user.name process.name process.parent.name destination.ip destination.port event.action | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port network.transport network.community_id event.code rule.name
```


**Tuning ideas:** allowlist approved admin scripts, package managers, MDM/GPO activity, backup tools, EDR activity, deployment systems, developer workflows, and sanctioned remote administration.

---

## T1555.001 — Credentials from Password Stores: Keychain

**Tactic:** Credential Access  
**Detection idea:** macOS Elastic Agent keychain enumeration, export, or credential access via security utility  
**Elastic implementation notes:** Host telemetry requires Elastic Agent with endpoint, system, Windows, macOS, Linux, or Elastic Defend integrations. Field availability varies by agent policy and event collection settings.

### Query 1 — Security Onion macOS Elastic Agent
**Security Onion specific:** Uses Elastic Agent telemetry in Security Onion 3.1.0 for macOS hosts. Requires Elastic Agent endpoint, system, Windows, macOS, Linux, or Elastic Defend data streams with ECS host, process, file, registry, authentication, or network fields.

```kql
event.category:process and agent.type:"elastic-agent" and host.os.type:macos and process.name:security and process.command_line:(*find-generic-password* or *find-internet-password* or *dump-keychain* or *export* or *login.keychain*)
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:process AND agent.type:"elastic-agent" AND host.os.type:macos AND process.name:security AND process.command_line:(*find\-generic\-password* OR *find\-internet\-password* OR *dump\-keychain* OR *export* OR *login.keychain*) | groupby host.name host.os.type user.name process.name process.parent.name destination.ip destination.port event.action | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port network.transport network.community_id event.code rule.name
```


**Tuning ideas:** allowlist approved admin scripts, package managers, MDM/GPO activity, backup tools, EDR activity, deployment systems, developer workflows, and sanctioned remote administration.

---

## T1556.003 — Modify Authentication Process: Pluggable Authentication Modules

**Tactic:** Credential Access / Persistence  
**Detection idea:** Linux Elastic Agent PAM configuration modification  
**Elastic implementation notes:** Host telemetry requires Elastic Agent with endpoint, system, Windows, macOS, Linux, or Elastic Defend integrations. Field availability varies by agent policy and event collection settings.

### Query 1 — Security Onion Linux Elastic Agent
**Security Onion specific:** Uses Elastic Agent telemetry in Security Onion 3.1.0 for Linux hosts. Requires Elastic Agent endpoint, system, Windows, macOS, Linux, or Elastic Defend data streams with ECS host, process, file, registry, authentication, or network fields.

```kql
event.category:file and agent.type:"elastic-agent" and host.os.type:linux and event.action:(creation or modification) and file.path:(/etc/pam.d/* or /lib/security/* or /usr/lib/security/*)
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:file AND agent.type:"elastic-agent" AND host.os.type:linux AND event.action:(creation OR modification) AND file.path:(\/etc\/pam.d\/* OR \/lib\/security\/* OR \/usr\/lib\/security\/*) | groupby host.name host.os.type user.name process.name process.parent.name destination.ip destination.port event.action | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line process.executable file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port destination.domain network.transport event.code rule.name
```


**Tuning ideas:** allowlist approved admin scripts, package managers, MDM/GPO activity, backup tools, EDR activity, deployment systems, developer workflows, and sanctioned remote administration.

---

---

## T1040 — Network Sniffing

**Tactic:** Credential Access  
**Detection idea:** Packet capture utilities, promiscuous capture workflows, and capture-file creation that may expose credentials in transit.  
**Elastic implementation notes:** These filters use ECS-style fields commonly present in Elastic Agent, Elastic Defend, Windows, Linux, macOS, Zeek, and Suricata data streams. Tune command-line patterns and administrative allowlists before production use.

### Query 1 — Security Onion Linux Elastic Agent
**Security Onion specific:** Uses Elastic Agent or Security Onion network telemetry in Security Onion 3.1.0. Requires the relevant endpoint, Zeek, Suricata, Windows, Linux, macOS, system, or Elastic Defend data streams with ECS-compatible fields.

```kql
event.category:process and agent.type:"elastic-agent" and host.os.type:linux and process.name:(tcpdump or tshark or dumpcap or wireshark or ettercap) and process.command_line:(*-i* or *-w* or *promisc* or *port\ 21* or *port\ 389* or *port\ 445*)
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:process AND agent.type:"elastic-agent" AND host.os.type:linux AND process.name:(tcpdump OR tshark OR dumpcap OR wireshark OR ettercap) AND process.command_line:(*\-i* OR *\-w* OR *promisc* OR *port\ 21* OR *port\ 389* OR *port\ 445*) | groupby host.name host.os.type user.name process.name process.parent.name event.action destination.ip destination.port | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line process.executable file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port destination.domain network.transport network.community_id event.code rule.name
```
### Query 2 — Security Onion macOS Elastic Agent
**Security Onion specific:** Uses Elastic Agent or Security Onion network telemetry in Security Onion 3.1.0. Requires the relevant endpoint, Zeek, Suricata, Windows, Linux, macOS, system, or Elastic Defend data streams with ECS-compatible fields.

```kql
event.category:process and agent.type:"elastic-agent" and host.os.type:macos and process.name:(tcpdump or tshark or dumpcap or Wireshark) and process.command_line:(*-i* or *-w* or *\ -k* or *en0* or *bridge*)
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:process AND agent.type:"elastic-agent" AND host.os.type:macos AND process.name:(tcpdump OR tshark OR dumpcap OR Wireshark) AND process.command_line:(*\-i* OR *\-w* OR *\ \-k* OR *en0* OR *bridge*) | groupby host.name host.os.type user.name process.name process.parent.name event.action destination.ip destination.port | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line process.executable file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port destination.domain network.transport network.community_id event.code rule.name
```
### Query 3 — Security Onion Windows Elastic Agent
**Security Onion specific:** Uses Elastic Agent or Security Onion network telemetry in Security Onion 3.1.0. Requires the relevant endpoint, Zeek, Suricata, Windows, Linux, macOS, system, or Elastic Defend data streams with ECS-compatible fields.

```kql
event.category:process and agent.type:"elastic-agent" and host.os.type:windows and process.name:("pktmon.exe" or "netsh.exe" or "dumpcap.exe" or "tshark.exe" or "Wireshark.exe") and process.command_line:(*start* or *capture* or *trace* or *-w* or *pcap*)
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:process AND agent.type:"elastic-agent" AND host.os.type:windows AND process.name:("pktmon.exe" OR "netsh.exe" OR "dumpcap.exe" OR "tshark.exe" OR "Wireshark.exe") AND process.command_line:(*start* OR *capture* OR *trace* OR *\-w* OR *pcap*) | groupby host.name host.os.type user.name process.name process.parent.name event.action destination.ip destination.port | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line process.executable file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port destination.domain network.transport network.community_id event.code rule.name
```

**Tuning ideas:** allowlist known administrators, software deployment tools, EDR activity, inventory systems, vulnerability scanners, patching tools, and sanctioned management workflows before alerting.

---

## T1056.001 — Input Capture: Keylogging

**Tactic:** Credential Access / Collection  
**Detection idea:** Keylogger process behavior, keyboard hook references, or suspicious accessibility/input monitoring.  
**Elastic implementation notes:** These filters use ECS-style fields commonly present in Elastic Agent, Elastic Defend, Windows, Linux, macOS, Zeek, Suricata, cloud, and SaaS data streams. Tune command-line patterns, data views, and administrative allowlists before production use.

### Query 1 — Security Onion Windows Elastic Agent
**Security Onion specific:** Uses Elastic Agent or Security Onion telemetry in Security Onion 3.1.0. Requires the relevant endpoint, Zeek, Suricata, cloud, SaaS, Windows, Linux, macOS, system, or Elastic Defend data streams with ECS-compatible fields.

```kql
event.category:process and agent.type:"elastic-agent" and host.os.type:windows and process.command_line:(*SetWindowsHookEx* or *GetAsyncKeyState* or *GetKeyState* or *keylog* or *keyboard\ hook*)
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:process AND agent.type:"elastic-agent" AND host.os.type:windows AND process.command_line:(*SetWindowsHookEx* OR *GetAsyncKeyState* OR *GetKeyState* OR *keylog* OR *keyboard\ hook*) | groupby host.name host.os.type user.name process.name process.parent.name event.action destination.ip destination.port | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line process.executable file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port destination.domain network.transport network.community_id event.code rule.name
```
### Query 2 — Security Onion Linux/macOS Elastic Agent
**Security Onion specific:** Uses Elastic Agent or Security Onion telemetry in Security Onion 3.1.0. Requires the relevant endpoint, Zeek, Suricata, cloud, SaaS, Windows, Linux, macOS, system, or Elastic Defend data streams with ECS-compatible fields.

```kql
event.category:process and agent.type:"elastic-agent" and host.os.type:(linux or macos) and process.command_line:(*xinput*test* or *showkey* or *ioreg*keyboard* or *CGEventTap* or *keylog*)
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:process AND agent.type:"elastic-agent" AND host.os.type:(linux OR macos) AND process.command_line:(*xinput*test* OR *showkey* OR *ioreg*keyboard* OR *CGEventTap* OR *keylog*) | groupby host.name host.os.type user.name process.name process.parent.name event.action destination.ip destination.port | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line process.executable file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port destination.domain network.transport network.community_id event.code rule.name
```

**Tuning ideas:** allowlist known administrators, software deployment tools, EDR activity, backup agents, inventory systems, vulnerability scanners, patching tools, and sanctioned management workflows before alerting.

---

## T1552.005 — Unsecured Credentials: Cloud Instance Metadata API

**Tactic:** Credential Access  
**Detection idea:** Processes querying cloud instance metadata services for identity tokens or credentials.  
**Elastic implementation notes:** These filters use ECS-style fields commonly present in Elastic Agent, Elastic Defend, Windows, Linux, macOS, Zeek, Suricata, cloud, and SaaS data streams. Tune command-line patterns, data views, and administrative allowlists before production use.

### Query 1 — Security Onion Linux/macOS Elastic Agent
**Security Onion specific:** Uses Elastic Agent or Security Onion telemetry in Security Onion 3.1.0. Requires the relevant endpoint, Zeek, Suricata, cloud, SaaS, Windows, Linux, macOS, system, or Elastic Defend data streams with ECS-compatible fields.

```kql
event.category:network and agent.type:"elastic-agent" and host.os.type:(linux or macos) and destination.ip:169.254.169.254 and process.name:(curl or wget or python or python3 or ruby or perl)
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:network AND agent.type:"elastic-agent" AND host.os.type:(linux OR macos) AND destination.ip:169.254.169.254 AND process.name:(curl OR wget OR python OR python3 OR ruby OR perl) | groupby host.name host.os.type user.name process.name process.parent.name event.action destination.ip destination.port | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line process.executable file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port destination.domain network.transport network.community_id event.code rule.name
```
### Query 2 — Security Onion Windows Elastic Agent
**Security Onion specific:** Uses Elastic Agent or Security Onion telemetry in Security Onion 3.1.0. Requires the relevant endpoint, Zeek, Suricata, cloud, SaaS, Windows, Linux, macOS, system, or Elastic Defend data streams with ECS-compatible fields.

```kql
event.category:process and agent.type:"elastic-agent" and host.os.type:windows and process.command_line:(*169.254.169.254* or *metadata/identity/oauth2/token* or *latest/meta-data/iam/security-credentials* or *Metadata-Flavor*)
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:process AND agent.type:"elastic-agent" AND host.os.type:windows AND process.command_line:(*169.254.169.254* OR *metadata\/identity\/oauth2\/token* OR *latest\/meta\-data\/iam\/security\-credentials* OR *Metadata\-Flavor*) | groupby host.name host.os.type user.name process.name process.parent.name event.action destination.ip destination.port | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line process.executable file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port destination.domain network.transport network.community_id event.code rule.name
```

**Tuning ideas:** allowlist known administrators, software deployment tools, EDR activity, backup agents, inventory systems, vulnerability scanners, patching tools, and sanctioned management workflows before alerting.

---

## T1555.005 — Credentials from Password Stores: Password Managers

**Tactic:** Credential Access  
**Detection idea:** Access to password manager databases, browser vaults, or common password store files.  
**Elastic implementation notes:** These filters use ECS-style fields commonly present in Elastic Agent, Elastic Defend, Windows, Linux, macOS, Zeek, Suricata, cloud, and SaaS data streams. Tune command-line patterns, data views, and administrative allowlists before production use.

### Query 1 — Security Onion Windows Elastic Agent
**Security Onion specific:** Uses Elastic Agent or Security Onion telemetry in Security Onion 3.1.0. Requires the relevant endpoint, Zeek, Suricata, cloud, SaaS, Windows, Linux, macOS, system, or Elastic Defend data streams with ECS-compatible fields.

```kql
event.category:file and agent.type:"elastic-agent" and host.os.type:windows and file.path:(*\\AppData\\Roaming\\1Password\\* or *\\AppData\\Local\\1Password\\* or *\\AppData\\Roaming\\KeePass\\* or *\\AppData\\Local\\Google\\Chrome\\User\ Data\\*\\Login\ Data)
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:file AND agent.type:"elastic-agent" AND host.os.type:windows AND file.path:(*\\AppData\\Roaming\\1Password\\* OR *\\AppData\\Local\\1Password\\* OR *\\AppData\\Roaming\\KeePass\\* OR *\\AppData\\Local\\Google\\Chrome\\User\ Data\\*\\Login\ Data) | groupby host.name host.os.type user.name process.name process.parent.name event.action destination.ip destination.port | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line process.executable file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port destination.domain network.transport network.community_id event.code rule.name
```
### Query 2 — Security Onion Linux/macOS Elastic Agent
**Security Onion specific:** Uses Elastic Agent or Security Onion telemetry in Security Onion 3.1.0. Requires the relevant endpoint, Zeek, Suricata, cloud, SaaS, Windows, Linux, macOS, system, or Elastic Defend data streams with ECS-compatible fields.

```kql
event.category:file and agent.type:"elastic-agent" and host.os.type:(linux or macos) and file.path:(*/.password-store/* or */.config/1Password/* or */Library/Application\ Support/1Password/* or */.config/google-chrome/*/Login\ Data or */Library/Application\ Support/Google/Chrome/*/Login\ Data)
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:file AND agent.type:"elastic-agent" AND host.os.type:(linux OR macos) AND file.path:(*\/.password\-store\/* OR *\/.config\/1Password\/* OR *\/Library\/Application\ Support\/1Password\/* OR *\/.config\/google\-chrome\/*\/Login\ Data OR *\/Library\/Application\ Support\/Google\/Chrome\/*\/Login\ Data) | groupby host.name host.os.type user.name process.name process.parent.name event.action destination.ip destination.port | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line process.executable file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port destination.domain network.transport network.community_id event.code rule.name
```

**Tuning ideas:** allowlist known administrators, software deployment tools, EDR activity, backup agents, inventory systems, vulnerability scanners, patching tools, and sanctioned management workflows before alerting.

---

## T1110.002 — Brute Force: Password Cracking

**Tactic:** Credential Access  
**Detection idea:** Execution of offline password cracking utilities against hashes or credential dumps.  
**Elastic implementation notes:** These filters use ECS-style fields commonly present in Elastic Agent, Elastic Defend, Windows, Linux, macOS, Zeek, Suricata, cloud, and SaaS data streams. Tune command-line patterns, data views, and administrative allowlists before production use.

### Query 1 — Security Onion Windows Elastic Agent
**Security Onion specific:** Uses Elastic Agent or Security Onion telemetry in Security Onion 3.1.0. Requires the relevant endpoint, Zeek, Suricata, cloud, SaaS, Windows, Linux, macOS, system, or Elastic Defend data streams with ECS-compatible fields.

```kql
event.category:process and agent.type:"elastic-agent" and host.os.type:windows and process.name:("hashcat.exe" or "john.exe" or "john-the-ripper.exe" or "rcrack.exe") and process.command_line:(*-m* or *--wordlist* or *.hash* or *.ntds* or *.kirbi*)
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:process AND agent.type:"elastic-agent" AND host.os.type:windows AND process.name:("hashcat.exe" OR "john.exe" OR "john-the-ripper.exe" OR "rcrack.exe") AND process.command_line:(*\-m* OR *\-\-wordlist* OR *.hash* OR *.ntds* OR *.kirbi*) | groupby host.name host.os.type user.name process.name process.parent.name event.action destination.ip destination.port | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line process.executable file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port destination.domain network.transport network.community_id event.code rule.name
```
### Query 2 — Security Onion Linux/macOS Elastic Agent
**Security Onion specific:** Uses Elastic Agent or Security Onion telemetry in Security Onion 3.1.0. Requires the relevant endpoint, Zeek, Suricata, cloud, SaaS, Windows, Linux, macOS, system, or Elastic Defend data streams with ECS-compatible fields.

```kql
event.category:process and agent.type:"elastic-agent" and host.os.type:(linux or macos) and process.name:(hashcat or john or johnny or rcrack) and process.command_line:(*--wordlist* or *-m* or *.hash* or *.pot* or *rockyou*)
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:process AND agent.type:"elastic-agent" AND host.os.type:(linux OR macos) AND process.name:(hashcat OR john OR johnny OR rcrack) AND process.command_line:(*\-\-wordlist* OR *\-m* OR *.hash* OR *.pot* OR *rockyou*) | groupby host.name host.os.type user.name process.name process.parent.name event.action destination.ip destination.port | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line process.executable file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port destination.domain network.transport network.community_id event.code rule.name
```

**Tuning ideas:** allowlist known administrators, software deployment tools, EDR activity, backup agents, inventory systems, vulnerability scanners, patching tools, and sanctioned management workflows before alerting.

