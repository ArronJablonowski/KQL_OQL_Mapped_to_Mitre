# TA0001 — Initial Access

> Query dialect: Elastic Kibana Query Language (**Elastic KQL**) using ECS-style fields. These are hunting-grade filters intended for Kibana Discover, Timeline, and Elastic Security rules. Tune fields, data views, and allowlists to your environment.

**Coverage count:** 6 technique sections / 18 KQL queries

## Techniques in this tactic

- [T1566.001 — Phishing: Spearphishing Attachment](SO_TA0001_Initial_Access.md#t1566.001-phishing-spearphishing-attachment) — 2 queries
- [T1190 — Exploit Public-Facing Application](SO_TA0001_Initial_Access.md#t1190-exploit-public-facing-application) — 4 queries
- [T1133 — External Remote Services](SO_TA0001_Initial_Access.md#t1133-external-remote-services) — 4 queries
- [T1566.002 — Phishing: Spearphishing Link](SO_TA0001_Initial_Access.md#t1566.002-phishing-spearphishing-link) — 4 queries
- [T1566.003 — Phishing: Spearphishing via Service](SO_TA0001_Initial_Access.md#t1566.003-phishing-spearphishing-via-service) — 2 queries
- [T1204.002 — User Execution: Malicious File](SO_TA0001_Initial_Access.md#t1204.002-user-execution-malicious-file) — 2 queries

---

## T1566.001 — Phishing: Spearphishing Attachment

**Tactic:** Initial Access  
**Detection idea:** Email attachment indicators for potentially malicious payload delivery  
**Elastic implementation notes:** ECS field names vary by integration. Start with the KQL below, then tune for your Elastic Agent, Elastic Defend, Windows, System, Sysmon, cloud, and email data streams.

### Query 1
```kql
event.category:email and email.attachments.file.extension:(exe or scr or js or jse or vbs or vbe or ps1 or hta or lnk or iso or img or zip or rar or 7z)
```

### Query 2
```kql
event.category:email and email.subject:(*invoice* or *payment* or *urgent* or *voicemail* or *docusign* or *password*) and email.attachments.file.name:*
```

**Tuning ideas:** allowlist known admin scripts, software deployment tools, scanners, EDR activity, patch management, and sanctioned cloud apps before alerting.

---

## T1190 — Exploit Public-Facing Application

**Tactic:** Initial Access  
**Detection idea:** Exploit attempts or suspicious requests against internet-facing applications  
**Elastic implementation notes:** ECS field names vary by integration. Start with the KQL below, then tune for your Elastic Agent, Elastic Defend, Windows, System, Sysmon, cloud, and email data streams.

### Query 1
```kql
event.dataset:("nginx.access" or "apache.access" or "iis.access" or "aws.waf" or "azure.application_gateway") and http.response.status_code:(400 or 401 or 403 or 404 or 500) and url.path:(*/wp-admin* or */phpmyadmin* or */.env* or */cgi-bin/* or */actuator/*)
```

### Query 2
```kql
event.category:web and url.query:(*union\ select* or *../* or *%2e%2e* or *cmd=* or *powershell* or *jndi\:* or *${jndi\:*)
```

**Tuning ideas:** allowlist known admin scripts, software deployment tools, scanners, EDR activity, patch management, and sanctioned cloud apps before alerting.

---

### Query 3 — Security Onion
**Security Onion specific:** Uses Security Onion Suricata alert names for exploit attempts against public-facing applications.

```kql
event.module:"Suricata" and event.dataset:"alert" and rule.name:(*EXPLOIT* or *WEB_SERVER* or *WEB_SPECIFIC_APPS* or *SQL\ Injection* or *Directory\ Traversal* or *Log4j*) and destination.port:(80 or 443 or 8080 or 8443)
```

**Security Onion Hunt dashboard (OQL):** Uses Security Onion 3.1 Hunt syntax. The filter uses Lucene/OQL boolean operators and adds Hunt-friendly grouping, sorting, and event-table columns.

```oql
event.module:"Suricata" AND event.dataset:"alert" AND rule.name:(*EXPLOIT* OR *WEB_SERVER* OR *WEB_SPECIFIC_APPS* OR *SQL\ Injection* OR *Directory\ Traversal* OR *Log4j*) AND destination.port:(80 OR 443 OR 8080 OR 8443) | groupby event.dataset source.ip destination.ip destination.port rule.name | sortby @timestamp | table event.module event.dataset source.ip source.port destination.ip destination.port network.transport network.community_id log.id.uid rule.name dns.question.name url.domain tls.server.name http.request.method file.name file.path host.name user.name event.code event.action
```

### Query 4 — Security Onion
**Security Onion specific:** Uses Security Onion Zeek HTTP metadata to hunt web exploit URI patterns.

```kql
event.dataset:http and url.path:(*/wp-admin* or */phpmyadmin* or */.env* or */cgi-bin/* or */actuator/*) and source.ip:* and destination.ip:*
```

**Security Onion Hunt dashboard (OQL):** Uses Security Onion 3.1 Hunt syntax. The filter uses Lucene/OQL boolean operators and adds Hunt-friendly grouping, sorting, and event-table columns.

```oql
event.dataset:http AND url.path:(*\/wp\-admin* OR *\/phpmyadmin* OR *\/.env* OR *\/cgi\-bin\/* OR *\/actuator\/*) AND source.ip:* AND destination.ip:* | groupby event.dataset source.ip destination.ip destination.port rule.name | sortby @timestamp | table event.module event.dataset source.ip source.port destination.ip destination.port network.transport network.community_id log.id.uid rule.name dns.question.name url.domain tls.server.name http.request.method file.name file.path host.name user.name event.code event.action
```

## T1133 — External Remote Services

**Tactic:** Initial Access  
**Detection idea:** Successful authentication to VPN, RDP, SSH, or remote access services from unusual sources  
**Elastic implementation notes:** ECS field names vary by integration. Start with the KQL below, then tune for your Elastic Agent, Elastic Defend, Windows, System, Sysmon, cloud, and email data streams.

### Query 1
```kql
event.category:authentication and event.outcome:success and event.dataset:("fortinet.firewall" or "panw.panos" or "cisco.asa" or "azure.signinlogs" or "windows.security") and source.ip:* and user.name:*
```

### Query 2
```kql
event.category:network and destination.port:(22 or 3389 or 5985 or 5986 or 443) and event.outcome:success and source.ip:* and user.name:*
```

**Tuning ideas:** allowlist known admin scripts, software deployment tools, scanners, EDR activity, patch management, and sanctioned cloud apps before alerting.

---

### Query 3 — Security Onion
**Security Onion specific:** Uses Security Onion Zeek connection metadata for inbound external remote service access.

```kql
event.dataset:conn and destination.port:(22 or 3389 or 5985 or 5986 or 443) and source.ip:* and destination.ip:* and not source.ip:(10.0.0.0/8 or 172.16.0.0/12 or 192.168.0.0/16)
```

**Security Onion Hunt dashboard (OQL):** Uses Security Onion 3.1 Hunt syntax. The filter uses Lucene/OQL boolean operators and adds Hunt-friendly grouping, sorting, and event-table columns.

```oql
event.dataset:conn AND destination.port:(22 OR 3389 OR 5985 OR 5986 OR 443) AND source.ip:* AND destination.ip:* AND NOT source.ip:(10.0.0.0/8 OR 172.16.0.0/12 OR 192.168.0.0/16) | groupby event.dataset source.ip destination.ip destination.port rule.name | sortby @timestamp | table event.module event.dataset source.ip source.port destination.ip destination.port network.transport network.community_id log.id.uid rule.name dns.question.name url.domain tls.server.name http.request.method file.name file.path host.name user.name event.code event.action
```

### Query 4 — Security Onion
**Security Onion specific:** Uses Security Onion Suricata alert data for VPN, RDP, SSH, and remote-access service alerts.

```kql
event.module:"Suricata" and event.dataset:"alert" and rule.name:(*VPN* or *RDP* or *SSH* or *Remote\ Access* or *AnyDesk* or *TeamViewer*) and source.ip:* and destination.ip:*
```

**Security Onion Hunt dashboard (OQL):** Uses Security Onion 3.1 Hunt syntax. The filter uses Lucene/OQL boolean operators and adds Hunt-friendly grouping, sorting, and event-table columns.

```oql
event.module:"Suricata" AND event.dataset:"alert" AND rule.name:(*VPN* OR *RDP* OR *SSH* OR *Remote\ Access* OR *AnyDesk* OR *TeamViewer*) AND source.ip:* AND destination.ip:* | groupby event.dataset source.ip destination.ip destination.port rule.name | sortby @timestamp | table event.module event.dataset source.ip source.port destination.ip destination.port network.transport network.community_id log.id.uid rule.name dns.question.name url.domain tls.server.name http.request.method file.name file.path host.name user.name event.code event.action
```

## T1566.002 — Phishing: Spearphishing Link

**Tactic:** Initial Access  
**Detection idea:** Email messages containing suspicious links or lure terms  
**Elastic implementation notes:** ECS field names vary by integration. Start with the KQL below, then tune for your Elastic Agent, Elastic Defend, Windows, System, Sysmon, cloud, and email data streams.

### Query 1
```kql
event.category:email and url.full:* and email.subject:(*invoice* or *payment* or *urgent* or *password* or *mfa* or *voicemail* or *docusign*)
```

### Query 2
```kql
event.category:email and url.domain:* and not url.domain:(*.microsoft.com or *.office.com or *.google.com) and email.from.address:*
```

**Tuning ideas:** allowlist known admin scripts, software deployment tools, scanners, EDR activity, patch management, and sanctioned cloud apps before alerting.

---

### Query 3 — Security Onion
**Security Onion specific:** Uses Security Onion Zeek DNS/HTTP metadata to hunt suspicious link-click infrastructure from monitored clients.

```kql
event.dataset:(dns or http) and (dns.question.name:(*.duckdns.org or *.ddns.net or *.ngrok.io or *.pages.dev or *.workers.dev) or url.domain:(*.duckdns.org or *.ddns.net or *.ngrok.io or *.pages.dev or *.workers.dev))
```

**Security Onion Hunt dashboard (OQL):** Uses Security Onion 3.1 Hunt syntax. The filter uses Lucene/OQL boolean operators and adds Hunt-friendly grouping, sorting, and event-table columns.

```oql
event.dataset:(dns OR http) AND (dns.question.name:(*.duckdns.org OR *.ddns.net OR *.ngrok.io OR *.pages.dev OR *.workers.dev) OR url.domain:(*.duckdns.org OR *.ddns.net OR *.ngrok.io OR *.pages.dev OR *.workers.dev)) | groupby event.dataset source.ip destination.ip destination.port rule.name | sortby @timestamp | table event.module event.dataset source.ip source.port destination.ip destination.port network.transport network.community_id log.id.uid rule.name dns.question.name url.domain tls.server.name http.request.method file.name file.path host.name user.name event.code event.action
```

### Query 4 — Security Onion
**Security Onion specific:** Uses Security Onion Suricata alert data for phishing or credential-harvesting detections.

```kql
event.module:"Suricata" and event.dataset:"alert" and rule.name:(*PHISH* or *Phishing* or *Credential* or *Login\ Page* or *Fake*Microsoft* or *Fake*Office*)
```

**Security Onion Hunt dashboard (OQL):** Uses Security Onion 3.1 Hunt syntax. The filter uses Lucene/OQL boolean operators and adds Hunt-friendly grouping, sorting, and event-table columns.

```oql
event.module:"Suricata" AND event.dataset:"alert" AND rule.name:(*PHISH* OR *Phishing* OR *Credential* OR *Login\ Page* OR *Fake*Microsoft* OR *Fake*Office*) | groupby event.dataset source.ip destination.ip destination.port rule.name | sortby @timestamp | table event.module event.dataset source.ip source.port destination.ip destination.port network.transport network.community_id log.id.uid rule.name dns.question.name url.domain tls.server.name http.request.method file.name file.path host.name user.name event.code event.action
```

## T1566.003 — Phishing: Spearphishing via Service

**Tactic:** Initial Access  
**Detection idea:** SaaS collaboration or messaging activity carrying suspicious external links  
**Elastic implementation notes:** ECS field names vary by integration. Start with the KQL below, then tune for your Elastic Agent, Elastic Defend, Windows, System, Sysmon, cloud, and email data streams.

### Query 1
```kql
event.dataset:("o365.audit" or "google_workspace.admin" or "slack.audit" or "zoom.audit") and event.action:(*message* or *sharing* or *file* or *link*) and url.full:*
```

### Query 2
```kql
event.dataset:("o365.audit" or "google_workspace.drive" or "google_workspace.admin") and event.action:(*SharingSet* or *FileShared* or *CreateLink* or *AnonymousLinkCreated*) and user.email:*
```

**Tuning ideas:** allowlist known admin scripts, software deployment tools, scanners, EDR activity, patch management, and sanctioned cloud apps before alerting.

---

## T1204.002 — User Execution: Malicious File

**Tactic:** Initial Access / Execution  
**Detection idea:** Windows Elastic Agent browser or email client spawning archive, script, or installer execution  
**Elastic implementation notes:** Host telemetry requires Elastic Agent with endpoint, system, Windows, macOS, Linux, or Elastic Defend integrations. Field availability varies by agent policy and event collection settings.

### Query 1 — Security Onion Windows Elastic Agent
**Security Onion specific:** Uses Elastic Agent telemetry in Security Onion 3.1.0 for Windows hosts. Requires Elastic Agent endpoint, system, Windows, macOS, Linux, or Elastic Defend data streams with ECS host, process, file, registry, authentication, or network fields.

```kql
event.category:process and agent.type:"elastic-agent" and host.os.type:windows and process.parent.name:("outlook.exe" or "chrome.exe" or "msedge.exe" or "firefox.exe" or "explorer.exe") and process.name:("powershell.exe" or "cmd.exe" or "wscript.exe" or "mshta.exe" or "rundll32.exe" or "regsvr32.exe" or "msiexec.exe")
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:process AND agent.type:"elastic-agent" AND host.os.type:windows AND process.parent.name:("outlook.exe" OR "chrome.exe" OR "msedge.exe" OR "firefox.exe" OR "explorer.exe") AND process.name:("powershell.exe" OR "cmd.exe" OR "wscript.exe" OR "mshta.exe" OR "rundll32.exe" OR "regsvr32.exe" OR "msiexec.exe") | groupby host.name host.os.type user.name process.name process.parent.name destination.ip destination.port event.action | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line process.executable file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port destination.domain network.transport event.code rule.name
```


### Query 2 — Security Onion macOS Elastic Agent
**Security Onion specific:** Uses Elastic Agent telemetry in Security Onion 3.1.0 for macOS hosts. Requires Elastic Agent endpoint, system, Windows, macOS, Linux, or Elastic Defend data streams with ECS host, process, file, registry, authentication, or network fields.

```kql
event.category:process and agent.type:"elastic-agent" and host.os.type:macos and process.parent.name:("Finder" or "Safari" or "Google Chrome" or "Microsoft Edge") and process.name:(osascript or bash or zsh or sh or python or installer)
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:process AND agent.type:"elastic-agent" AND host.os.type:macos AND process.parent.name:("Finder" OR "Safari" OR "Google Chrome" OR "Microsoft Edge") AND process.name:(osascript OR bash OR zsh OR sh OR python OR installer) | groupby host.name host.os.type user.name process.name process.parent.name destination.ip destination.port event.action | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line process.executable file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port destination.domain network.transport event.code rule.name
```

**Tuning ideas:** allowlist approved admin scripts, package managers, MDM/GPO activity, backup tools, EDR activity, deployment systems, developer workflows, and sanctioned remote administration.

---
