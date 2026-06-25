# TA0043 — Reconnaissance

> Query dialect: Elastic Kibana Query Language (**Elastic KQL**) using ECS-style fields. These are hunting-grade filters intended for Kibana Discover, Timeline, and Elastic Security rules. Tune fields, data views, and allowlists to your environment.

**Coverage count:** 1 technique sections / 4 KQL queries

## Techniques in this tactic

- [T1595.002 — Vulnerability Scanning](SO_TA0043_Reconnaissance.md#t1595.002-vulnerability-scanning) — 4 queries

---

## T1595.002 — Vulnerability Scanning

**Tactic:** Reconnaissance  
**Detection idea:** Inbound vulnerability scanner or probing activity against public-facing services  
**Elastic implementation notes:** ECS field names vary by integration. Start with the KQL below, then tune for your Elastic Agent, Elastic Defend, Windows, System, Sysmon, cloud, and email data streams.

### Query 1
```kql
event.category:network and source.ip:* and destination.port:(80 or 443 or 8080 or 8443 or 3389 or 445 or 22) and event.action:(connection_attempted or connection_accepted or network_connection)
```

### Query 2
```kql
event.dataset:("nginx.access" or "apache.access" or "iis.access" or "aws.waf" or "azure.firewall") and url.path:("*/wp-admin*" or "*/phpmyadmin*" or "*/.env*" or "*/server-status*" or "*/cgi-bin/*" or "*/actuator/*")
```

**Tuning ideas:** allowlist known admin scripts, software deployment tools, scanners, EDR activity, patch management, and sanctioned cloud apps before alerting.

---

### Query 3 — Security Onion
**Security Onion specific:** Uses Security Onion Suricata NIDS alert data (`event.module:"Suricata"`, `event.dataset:"alert"`) for scan/probe signatures.

```kql
event.module:"Suricata" and event.dataset:"alert" and rule.name:("*SCAN*" or "*Nmap*" or "*Masscan*" or "*SIPVicious*" or "*Nikto*" or "*Zgrab*") and source.ip:* and destination.ip:*
```

**Security Onion Hunt dashboard (OQL):** Uses Security Onion 3.1 Hunt syntax. The filter uses Lucene/OQL boolean operators and adds Hunt-friendly grouping, sorting, and event-table columns.

```oql
event.module:"Suricata" AND event.dataset:"alert" AND rule.name:("*SCAN*" OR "*Nmap*" OR "*Masscan*" OR "*SIPVicious*" OR "*Nikto*" OR "*Zgrab*") AND source.ip:* AND destination.ip:* | groupby event.dataset source.ip destination.ip destination.port rule.name | sortby @timestamp | table event.module event.dataset source.ip source.port destination.ip destination.port network.transport network.community_id log.id.uid rule.name dns.question.name url.domain tls.server.name http.request.method file.name file.path host.name user.name event.code event.action
```

### Query 4 — Security Onion
**Security Onion specific:** Uses Security Onion Zeek connection metadata (`event.dataset:conn`) for inbound probing against commonly scanned services.

```kql
event.dataset:conn and destination.port:(21 or 22 or 23 or 25 or 53 or 80 or 110 or 135 or 139 or 143 or 443 or 445 or 3389 or 8080 or 8443) and source.ip:* and destination.ip:*
```

**Security Onion Hunt dashboard (OQL):** Uses Security Onion 3.1 Hunt syntax. The filter uses Lucene/OQL boolean operators and adds Hunt-friendly grouping, sorting, and event-table columns.

```oql
event.dataset:conn AND destination.port:(21 OR 22 OR 23 OR 25 OR 53 OR 80 OR 110 OR 135 OR 139 OR 143 OR 443 OR 445 OR 3389 OR 8080 OR 8443) AND source.ip:* AND destination.ip:* | groupby event.dataset source.ip destination.ip destination.port rule.name | sortby @timestamp | table event.module event.dataset source.ip source.port destination.ip destination.port network.transport network.community_id log.id.uid rule.name dns.question.name url.domain tls.server.name http.request.method file.name file.path host.name user.name event.code event.action
```
