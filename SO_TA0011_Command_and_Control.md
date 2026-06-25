# TA0011 — Command and Control

> Query dialect: Elastic Kibana Query Language (**Elastic KQL**) using ECS-style fields. These are hunting-grade filters intended for Kibana Discover, Timeline, and Elastic Security rules. Tune fields, data views, and allowlists to your environment.

**Coverage count:** 13 technique sections / 44 KQL queries

## Techniques in this tactic

- [T1105 — Ingress Tool Transfer](SO_TA0011_Command_and_Control.md#t1105-ingress-tool-transfer) — 5 queries
- [T1071.001 — Application Layer Protocol: Web Protocols](SO_TA0011_Command_and_Control.md#t1071.001-application-layer-protocol-web-protocols) — 4 queries
- [T1090 — Proxy](SO_TA0011_Command_and_Control.md#t1090-proxy) — 6 queries
- [T1572 — Protocol Tunneling](SO_TA0011_Command_and_Control.md#t1572-protocol-tunneling) — 5 queries
- [T1095 — Non-Application Layer Protocol](SO_TA0011_Command_and_Control.md#t1095-non-application-layer-protocol) — 2 queries
- [T1219 — Remote Access Software](SO_TA0011_Command_and_Control.md#t1219-remote-access-software) — 6 queries
- [T1571 — Non-Standard Port](SO_TA0011_Command_and_Control.md#t1571-non-standard-port) — 3 queries
- [T1132 — Data Encoding](SO_TA0011_Command_and_Control.md#t1132-data-encoding) — 3 queries
- [T1071.004 — Application Layer Protocol: DNS](SO_TA0011_Command_and_Control.md#t1071.004-application-layer-protocol-dns) — 2 queries
- [T1568.001 — Dynamic Resolution: Fast Flux DNS](SO_TA0011_Command_and_Control.md#t1568.001-dynamic-resolution-fast-flux-dns) — 2 queries
- [T1568.002 — Dynamic Resolution: Domain Generation Algorithms](SO_TA0011_Command_and_Control.md#t1568.002-dynamic-resolution-domain-generation-algorithms) — 2 queries
- [T1132.001 — Data Encoding: Standard Encoding](SO_TA0011_Command_and_Control.md#t1132.001-data-encoding-standard-encoding) — 2 queries
- [T1132.002 — Data Encoding: Non-Standard Encoding](SO_TA0011_Command_and_Control.md#t1132.002-data-encoding-non-standard-encoding) — 2 queries

---

## T1105 — Ingress Tool Transfer

**Tactic:** Command and Control  
**Detection idea:** Native utilities downloading payloads or scripts  
**Elastic implementation notes:** ECS field names vary by integration. Start with the KQL below, then tune for your Elastic Agent, Elastic Defend, Windows, System, Sysmon, cloud, and email data streams.

### Query 1
```kql
event.category:process and process.name:("certutil.exe" or "bitsadmin.exe" or "curl.exe" or "wget.exe" or "powershell.exe" or "pwsh.exe") and process.command_line:("*http://*" or "*https://*" or "*ftp://*")
```

### Query 2
```kql
event.category:network and process.name:("powershell.exe" or "pwsh.exe" or "certutil.exe" or "bitsadmin.exe" or "mshta.exe" or "rundll32.exe") and destination.ip:* and not destination.ip:(10.0.0.0/8 or 172.16.0.0/12 or 192.168.0.0/16)
```

### Query 3 — Security Onion Linux/macOS Elastic Agent
**Security Onion specific:** Uses Elastic Agent telemetry in Security Onion 3.1.0 for Linux/macOS hosts. Requires Elastic Agent endpoint, system, or Elastic Defend data streams with ECS host, process, file, or network fields.

```kql
event.category:network and agent.type:"elastic-agent" and host.os.type:(linux or macos) and process.name:(curl or wget or python or python3 or perl or ruby or nc or ncat or openssl or bash or zsh or sh) and destination.ip:* and not destination.ip:(10.0.0.0/8 or 172.16.0.0/12 or 192.168.0.0/16)
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:network AND agent.type:"elastic-agent" AND host.os.type:(linux OR macos) AND process.name:(curl OR wget OR python OR python3 OR perl OR ruby OR nc OR ncat OR openssl OR bash OR zsh OR sh) AND destination.ip:* AND NOT destination.ip:(10.0.0.0/8 OR 172.16.0.0/12 OR 192.168.0.0/16) | groupby host.name host.os.type user.name process.name source.ip destination.ip destination.port | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line file.path file.name file.extension source.ip source.port destination.ip destination.port network.transport network.community_id rule.name
```

### Query 4 — Security Onion Linux Elastic Agent
**Security Onion specific:** Uses Elastic Agent telemetry in Security Onion 3.1.0 for Linux hosts. Requires Elastic Agent endpoint, system, Windows, macOS, Linux, or Elastic Defend data streams with ECS host, process, file, registry, authentication, or network fields.

```kql
event.category:process and agent.type:"elastic-agent" and host.os.type:linux and process.name:(curl or wget or python or python3 or perl or php) and process.command_line:("*/tmp/*" or "*/dev/shm/*" or "* -O *" or "* -o *" or "*http*")
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:process AND agent.type:"elastic-agent" AND host.os.type:linux AND process.name:(curl OR wget OR python OR python3 OR perl OR php) AND process.command_line:("*/tmp/*" OR "*/dev/shm/*" OR "* -O *" OR "* -o *" OR "*http*") | groupby host.name host.os.type user.name process.name process.parent.name destination.ip destination.port event.action | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port network.transport network.community_id event.code rule.name
```

### Query 5 — Security Onion macOS Elastic Agent
**Security Onion specific:** Uses Elastic Agent telemetry in Security Onion 3.1.0 for macOS hosts. Requires Elastic Agent endpoint, system, Windows, macOS, Linux, or Elastic Defend data streams with ECS host, process, file, registry, authentication, or network fields.

```kql
event.category:process and agent.type:"elastic-agent" and host.os.type:macos and process.name:(curl or osascript or python or python3 or bash or zsh or sh) and process.command_line:("*http*" or "*/tmp/*" or "*/Users/Shared/*" or "* -o *" or "*do shell script*")
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:process AND agent.type:"elastic-agent" AND host.os.type:macos AND process.name:(curl OR osascript OR python OR python3 OR bash OR zsh OR sh) AND process.command_line:("*http*" OR "*/tmp/*" OR "*/Users/Shared/*" OR "* -o *" OR "*do shell script*") | groupby host.name host.os.type user.name process.name process.parent.name destination.ip destination.port event.action | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port network.transport network.community_id event.code rule.name
```

**Tuning ideas:** allowlist known admin scripts, software deployment tools, scanners, EDR activity, patch management, and sanctioned cloud apps before alerting.

---

## T1071.001 — Application Layer Protocol: Web Protocols

**Tactic:** Command and Control  
**Detection idea:** Suspicious web protocol use by scripting interpreters or LOLBins  
**Elastic implementation notes:** ECS field names vary by integration. Start with the KQL below, then tune for your Elastic Agent, Elastic Defend, Windows, System, Sysmon, cloud, and email data streams.

### Query 1
```kql
event.category:network and process.name:("powershell.exe" or "pwsh.exe" or "mshta.exe" or "rundll32.exe" or "regsvr32.exe" or "wscript.exe" or "cscript.exe") and destination.port:(80 or 443 or 8080 or 8443)
```

### Query 2
```kql
event.category:process and process.command_line:("*http://*" or "*https://*") and process.name:("powershell.exe" or "pwsh.exe" or "cmd.exe" or "mshta.exe" or "regsvr32.exe")
```

**Tuning ideas:** allowlist known admin scripts, software deployment tools, scanners, EDR activity, patch management, and sanctioned cloud apps before alerting.

---

### Query 3 — Security Onion
**Security Onion specific:** Uses Security Onion Zeek HTTP/SSL/DNS metadata for suspicious web C2 indicators.

```kql
event.dataset:(http or ssl or dns) and (url.domain:("*.duckdns.org" or "*.ddns.net" or "*.ngrok.io" or "*.workers.dev") or tls.server.name:("*.duckdns.org" or "*.ddns.net" or "*.ngrok.io" or "*.workers.dev") or dns.question.name:("*.duckdns.org" or "*.ddns.net" or "*.ngrok.io" or "*.workers.dev"))
```

**Security Onion Hunt dashboard (OQL):** Uses Security Onion 3.1 Hunt syntax. The filter uses Lucene/OQL boolean operators and adds Hunt-friendly grouping, sorting, and event-table columns.

```oql
event.dataset:(http OR ssl OR dns) AND (url.domain:("*.duckdns.org" OR "*.ddns.net" OR "*.ngrok.io" OR "*.workers.dev") OR tls.server.name:("*.duckdns.org" OR "*.ddns.net" OR "*.ngrok.io" OR "*.workers.dev") OR dns.question.name:("*.duckdns.org" OR "*.ddns.net" OR "*.ngrok.io" OR "*.workers.dev")) | groupby event.dataset source.ip destination.ip destination.port rule.name | sortby @timestamp | table event.module event.dataset source.ip source.port destination.ip destination.port network.transport network.community_id log.id.uid rule.name dns.question.name url.domain tls.server.name http.request.method file.name file.path host.name user.name event.code event.action
```

### Query 4 — Security Onion
**Security Onion specific:** Uses Security Onion Suricata alert data for HTTP/HTTPS C2 or malware callback signatures.

```kql
event.module:"Suricata" and event.dataset:"alert" and rule.name:("*C2*" or "*CnC*" or "*Command and Control*" or "*Callback*" or "*Beacon*")
```

**Security Onion Hunt dashboard (OQL):** Uses Security Onion 3.1 Hunt syntax. The filter uses Lucene/OQL boolean operators and adds Hunt-friendly grouping, sorting, and event-table columns.

```oql
event.module:"Suricata" AND event.dataset:"alert" AND rule.name:("*C2*" OR "*CnC*" OR "*Command and Control*" OR "*Callback*" OR "*Beacon*") | groupby event.dataset source.ip destination.ip destination.port rule.name | sortby @timestamp | table event.module event.dataset source.ip source.port destination.ip destination.port network.transport network.community_id log.id.uid rule.name dns.question.name url.domain tls.server.name http.request.method file.name file.path host.name user.name event.code event.action
```

## T1090 — Proxy

**Tactic:** Command and Control  
**Detection idea:** Proxy tooling, SOCKS tunneling, or proxy configuration changes  
**Elastic implementation notes:** ECS field names vary by integration. Start with the KQL below, then tune for your Elastic Agent, Elastic Defend, Windows, System, Sysmon, cloud, and email data streams.

### Query 1
```kql
event.category:process and process.command_line:("*socks*" or "*proxy*" or "*chisel*" or "*frp*" or "*ngrok*" or "*proxychains*" or "*ssh -D*")
```

### Query 2
```kql
event.category:network and process.name:("chisel.exe" or "ngrok.exe" or "plink.exe" or "ssh.exe" or "stunnel.exe") and destination.ip:*
```

**Tuning ideas:** allowlist known admin scripts, software deployment tools, scanners, EDR activity, patch management, and sanctioned cloud apps before alerting.

---

### Query 3 — Security Onion
**Security Onion specific:** Uses Security Onion Zeek HTTP metadata for proxy-like request behavior.

```kql
event.dataset:http and http.request.method:(CONNECT or POST) and destination.port:(80 or 443 or 8080 or 8443 or 3128) and source.ip:*
```

**Security Onion Hunt dashboard (OQL):** Uses Security Onion 3.1 Hunt syntax. The filter uses Lucene/OQL boolean operators and adds Hunt-friendly grouping, sorting, and event-table columns.

```oql
event.dataset:http AND http.request.method:(CONNECT OR POST) AND destination.port:(80 OR 443 OR 8080 OR 8443 OR 3128) AND source.ip:* | groupby event.dataset source.ip destination.ip destination.port rule.name | sortby @timestamp | table event.module event.dataset source.ip source.port destination.ip destination.port network.transport network.community_id log.id.uid rule.name dns.question.name url.domain tls.server.name http.request.method file.name file.path host.name user.name event.code event.action
```

### Query 4 — Security Onion
**Security Onion specific:** Uses Security Onion Suricata alert data for proxy, tunnel, or anonymizer signatures.

```kql
event.module:"Suricata" and event.dataset:"alert" and rule.name:("*Proxy*" or "*SOCKS*" or "*Tor*" or "*Teredo*" or "*Tunnel*")
```

**Security Onion Hunt dashboard (OQL):** Uses Security Onion 3.1 Hunt syntax. The filter uses Lucene/OQL boolean operators and adds Hunt-friendly grouping, sorting, and event-table columns.

```oql
event.module:"Suricata" AND event.dataset:"alert" AND rule.name:("*Proxy*" OR "*SOCKS*" OR "*Tor*" OR "*Teredo*" OR "*Tunnel*") | groupby event.dataset source.ip destination.ip destination.port rule.name | sortby @timestamp | table event.module event.dataset source.ip source.port destination.ip destination.port network.transport network.community_id log.id.uid rule.name dns.question.name url.domain tls.server.name http.request.method file.name file.path host.name user.name event.code event.action
```
### Query 5 — Security Onion Linux Elastic Agent
**Security Onion specific:** Uses Elastic Agent telemetry in Security Onion 3.1.0 for Linux hosts. Requires Elastic Agent endpoint, system, Windows, macOS, Linux, or Elastic Defend data streams with ECS host, process, file, registry, authentication, or network fields.

```kql
event.category:process and agent.type:"elastic-agent" and host.os.type:linux and process.name:(ssh or socat or chisel or ngrok or stunnel) and process.command_line:("* -D *" or "* -L *" or "* -R *" or "*socks*" or "*reverse*" or "*client*")
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:process AND agent.type:"elastic-agent" AND host.os.type:linux AND process.name:(ssh OR socat OR chisel OR ngrok OR stunnel) AND process.command_line:("* -D *" OR "* -L *" OR "* -R *" OR "*socks*" OR "*reverse*" OR "*client*") | groupby host.name host.os.type user.name process.name process.parent.name destination.ip destination.port event.action | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line process.executable file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port destination.domain network.transport event.code rule.name
```
### Query 6 — Security Onion macOS Elastic Agent
**Security Onion specific:** Uses Elastic Agent telemetry in Security Onion 3.1.0 for macOS hosts. Requires Elastic Agent endpoint, system, Windows, macOS, Linux, or Elastic Defend data streams with ECS host, process, file, registry, authentication, or network fields.

```kql
event.category:process and agent.type:"elastic-agent" and host.os.type:macos and process.name:(ssh or chisel or ngrok or stunnel) and process.command_line:("* -D *" or "* -L *" or "* -R *" or "*socks*" or "*reverse*")
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:process AND agent.type:"elastic-agent" AND host.os.type:macos AND process.name:(ssh OR chisel OR ngrok OR stunnel) AND process.command_line:("* -D *" OR "* -L *" OR "* -R *" OR "*socks*" OR "*reverse*") | groupby host.name host.os.type user.name process.name process.parent.name destination.ip destination.port event.action | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line process.executable file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port destination.domain network.transport event.code rule.name
```

## T1572 — Protocol Tunneling

**Tactic:** Command and Control  
**Detection idea:** Tunneling utilities or SSH dynamic forwarding  
**Elastic implementation notes:** ECS field names vary by integration. Start with the KQL below, then tune for your Elastic Agent, Elastic Defend, Windows, System, Sysmon, cloud, and email data streams.

### Query 1
```kql
event.category:process and process.command_line:("*ssh -L*" or "*ssh -R*" or "*ssh -D*" or "*plink* -L*" or "*plink* -R*" or "*chisel*" or "*stunnel*")
```

### Query 2
```kql
event.category:network and process.name:("ssh.exe" or "plink.exe" or "chisel.exe" or "stunnel.exe" or "ngrok.exe") and destination.ip:*
```

**Tuning ideas:** allowlist known admin scripts, software deployment tools, scanners, EDR activity, patch management, and sanctioned cloud apps before alerting.

---

### Query 3 — Security Onion
**Security Onion specific:** Uses Security Onion Zeek connection metadata for common tunnel ports and long-lived tunnel candidates.

```kql
event.dataset:conn and destination.port:(22 or 443 or 1194 or 1701 or 1723 or 500 or 4500 or 51820) and source.ip:* and destination.ip:*
```

**Security Onion Hunt dashboard (OQL):** Uses Security Onion 3.1 Hunt syntax. The filter uses Lucene/OQL boolean operators and adds Hunt-friendly grouping, sorting, and event-table columns.

```oql
event.dataset:conn AND destination.port:(22 OR 443 OR 1194 OR 1701 OR 1723 OR 500 OR 4500 OR 51820) AND source.ip:* AND destination.ip:* | groupby event.dataset source.ip destination.ip destination.port rule.name | sortby @timestamp | table event.module event.dataset source.ip source.port destination.ip destination.port network.transport network.community_id log.id.uid rule.name dns.question.name url.domain tls.server.name http.request.method file.name file.path host.name user.name event.code event.action
```

### Query 4 — Security Onion
**Security Onion specific:** Uses Security Onion Suricata alert data for VPN, tunnel, and encapsulation signatures.

```kql
event.module:"Suricata" and event.dataset:"alert" and rule.name:("*Tunnel*" or "*VPN*" or "*OpenVPN*" or "*WireGuard*" or "*GRE*" or "*IPsec*")
```

**Security Onion Hunt dashboard (OQL):** Uses Security Onion 3.1 Hunt syntax. The filter uses Lucene/OQL boolean operators and adds Hunt-friendly grouping, sorting, and event-table columns.

```oql
event.module:"Suricata" AND event.dataset:"alert" AND rule.name:("*Tunnel*" OR "*VPN*" OR "*OpenVPN*" OR "*WireGuard*" OR "*GRE*" OR "*IPsec*") | groupby event.dataset source.ip destination.ip destination.port rule.name | sortby @timestamp | table event.module event.dataset source.ip source.port destination.ip destination.port network.transport network.community_id log.id.uid rule.name dns.question.name url.domain tls.server.name http.request.method file.name file.path host.name user.name event.code event.action
```
### Query 5 — Security Onion Linux Elastic Agent
**Security Onion specific:** Uses Elastic Agent telemetry in Security Onion 3.1.0 for Linux hosts. Requires Elastic Agent endpoint, system, Windows, macOS, Linux, or Elastic Defend data streams with ECS host, process, file, registry, authentication, or network fields.

```kql
event.category:process and agent.type:"elastic-agent" and host.os.type:linux and process.name:(ssh or chisel or stunnel or openvpn or wg or wireguard-go) and process.command_line:("*tun*" or "*tap*" or "*socks*" or "*reverse*" or "*client*")
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:process AND agent.type:"elastic-agent" AND host.os.type:linux AND process.name:(ssh OR chisel OR stunnel OR openvpn OR wg OR wireguard-go) AND process.command_line:("*tun*" OR "*tap*" OR "*socks*" OR "*reverse*" OR "*client*") | groupby host.name host.os.type user.name process.name process.parent.name destination.ip destination.port event.action | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line process.executable file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port destination.domain network.transport event.code rule.name
```

## T1095 — Non-Application Layer Protocol

**Tactic:** Command and Control  
**Detection idea:** Raw TCP/ICMP-style tooling or non-standard beacon channels  
**Elastic implementation notes:** ECS field names vary by integration. Start with the KQL below, then tune for your Elastic Agent, Elastic Defend, Windows, System, Sysmon, cloud, and email data streams.

### Query 1
```kql
event.category:network and network.protocol:(icmp or tcp or udp) and process.name:("powershell.exe" or "pwsh.exe" or "nc.exe" or "netcat.exe" or "ncat.exe") and destination.ip:*
```

### Query 2
```kql
event.category:process and process.command_line:("*Test-Connection*" or "*System.Net.Sockets.TcpClient*" or "*nc.exe*" or "*ncat*" or "*ping -t*")
```

**Tuning ideas:** allowlist known admin scripts, software deployment tools, scanners, EDR activity, patch management, and sanctioned cloud apps before alerting.

---

## T1219 — Remote Access Software

**Tactic:** Command and Control  
**Detection idea:** Remote access tools used from endpoints or servers  
**Elastic implementation notes:** ECS field names vary by integration. Start with the KQL below, then tune for your Elastic Agent, Elastic Defend, Windows, System, Sysmon, cloud, and email data streams.

### Query 1
```kql
event.category:process and process.name:("anydesk.exe" or "teamviewer.exe" or "screenconnect.clientservice.exe" or "rustdesk.exe" or "logmein.exe" or "splashtop.exe")
```

### Query 2
```kql
event.category:network and process.name:("anydesk.exe" or "teamviewer.exe" or "rustdesk.exe" or "screenconnect.clientservice.exe") and destination.ip:*
```

**Tuning ideas:** allowlist known admin scripts, software deployment tools, scanners, EDR activity, patch management, and sanctioned cloud apps before alerting.

---

### Query 3 — Security Onion
**Security Onion specific:** Uses Security Onion Zeek SSL/DNS metadata for common remote-access tool infrastructure.

```kql
event.dataset:(dns or ssl) and (dns.question.name:("*anydesk*" or "*teamviewer*" or "*screenconnect*" or "*rustdesk*" or "*logmein*") or tls.server.name:("*anydesk*" or "*teamviewer*" or "*screenconnect*" or "*rustdesk*" or "*logmein*"))
```

**Security Onion Hunt dashboard (OQL):** Uses Security Onion 3.1 Hunt syntax. The filter uses Lucene/OQL boolean operators and adds Hunt-friendly grouping, sorting, and event-table columns.

```oql
event.dataset:(dns OR ssl) AND (dns.question.name:("*anydesk*" OR "*teamviewer*" OR "*screenconnect*" OR "*rustdesk*" OR "*logmein*") OR tls.server.name:("*anydesk*" OR "*teamviewer*" OR "*screenconnect*" OR "*rustdesk*" OR "*logmein*")) | groupby event.dataset source.ip destination.ip destination.port rule.name | sortby @timestamp | table event.module event.dataset source.ip source.port destination.ip destination.port network.transport network.community_id log.id.uid rule.name dns.question.name url.domain tls.server.name http.request.method file.name file.path host.name user.name event.code event.action
```

### Query 4 — Security Onion
**Security Onion specific:** Uses Security Onion Suricata alert data for remote access software signatures.

```kql
event.module:"Suricata" and event.dataset:"alert" and rule.name:("*AnyDesk*" or "*TeamViewer*" or "*ScreenConnect*" or "*RustDesk*" or "*LogMeIn*")
```

**Security Onion Hunt dashboard (OQL):** Uses Security Onion 3.1 Hunt syntax. The filter uses Lucene/OQL boolean operators and adds Hunt-friendly grouping, sorting, and event-table columns.

```oql
event.module:"Suricata" AND event.dataset:"alert" AND rule.name:("*AnyDesk*" OR "*TeamViewer*" OR "*ScreenConnect*" OR "*RustDesk*" OR "*LogMeIn*") | groupby event.dataset source.ip destination.ip destination.port rule.name | sortby @timestamp | table event.module event.dataset source.ip source.port destination.ip destination.port network.transport network.community_id log.id.uid rule.name dns.question.name url.domain tls.server.name http.request.method file.name file.path host.name user.name event.code event.action
```
### Query 5 — Security Onion Windows Elastic Agent
**Security Onion specific:** Uses Elastic Agent telemetry in Security Onion 3.1.0 for Windows hosts. Requires Elastic Agent endpoint, system, Windows, macOS, Linux, or Elastic Defend data streams with ECS host, process, file, registry, authentication, or network fields.

```kql
event.category:(process or network) and agent.type:"elastic-agent" and host.os.type:windows and (process.name:("anydesk.exe" or "teamviewer.exe" or "rustdesk.exe" or "screenconnect.clientservice.exe" or "logmein.exe") or destination.domain:("*anydesk*" or "*teamviewer*" or "*rustdesk*" or "*screenconnect*"))
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:(process OR network) AND agent.type:"elastic-agent" AND host.os.type:windows AND (process.name:("anydesk.exe" OR "teamviewer.exe" OR "rustdesk.exe" OR "screenconnect.clientservice.exe" OR "logmein.exe") OR destination.domain:("*anydesk*" OR "*teamviewer*" OR "*rustdesk*" OR "*screenconnect*")) | groupby host.name host.os.type user.name process.name process.parent.name destination.ip destination.port event.action | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line process.executable file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port destination.domain network.transport event.code rule.name
```
### Query 6 — Security Onion macOS Elastic Agent
**Security Onion specific:** Uses Elastic Agent telemetry in Security Onion 3.1.0 for macOS hosts. Requires Elastic Agent endpoint, system, Windows, macOS, Linux, or Elastic Defend data streams with ECS host, process, file, registry, authentication, or network fields.

```kql
event.category:(process or network) and agent.type:"elastic-agent" and host.os.type:macos and (process.name:(AnyDesk or TeamViewer or RustDesk or ScreenConnect) or destination.domain:("*anydesk*" or "*teamviewer*" or "*rustdesk*" or "*screenconnect*"))
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:(process OR network) AND agent.type:"elastic-agent" AND host.os.type:macos AND (process.name:(AnyDesk OR TeamViewer OR RustDesk OR ScreenConnect) OR destination.domain:("*anydesk*" OR "*teamviewer*" OR "*rustdesk*" OR "*screenconnect*")) | groupby host.name host.os.type user.name process.name process.parent.name destination.ip destination.port event.action | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line process.executable file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port destination.domain network.transport event.code rule.name
```

---

## T1571 — Non-Standard Port

**Tactic:** Command and Control  
**Detection idea:** Protocol and destination-port combinations that do not match expected HTTP, TLS, DNS, SSH, RDP, or SMTP service conventions.  
**Elastic implementation notes:** These filters use ECS-style fields commonly present in Elastic Agent, Elastic Defend, Windows, Linux, macOS, Zeek, and Suricata data streams. Tune command-line patterns and administrative allowlists before production use.

### Query 1 — Security Onion Zeek/Security Onion Network
**Security Onion specific:** Uses Elastic Agent or Security Onion network telemetry in Security Onion 3.1.0. Requires the relevant endpoint, Zeek, Suricata, Windows, Linux, macOS, system, or Elastic Defend data streams with ECS-compatible fields.

```kql
event.dataset:(conn or http or ssl) and destination.port:(8080 or 8443 or 8888 or 4443 or 9443 or 587 or 53 or 22) and source.ip:* and destination.ip:*
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.dataset:(conn OR http OR ssl) AND destination.port:(8080 OR 8443 OR 8888 OR 4443 OR 9443 OR 587 OR 53 OR 22) AND source.ip:* AND destination.ip:* | groupby host.name host.os.type user.name process.name process.parent.name event.action destination.ip destination.port | sortby @timestamp | table @timestamp event.module event.dataset source.ip source.port destination.ip destination.port destination.domain network.transport network.protocol network.community_id log.id.uid rule.name dns.question.name url.domain tls.server.name http.request.method http.request.body.content file.name file.path host.name user.name process.name event.code event.action
```
### Query 2 — Security Onion Zeek/Security Onion Network
**Security Onion specific:** Uses Elastic Agent or Security Onion network telemetry in Security Onion 3.1.0. Requires the relevant endpoint, Zeek, Suricata, Windows, Linux, macOS, system, or Elastic Defend data streams with ECS-compatible fields.

```kql
event.dataset:http and destination.port:(443 or 8443 or 9443 or 4443) and http.request.method:* and source.ip:* and destination.ip:*
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.dataset:http AND destination.port:(443 OR 8443 OR 9443 OR 4443) AND http.request.method:* AND source.ip:* AND destination.ip:* | groupby host.name host.os.type user.name process.name process.parent.name event.action destination.ip destination.port | sortby @timestamp | table @timestamp event.module event.dataset source.ip source.port destination.ip destination.port destination.domain network.transport network.protocol network.community_id log.id.uid rule.name dns.question.name url.domain tls.server.name http.request.method http.request.body.content file.name file.path host.name user.name process.name event.code event.action
```
### Query 3 — Security Onion Elastic Agent Network
**Security Onion specific:** Uses Elastic Agent or Security Onion network telemetry in Security Onion 3.1.0. Requires the relevant endpoint, Zeek, Suricata, Windows, Linux, macOS, system, or Elastic Defend data streams with ECS-compatible fields.

```kql
event.category:network and agent.type:"elastic-agent" and destination.ip:* and ((network.protocol:http and not destination.port:(80 or 8080 or 8000)) or (network.protocol:tls and not destination.port:(443 or 8443)) or (network.protocol:ssh and not destination.port:22))
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:network AND agent.type:"elastic-agent" AND destination.ip:* AND ((network.protocol:http AND NOT destination.port:(80 OR 8080 OR 8000)) OR (network.protocol:tls AND NOT destination.port:(443 OR 8443)) OR (network.protocol:ssh AND NOT destination.port:22)) | groupby host.name host.os.type user.name process.name process.parent.name event.action destination.ip destination.port | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line process.executable file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port destination.domain network.transport network.community_id event.code rule.name
```

**Tuning ideas:** allowlist known administrators, software deployment tools, EDR activity, inventory systems, vulnerability scanners, patching tools, and sanctioned management workflows before alerting.

---

## T1132 — Data Encoding

**Tactic:** Command and Control  
**Detection idea:** Encoded C2 content in command lines, URLs, DNS labels, HTTP bodies, or suspicious binary-to-text payload patterns.  
**Elastic implementation notes:** These filters use ECS-style fields commonly present in Elastic Agent, Elastic Defend, Windows, Linux, macOS, Zeek, and Suricata data streams. Tune command-line patterns and administrative allowlists before production use.

### Query 1 — Security Onion Windows Elastic Agent
**Security Onion specific:** Uses Elastic Agent or Security Onion network telemetry in Security Onion 3.1.0. Requires the relevant endpoint, Zeek, Suricata, Windows, Linux, macOS, system, or Elastic Defend data streams with ECS-compatible fields.

```kql
event.category:process and agent.type:"elastic-agent" and host.os.type:windows and process.name:("powershell.exe" or "pwsh.exe" or "certutil.exe" or "cmd.exe") and process.command_line:("*-EncodedCommand*" or "*FromBase64String*" or "*ToBase64String*" or "*certutil* -decode*" or "*certutil* -encode*")
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:process AND agent.type:"elastic-agent" AND host.os.type:windows AND process.name:("powershell.exe" OR "pwsh.exe" OR "certutil.exe" OR "cmd.exe") AND process.command_line:("*-EncodedCommand*" OR "*FromBase64String*" OR "*ToBase64String*" OR "*certutil* -decode*" OR "*certutil* -encode*") | groupby host.name host.os.type user.name process.name process.parent.name event.action destination.ip destination.port | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line process.executable file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port destination.domain network.transport network.community_id event.code rule.name
```
### Query 2 — Security Onion Linux/macOS Elastic Agent
**Security Onion specific:** Uses Elastic Agent or Security Onion network telemetry in Security Onion 3.1.0. Requires the relevant endpoint, Zeek, Suricata, Windows, Linux, macOS, system, or Elastic Defend data streams with ECS-compatible fields.

```kql
event.category:process and agent.type:"elastic-agent" and host.os.type:(linux or macos) and process.name:(base64 or openssl or python or python3 or perl or ruby) and process.command_line:("*base64*" or "*-d*" or "*decode*" or "*encode*" or "*b64decode*" or "*b64encode*")
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:process AND agent.type:"elastic-agent" AND host.os.type:(linux OR macos) AND process.name:(base64 OR openssl OR python OR python3 OR perl OR ruby) AND process.command_line:("*base64*" OR "*-d*" OR "*decode*" OR "*encode*" OR "*b64decode*" OR "*b64encode*") | groupby host.name host.os.type user.name process.name process.parent.name event.action destination.ip destination.port | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line process.executable file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port destination.domain network.transport network.community_id event.code rule.name
```
### Query 3 — Security Onion Zeek/Security Onion Network
**Security Onion specific:** Uses Elastic Agent or Security Onion network telemetry in Security Onion 3.1.0. Requires the relevant endpoint, Zeek, Suricata, Windows, Linux, macOS, system, or Elastic Defend data streams with ECS-compatible fields.

```kql
event.dataset:(dns or http) and (dns.question.name:("*==*" or "*-*-*-*" or "*[0-9a-f][0-9a-f][0-9a-f]*") or url.query:("*==*" or "*base64*" or "*b64*" or "*%3D%3D*") or http.request.body.content:("*==*" or "*base64*" or "*b64*"))
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.dataset:(dns OR http) AND (dns.question.name:("*==*" OR "*-*-*-*" OR "*[0-9a-f][0-9a-f][0-9a-f]*") OR url.query:("*==*" OR "*base64*" OR "*b64*" OR "*%3D%3D*") OR http.request.body.content:("*==*" OR "*base64*" OR "*b64*")) | groupby host.name host.os.type user.name process.name process.parent.name event.action destination.ip destination.port | sortby @timestamp | table @timestamp event.module event.dataset source.ip source.port destination.ip destination.port destination.domain network.transport network.protocol network.community_id log.id.uid rule.name dns.question.name url.domain tls.server.name http.request.method http.request.body.content file.name file.path host.name user.name process.name event.code event.action
```

**Tuning ideas:** allowlist known administrators, software deployment tools, EDR activity, inventory systems, vulnerability scanners, patching tools, and sanctioned management workflows before alerting.

---

## T1071.004 — Application Layer Protocol: DNS

**Tactic:** Command and Control  
**Detection idea:** DNS-based C2 indicators such as unusual query types, dynamic DNS domains, or suspicious high-volume DNS clients.  
**Elastic implementation notes:** These filters use ECS-style fields commonly present in Elastic Agent, Elastic Defend, Windows, Linux, macOS, Zeek, Suricata, cloud, and SaaS data streams. Tune command-line patterns, data views, and administrative allowlists before production use.

### Query 1 — Security Onion Zeek/Security Onion Network
**Security Onion specific:** Uses Elastic Agent or Security Onion telemetry in Security Onion 3.1.0. Requires the relevant endpoint, Zeek, Suricata, cloud, SaaS, Windows, Linux, macOS, system, or Elastic Defend data streams with ECS-compatible fields.

```kql
event.dataset:dns and dns.question.type:(TXT or NULL or CNAME) and source.ip:* and dns.question.name:*
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.dataset:dns AND dns.question.type:(TXT OR NULL OR CNAME) AND source.ip:* AND dns.question.name:* | groupby host.name host.os.type user.name process.name process.parent.name event.action destination.ip destination.port | sortby @timestamp | table @timestamp event.module event.dataset source.ip source.port destination.ip destination.port destination.domain network.transport network.protocol network.community_id log.id.uid rule.name dns.question.name url.domain tls.server.name http.request.method http.request.body.content file.name file.path host.name user.name process.name event.code event.action
```
### Query 2 — Security Onion Zeek/Security Onion Network
**Security Onion specific:** Uses Elastic Agent or Security Onion telemetry in Security Onion 3.1.0. Requires the relevant endpoint, Zeek, Suricata, cloud, SaaS, Windows, Linux, macOS, system, or Elastic Defend data streams with ECS-compatible fields.

```kql
event.dataset:dns and dns.question.name:("*.duckdns.org" or "*.ddns.net" or "*.no-ip.org" or "*.dynu.net" or "*.hopto.org") and source.ip:*
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.dataset:dns AND dns.question.name:("*.duckdns.org" OR "*.ddns.net" OR "*.no-ip.org" OR "*.dynu.net" OR "*.hopto.org") AND source.ip:* | groupby host.name host.os.type user.name process.name process.parent.name event.action destination.ip destination.port | sortby @timestamp | table @timestamp event.module event.dataset source.ip source.port destination.ip destination.port destination.domain network.transport network.protocol network.community_id log.id.uid rule.name dns.question.name url.domain tls.server.name http.request.method http.request.body.content file.name file.path host.name user.name process.name event.code event.action
```

**Tuning ideas:** allowlist known administrators, software deployment tools, EDR activity, backup agents, inventory systems, vulnerability scanners, patching tools, and sanctioned management workflows before alerting.

---

## T1568.001 — Dynamic Resolution: Fast Flux DNS

**Tactic:** Command and Control  
**Detection idea:** Fast-flux candidates using dynamic DNS, repeated DNS answers, or short-lived rotating destinations.  
**Elastic implementation notes:** These filters use ECS-style fields commonly present in Elastic Agent, Elastic Defend, Windows, Linux, macOS, Zeek, Suricata, cloud, and SaaS data streams. Tune command-line patterns, data views, and administrative allowlists before production use.

### Query 1 — Security Onion Zeek/Security Onion Network
**Security Onion specific:** Uses Elastic Agent or Security Onion telemetry in Security Onion 3.1.0. Requires the relevant endpoint, Zeek, Suricata, cloud, SaaS, Windows, Linux, macOS, system, or Elastic Defend data streams with ECS-compatible fields.

```kql
event.dataset:dns and dns.answers.data:* and dns.question.name:("*.duckdns.org" or "*.ddns.net" or "*.no-ip.org" or "*.dynu.net")
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.dataset:dns AND dns.answers.data:* AND dns.question.name:("*.duckdns.org" OR "*.ddns.net" OR "*.no-ip.org" OR "*.dynu.net") | groupby host.name host.os.type user.name process.name process.parent.name event.action destination.ip destination.port | sortby @timestamp | table @timestamp event.module event.dataset source.ip source.port destination.ip destination.port destination.domain network.transport network.protocol network.community_id log.id.uid rule.name dns.question.name url.domain tls.server.name http.request.method http.request.body.content file.name file.path host.name user.name process.name event.code event.action
```
### Query 2 — Security Onion Zeek/Security Onion Network
**Security Onion specific:** Uses Elastic Agent or Security Onion telemetry in Security Onion 3.1.0. Requires the relevant endpoint, Zeek, Suricata, cloud, SaaS, Windows, Linux, macOS, system, or Elastic Defend data streams with ECS-compatible fields.

```kql
event.dataset:dns and dns.question.name:* and dns.answers.data:* and source.ip:*
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.dataset:dns AND dns.question.name:* AND dns.answers.data:* AND source.ip:* | groupby host.name host.os.type user.name process.name process.parent.name event.action destination.ip destination.port | sortby @timestamp | table @timestamp event.module event.dataset source.ip source.port destination.ip destination.port destination.domain network.transport network.protocol network.community_id log.id.uid rule.name dns.question.name url.domain tls.server.name http.request.method http.request.body.content file.name file.path host.name user.name process.name event.code event.action
```

**Tuning ideas:** allowlist known administrators, software deployment tools, EDR activity, backup agents, inventory systems, vulnerability scanners, patching tools, and sanctioned management workflows before alerting.

---

## T1568.002 — Dynamic Resolution: Domain Generation Algorithms

**Tactic:** Command and Control  
**Detection idea:** DGA-like DNS activity using random-looking labels, uncommon TLDs, or automated lookup patterns.  
**Elastic implementation notes:** These filters use ECS-style fields commonly present in Elastic Agent, Elastic Defend, Windows, Linux, macOS, Zeek, Suricata, cloud, and SaaS data streams. Tune command-line patterns, data views, and administrative allowlists before production use.

### Query 1 — Security Onion Zeek/Security Onion Network
**Security Onion specific:** Uses Elastic Agent or Security Onion telemetry in Security Onion 3.1.0. Requires the relevant endpoint, Zeek, Suricata, cloud, SaaS, Windows, Linux, macOS, system, or Elastic Defend data streams with ECS-compatible fields.

```kql
event.dataset:dns and dns.question.name:("*.top" or "*.xyz" or "*.club" or "*.icu" or "*.monster" or "*.click") and source.ip:*
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.dataset:dns AND dns.question.name:("*.top" OR "*.xyz" OR "*.club" OR "*.icu" OR "*.monster" OR "*.click") AND source.ip:* | groupby host.name host.os.type user.name process.name process.parent.name event.action destination.ip destination.port | sortby @timestamp | table @timestamp event.module event.dataset source.ip source.port destination.ip destination.port destination.domain network.transport network.protocol network.community_id log.id.uid rule.name dns.question.name url.domain tls.server.name http.request.method http.request.body.content file.name file.path host.name user.name process.name event.code event.action
```
### Query 2 — Security Onion Zeek/Security Onion Network
**Security Onion specific:** Uses Elastic Agent or Security Onion telemetry in Security Onion 3.1.0. Requires the relevant endpoint, Zeek, Suricata, cloud, SaaS, Windows, Linux, macOS, system, or Elastic Defend data streams with ECS-compatible fields.

```kql
event.dataset:dns and dns.question.name:("*0*1*2*" or "*q* x*" or "*z* q*" or "*j* k*") and source.ip:*
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.dataset:dns AND dns.question.name:("*0*1*2*" OR "*q* x*" OR "*z* q*" OR "*j* k*") AND source.ip:* | groupby host.name host.os.type user.name process.name process.parent.name event.action destination.ip destination.port | sortby @timestamp | table @timestamp event.module event.dataset source.ip source.port destination.ip destination.port destination.domain network.transport network.protocol network.community_id log.id.uid rule.name dns.question.name url.domain tls.server.name http.request.method http.request.body.content file.name file.path host.name user.name process.name event.code event.action
```

**Tuning ideas:** allowlist known administrators, software deployment tools, EDR activity, backup agents, inventory systems, vulnerability scanners, patching tools, and sanctioned management workflows before alerting.

---

## T1132.001 — Data Encoding: Standard Encoding

**Tactic:** Command and Control  
**Detection idea:** Standard Base64, hex, URL, or MIME encoding patterns in process and network C2 artifacts.  
**Elastic implementation notes:** These filters use ECS-style fields commonly present in Elastic Agent, Elastic Defend, Windows, Linux, macOS, Zeek, Suricata, cloud, and SaaS data streams. Tune command-line patterns, data views, and administrative allowlists before production use.

### Query 1 — Security Onion Windows Elastic Agent
**Security Onion specific:** Uses Elastic Agent or Security Onion telemetry in Security Onion 3.1.0. Requires the relevant endpoint, Zeek, Suricata, cloud, SaaS, Windows, Linux, macOS, system, or Elastic Defend data streams with ECS-compatible fields.

```kql
event.category:process and agent.type:"elastic-agent" and host.os.type:windows and process.command_line:("*FromBase64String*" or "*ToBase64String*" or "*-EncodedCommand*" or "*certutil* -decode*" or "*base64*")
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:process AND agent.type:"elastic-agent" AND host.os.type:windows AND process.command_line:("*FromBase64String*" OR "*ToBase64String*" OR "*-EncodedCommand*" OR "*certutil* -decode*" OR "*base64*") | groupby host.name host.os.type user.name process.name process.parent.name event.action destination.ip destination.port | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line process.executable file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port destination.domain network.transport network.community_id event.code rule.name
```
### Query 2 — Security Onion Zeek/Security Onion Network
**Security Onion specific:** Uses Elastic Agent or Security Onion telemetry in Security Onion 3.1.0. Requires the relevant endpoint, Zeek, Suricata, cloud, SaaS, Windows, Linux, macOS, system, or Elastic Defend data streams with ECS-compatible fields.

```kql
event.dataset:(http or dns) and (url.query:("*%3D%3D*" or "*base64*" or "*b64*") or dns.question.name:("*==*" or "*base64*"))
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.dataset:(http OR dns) AND (url.query:("*%3D%3D*" OR "*base64*" OR "*b64*") OR dns.question.name:("*==*" OR "*base64*")) | groupby host.name host.os.type user.name process.name process.parent.name event.action destination.ip destination.port | sortby @timestamp | table @timestamp event.module event.dataset source.ip source.port destination.ip destination.port destination.domain network.transport network.protocol network.community_id log.id.uid rule.name dns.question.name url.domain tls.server.name http.request.method http.request.body.content file.name file.path host.name user.name process.name event.code event.action
```

**Tuning ideas:** allowlist known administrators, software deployment tools, EDR activity, backup agents, inventory systems, vulnerability scanners, patching tools, and sanctioned management workflows before alerting.

---

## T1132.002 — Data Encoding: Non-Standard Encoding

**Tactic:** Command and Control  
**Detection idea:** Custom encoding and uncommon binary-to-text transformations used around C2 payloads.  
**Elastic implementation notes:** These filters use ECS-style fields commonly present in Elastic Agent, Elastic Defend, Windows, Linux, macOS, Zeek, Suricata, cloud, and SaaS data streams. Tune command-line patterns, data views, and administrative allowlists before production use.

### Query 1 — Security Onion Linux/macOS Elastic Agent
**Security Onion specific:** Uses Elastic Agent or Security Onion telemetry in Security Onion 3.1.0. Requires the relevant endpoint, Zeek, Suricata, cloud, SaaS, Windows, Linux, macOS, system, or Elastic Defend data streams with ECS-compatible fields.

```kql
event.category:process and agent.type:"elastic-agent" and host.os.type:(linux or macos) and process.name:(python or python3 or perl or ruby or openssl) and process.command_line:("*xor*" or "*rot13*" or "*bytearray*" or "*hexlify*" or "*unhexlify*")
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:process AND agent.type:"elastic-agent" AND host.os.type:(linux OR macos) AND process.name:(python OR python3 OR perl OR ruby OR openssl) AND process.command_line:("*xor*" OR "*rot13*" OR "*bytearray*" OR "*hexlify*" OR "*unhexlify*") | groupby host.name host.os.type user.name process.name process.parent.name event.action destination.ip destination.port | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line process.executable file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port destination.domain network.transport network.community_id event.code rule.name
```
### Query 2 — Security Onion Windows Elastic Agent
**Security Onion specific:** Uses Elastic Agent or Security Onion telemetry in Security Onion 3.1.0. Requires the relevant endpoint, Zeek, Suricata, cloud, SaaS, Windows, Linux, macOS, system, or Elastic Defend data streams with ECS-compatible fields.

```kql
event.category:process and agent.type:"elastic-agent" and host.os.type:windows and process.name:("powershell.exe" or "pwsh.exe" or "python.exe") and process.command_line:("*bxor*" or "*ToCharArray*" or "*[convert]::ToString*" or "*FromHexString*" or "*rot13*")
```

**Security Onion Hunt dashboard (OQL):** OQL version for Security Onion 3.1.0 Hunt using Lucene-style boolean operators plus Hunt-friendly grouping, sorting, and table columns.

```oql
event.category:process AND agent.type:"elastic-agent" AND host.os.type:windows AND process.name:("powershell.exe" OR "pwsh.exe" OR "python.exe") AND process.command_line:("*bxor*" OR "*ToCharArray*" OR "*[convert]::ToString*" OR "*FromHexString*" OR "*rot13*") | groupby host.name host.os.type user.name process.name process.parent.name event.action destination.ip destination.port | sortby @timestamp | table @timestamp event.category event.action event.dataset agent.type host.name host.os.type user.name process.name process.parent.name process.command_line process.executable file.path file.name file.extension registry.path registry.value source.ip source.port destination.ip destination.port destination.domain network.transport network.community_id event.code rule.name
```

**Tuning ideas:** allowlist known administrators, software deployment tools, EDR activity, backup agents, inventory systems, vulnerability scanners, patching tools, and sanctioned management workflows before alerting.

