# Master Elastic KQL Index

MITRE ATT&CK Enterprise coverage mapped to hunting-grade Elastic Kibana Query Language (**Elastic KQL**) queries using ECS-style fields.

**Docs:** [Elastic KQL documentation](https://www.elastic.co/docs/reference/query-languages/kql)  
**Baseline:** MITRE ATT&CK Enterprise via `attack.mitre.org` / MITRE CTI STIX, pulled 2026-06-01  
**Coverage:** 196 technique sections / 540 KQL query blocks / 338 Security Onion Hunt OQL query blocks  
**Data views:** `logs-*`, `endpoint-*`, `logs-endpoint.events.*`, `logs-windows.*`, `logs-system.*`, `logs-o365.*`, `logs-azure.*`, `logs-aws.*`, `logs-zeek-so*`, `logs-suricata-so*`

## Use Notes

- These filters are for Kibana Discover, Lens, Timeline, and Elastic Security rules.
- Elastic KQL filters data only; use Elastic rule features, EQL, ES|QL, threshold rules, or exceptions for correlation and aggregation.
- Security Onion Hunt dashboard queries use Onion Query Language (**OQL**) for Security Onion 3.1.0. OQL starts with Lucene syntax and can add `groupby`, `sortby`, and `table` segments.
- ECS fields vary by integration. Map missing fields to local equivalents before enabling detections.
- Multi-tactic techniques are intentionally duplicated under each relevant tactic.
- Queries marked **Security Onion specific** use Security Onion data streams and parsed fields from Zeek, Suricata, and Fleet-managed Elastic Agent integrations such as Elastic Defend, Windows, System, Osquery Manager, and Custom Logs.
- Recent ATT&CK replacements in this corpus: `T1562.001` -> `T1685`, `T1562.004` -> `T1686`, `T1070.001` -> `T1685.005`.

## KQL Quick Reference

- Exact value: `field.name:"exact value"`
- Multiple values: `field.name:("value1" or "value2" or wildcard*)`
- Exists: `field.name:*`
- Boolean logic: `and`, `or`, `not`
- Wildcard hunts should use unquoted wildcard terms, for example `process.command_line:*EncodedCommand*`. Escape spaces and special characters inside wildcard terms, for example `rule.name:*Command\ and\ Control*` or `process.command_line:*jndi\:*`.
- Leading wildcard hunts such as `process.command_line:*EncodedCommand*` depend on Kibana's `query:allowLeadingWildcards` advanced setting. Verify it is enabled in the target Kibana space; if disabled, rewrite leading wildcard clauses as prefix, exact-match, normalized-field, or rule-exception logic.
- Elastic's KQL language reference says leading wildcards are disallowed by default for performance reasons, while the current Kibana advanced settings reference lists `query:allowLeadingWildcards` as a boolean setting with default `true`. Treat leading wildcard support as an environment compatibility setting.
- To check this in Security Onion, open **Security Onion Console**, go to **Kibana**, then open **Stack Management** -> **Advanced Settings**. Search for `query:allowLeadingWildcards` and confirm **Allow leading wildcards in query** is enabled. In Kibana, this is a **Space Settings** value, so verify it in each Kibana space where these KQL queries will be used.
- Windows path wildcard hunts should use unquoted wildcard terms with escaped special characters, for example `file.path:C\:\\Windows\\System32\\Tasks\\*`
- Set time ranges in the Kibana UI, or use date math such as `@timestamp >= now-24h` where supported.

## Security Onion Hunt OQL Quick Reference

- Official docs: [Security Onion Dashboards/OQL documentation](https://docs.securityonion.net/en/3/main/dashboards/)
- Boolean logic: `AND`, `OR`, `NOT`
- Exact value: `field.name:"exact value"`
- Multiple values: `field.name:("value1" OR "value2" OR wildcard*)`
- Exists: `field.name:*`
- Aggregation: `| groupby source.ip destination.ip destination.port`
- Sorting: `| sortby @timestamp`
- Event columns: `| table event.dataset source.ip destination.ip destination.port rule.name`

## Common ECS Fields

- Process: `event.category:process`, `process.name`, `process.executable`, `process.command_line`, `process.parent.name`, `process.parent.command_line`
- File: `event.category:file`, `file.name`, `file.path`, `file.extension`, `file.hash.sha256`, `file.directory`, `event.action`
- Registry: `event.category:registry`, `registry.path`, `registry.key`, `registry.value`, `registry.data.strings`
- Network: `event.category:network`, `source.ip`, `destination.ip`, `destination.port`, `destination.domain`, `network.protocol`, `process.name`
- Auth/IAM: `event.category:authentication`, `event.category:iam`, `event.outcome`, `user.name`, `source.ip`, `event.action`, `event.code`, `cloud.provider`
- Email/SaaS: `event.category:email`, `email.subject`, `email.from.address`, `email.attachments.file.*`, `event.dataset`
- Security Onion: `event.module:Suricata`, `event.dataset:alert`, `event.dataset:conn`, `event.dataset:dns`, `event.dataset:http`, `event.dataset:ssl`, `event.dataset:files`, `rule.name`, `network.community_id`, `log.id.uid`

## Tactic Modules

| Tactic | Module | Sections | Queries |
| --- | --- | ---: | ---: |
| TA0043 Reconnaissance | [SO_TA0043_Reconnaissance.md](SO_TA0043_Reconnaissance.md) | 1 | 4 |
| TA0042 Resource Development | [SO_TA0042_Resource_Development.md](SO_TA0042_Resource_Development.md) | 0 | 0 |
| TA0001 Initial Access | [SO_TA0001_Initial_Access.md](SO_TA0001_Initial_Access.md) | 6 | 18 |
| TA0002 Execution | [SO_TA0002_Execution.md](SO_TA0002_Execution.md) | 20 | 48 |
| TA0003 Persistence | [SO_TA0003_Persistence.md](SO_TA0003_Persistence.md) | 32 | 63 |
| TA0004 Privilege Escalation | [SO_TA0004_Privilege_Escalation.md](SO_TA0004_Privilege_Escalation.md) | 6 | 17 |
| TA0005 Defense Evasion | [SO_TA0005_Defense_Evasion.md](SO_TA0005_Defense_Evasion.md) | 34 | 82 |
| TA0006 Credential Access | [SO_TA0006_Credential_Access.md](SO_TA0006_Credential_Access.md) | 24 | 62 |
| TA0007 Discovery | [SO_TA0007_Discovery.md](SO_TA0007_Discovery.md) | 29 | 88 |
| TA0008 Lateral Movement | [SO_TA0008_Lateral_Movement.md](SO_TA0008_Lateral_Movement.md) | 6 | 29 |
| TA0009 Collection | [SO_TA0009_Collection.md](SO_TA0009_Collection.md) | 12 | 34 |
| TA0011 Command and Control | [SO_TA0011_Command_and_Control.md](SO_TA0011_Command_and_Control.md) | 13 | 44 |
| TA0010 Exfiltration | [SO_TA0010_Exfiltration.md](SO_TA0010_Exfiltration.md) | 6 | 25 |
| TA0040 Impact | [SO_TA0040_Impact.md](SO_TA0040_Impact.md) | 7 | 26 |





## Project Metrics

| Metric | Count |
| --- | ---: |
| ATT&CK tactics covered | 14 |
| ATT&CK technique sections covered | 196 |
| Detection procedures documented | 540 |
| Elastic KQL queries | 540 |
| Security Onion-specific KQL queries | 338 |
| Security Onion Hunt OQL queries | 338 |

**Procedure definition:** one documented detection procedure equals one fenced Elastic KQL query block in the tactic modules.

## Coverage Checklist

Unchecked boxes are for local validation and enablement tracking.

### TA0043 - Reconnaissance

- [ ] [T1595.002 — Vulnerability Scanning](SO_TA0043_Reconnaissance.md#t1595.002-vulnerability-scanning)

### TA0042 - Resource Development

- [ ] No current coverage.

### TA0001 - Initial Access

- [ ] [T1566.001 — Phishing: Spearphishing Attachment](SO_TA0001_Initial_Access.md#t1566.001-phishing-spearphishing-attachment)
- [ ] [T1190 — Exploit Public-Facing Application](SO_TA0001_Initial_Access.md#t1190-exploit-public-facing-application)
- [ ] [T1133 — External Remote Services](SO_TA0001_Initial_Access.md#t1133-external-remote-services)
- [ ] [T1566.002 — Phishing: Spearphishing Link](SO_TA0001_Initial_Access.md#t1566.002-phishing-spearphishing-link)
- [ ] [T1566.003 — Phishing: Spearphishing via Service](SO_TA0001_Initial_Access.md#t1566.003-phishing-spearphishing-via-service)
- [ ] [T1204.002 — User Execution: Malicious File](SO_TA0001_Initial_Access.md#t1204.002-user-execution-malicious-file)

### TA0002 - Execution

- [ ] [T1059.001 — PowerShell](SO_TA0002_Execution.md#t1059.001-powershell)
- [ ] [T1059.003 — Windows Command Shell](SO_TA0002_Execution.md#t1059.003-windows-command-shell)
- [ ] [T1047 — Windows Management Instrumentation](SO_TA0002_Execution.md#t1047-windows-management-instrumentation)
- [ ] [T1204.002 — User Execution: Malicious File](SO_TA0002_Execution.md#t1204.002-user-execution-malicious-file)
- [ ] [T1059.005 — Command and Scripting Interpreter: Visual Basic](SO_TA0002_Execution.md#t1059.005-command-and-scripting-interpreter-visual-basic)
- [ ] [T1059.006 — Command and Scripting Interpreter: Python](SO_TA0002_Execution.md#t1059.006-command-and-scripting-interpreter-python)
- [ ] [T1059.007 — Command and Scripting Interpreter: JavaScript](SO_TA0002_Execution.md#t1059.007-command-and-scripting-interpreter-javascript)
- [ ] [T1203 — Exploitation for Client Execution](SO_TA0002_Execution.md#t1203-exploitation-for-client-execution)
- [ ] [T1059.004 — Command and Scripting Interpreter: Unix Shell](SO_TA0002_Execution.md#t1059.004-command-and-scripting-interpreter-unix-shell)
- [ ] [T1059.002 — Command and Scripting Interpreter: AppleScript](SO_TA0002_Execution.md#t1059.002-command-and-scripting-interpreter-applescript)
- [ ] [T1106 — Native API](SO_TA0002_Execution.md#t1106-native-api)
- [ ] [T1127.001 — Trusted Developer Utilities Proxy Execution: MSBuild](SO_TA0002_Execution.md#t1127.001-trusted-developer-utilities-proxy-execution-msbuild)
- [ ] [T1218.007 — System Binary Proxy Execution: Msiexec](SO_TA0002_Execution.md#t1218.007-system-binary-proxy-execution-msiexec)
- [ ] [T1059.008 — Command and Scripting Interpreter: Network Device CLI](SO_TA0002_Execution.md#t1059.008-command-and-scripting-interpreter-network-device-cli)
- [ ] [T1197 — BITS Jobs](SO_TA0002_Execution.md#t1197-bits-jobs)
- [ ] [T1129 — Shared Modules](SO_TA0002_Execution.md#t1129-shared-modules)
- [ ] [T1559.001 — Inter-Process Communication: Component Object Model](SO_TA0002_Execution.md#t1559.001-inter-process-communication-component-object-model)
- [ ] [T1559.002 — Inter-Process Communication: Dynamic Data Exchange](SO_TA0002_Execution.md#t1559.002-inter-process-communication-dynamic-data-exchange)
- [ ] [T1218.004 — System Binary Proxy Execution: InstallUtil](SO_TA0002_Execution.md#t1218.004-system-binary-proxy-execution-installutil)
- [ ] [T1218.013 — System Binary Proxy Execution: Mavinject](SO_TA0002_Execution.md#t1218.013-system-binary-proxy-execution-mavinject)

### TA0003 - Persistence

- [ ] [T1053.005 — Scheduled Task / Job: Scheduled Task](SO_TA0003_Persistence.md#t1053.005-scheduled-task-job-scheduled-task)
- [ ] [T1547.001 — Registry Run Keys / Startup Folder](SO_TA0003_Persistence.md#t1547.001-registry-run-keys-startup-folder)
- [ ] [T1543.003 — Windows Service](SO_TA0003_Persistence.md#t1543.003-windows-service)
- [ ] [T1078 — Valid Accounts](SO_TA0003_Persistence.md#t1078-valid-accounts)
- [ ] [T1098 — Account Manipulation](SO_TA0003_Persistence.md#t1098-account-manipulation)
- [ ] [T1136.003 — Create Account: Cloud Account](SO_TA0003_Persistence.md#t1136.003-create-account-cloud-account)
- [ ] [T1546.003 — Event Triggered Execution: Windows Management Instrumentation Event Subscription](SO_TA0003_Persistence.md#t1546.003-event-triggered-execution-windows-management-instrumentation-event-subscription)
- [ ] [T1505.003 — Server Software Component: Web Shell](SO_TA0003_Persistence.md#t1505.003-server-software-component-web-shell)
- [ ] [T1136.001 — Create Account: Local Account](SO_TA0003_Persistence.md#t1136.001-create-account-local-account)
- [ ] [T1136.002 — Create Account: Domain Account](SO_TA0003_Persistence.md#t1136.002-create-account-domain-account)
- [ ] [T1547.009 — Boot or Logon Autostart Execution: Shortcut Modification](SO_TA0003_Persistence.md#t1547.009-boot-or-logon-autostart-execution-shortcut-modification)
- [ ] [T1053.003 — Scheduled Task/Job: Cron](SO_TA0003_Persistence.md#t1053.003-scheduled-taskjob-cron)
- [ ] [T1543.002 — Create or Modify System Process: Systemd Service](SO_TA0003_Persistence.md#t1543.002-create-or-modify-system-process-systemd-service)
- [ ] [T1543.001 / T1543.004 — Create or Modify System Process: Launch Agent / Launch Daemon](SO_TA0003_Persistence.md#t1543.001-t1543.004-create-or-modify-system-process-launch-agent-launch-daemon)
- [ ] [T1037.004 — Boot or Logon Initialization Scripts: RC Scripts](SO_TA0003_Persistence.md#t1037.004-boot-or-logon-initialization-scripts-rc-scripts)
- [ ] [T1547.006 — Boot or Logon Autostart Execution: Kernel Modules and Extensions](SO_TA0003_Persistence.md#t1547.006-boot-or-logon-autostart-execution-kernel-modules-and-extensions)
- [ ] [T1037.002 — Boot or Logon Initialization Scripts: Login Hook](SO_TA0003_Persistence.md#t1037.002-boot-or-logon-initialization-scripts-login-hook)
- [ ] [T1547.011 — Boot or Logon Autostart Execution: Plist Modification](SO_TA0003_Persistence.md#t1547.011-boot-or-logon-autostart-execution-plist-modification)
- [ ] [T1546.004 — Event Triggered Execution: Unix Shell Configuration Modification](SO_TA0003_Persistence.md#t1546.004-event-triggered-execution-unix-shell-configuration-modification)
- [ ] [T1546.016 — Event Triggered Execution: Installer Packages](SO_TA0003_Persistence.md#t1546.016-event-triggered-execution-installer-packages)
- [ ] [T1546.011 — Event Triggered Execution: Application Shimming](SO_TA0003_Persistence.md#t1546.011-event-triggered-execution-application-shimming)
- [ ] [T1546.008 — Event Triggered Execution: Accessibility Features](SO_TA0003_Persistence.md#t1546.008-event-triggered-execution-accessibility-features)
- [ ] [T1546.012 — Event Triggered Execution: Image File Execution Options Injection](SO_TA0003_Persistence.md#t1546.012-event-triggered-execution-image-file-execution-options-injection)
- [ ] [T1053.006 — Scheduled Task/Job: Systemd Timers](SO_TA0003_Persistence.md#t1053.006-scheduled-taskjob-systemd-timers)
- [ ] [T1053.002 — Scheduled Task/Job: At](SO_TA0003_Persistence.md#t1053.002-scheduled-taskjob-at)
- [ ] [T1546.014 — Event Triggered Execution: Emond](SO_TA0003_Persistence.md#t1546.014-event-triggered-execution-emond)
- [ ] [T1547.015 — Boot or Logon Autostart Execution: Login Items](SO_TA0003_Persistence.md#t1547.015-boot-or-logon-autostart-execution-login-items)
- [ ] [T1197 — BITS Jobs](SO_TA0003_Persistence.md#t1197-bits-jobs)
- [ ] [T1176 — Software Extensions](SO_TA0003_Persistence.md#t1176-software-extensions)
- [ ] [T1546.013 — Event Triggered Execution: PowerShell Profile](SO_TA0003_Persistence.md#t1546.013-event-triggered-execution-powershell-profile)
- [ ] [T1547.014 — Boot or Logon Autostart Execution: Active Setup](SO_TA0003_Persistence.md#t1547.014-boot-or-logon-autostart-execution-active-setup)
- [ ] [T1137 — Office Application Startup](SO_TA0003_Persistence.md#t1137-office-application-startup)

### TA0004 - Privilege Escalation

- [ ] [T1098 — Account Manipulation](SO_TA0004_Privilege_Escalation.md#t1098-account-manipulation)
- [ ] [T1548.002 — Abuse Elevation Control Mechanism: Bypass User Account Control](SO_TA0004_Privilege_Escalation.md#t1548.002-abuse-elevation-control-mechanism-bypass-user-account-control)
- [ ] [T1068 — Exploitation for Privilege Escalation](SO_TA0004_Privilege_Escalation.md#t1068-exploitation-for-privilege-escalation)
- [ ] [T1134.001 — Access Token Manipulation: Token Impersonation/Theft](SO_TA0004_Privilege_Escalation.md#t1134.001-access-token-manipulation-token-impersonationtheft)
- [ ] [T1548.001 — Abuse Elevation Control Mechanism: Setuid and Setgid](SO_TA0004_Privilege_Escalation.md#t1548.001-abuse-elevation-control-mechanism-setuid-and-setgid)
- [ ] [T1548.003 — Abuse Elevation Control Mechanism: Sudo and Sudo Caching](SO_TA0004_Privilege_Escalation.md#t1548.003-abuse-elevation-control-mechanism-sudo-and-sudo-caching)

### TA0005 - Defense Evasion

- [ ] [T1027 / T1027.010 — Obfuscated Files or Information / Command Obfuscation](SO_TA0005_Defense_Evasion.md#t1027-t1027.010-obfuscated-files-or-information-command-obfuscation)
- [ ] [T1218.011 — Rundll32](SO_TA0005_Defense_Evasion.md#t1218.011-rundll32)
- [ ] [T1218.005 — Mshta](SO_TA0005_Defense_Evasion.md#t1218.005-mshta)
- [ ] [T1055 / T1055.012 — Process Injection / Process Hollowing](SO_TA0005_Defense_Evasion.md#t1055-t1055.012-process-injection-process-hollowing)
- [ ] [T1112 — Modify Registry](SO_TA0005_Defense_Evasion.md#t1112-modify-registry)
- [ ] [T1685 — Disable or Modify Tools](SO_TA0005_Defense_Evasion.md#t1685-disable-or-modify-tools)
- [ ] [T1686 — Disable or Modify System Firewall](SO_TA0005_Defense_Evasion.md#t1686-disable-or-modify-system-firewall)
- [ ] [T1685.005 — Clear Windows Event Logs](SO_TA0005_Defense_Evasion.md#t1685.005-clear-windows-event-logs)
- [ ] [T1070.004 — File Deletion](SO_TA0005_Defense_Evasion.md#t1070.004-file-deletion)
- [ ] [T1078 — Valid Accounts](SO_TA0005_Defense_Evasion.md#t1078-valid-accounts)
- [ ] [T1140 — Deobfuscate/Decode Files or Information](SO_TA0005_Defense_Evasion.md#t1140-deobfuscatedecode-files-or-information)
- [ ] [T1036 — Masquerading](SO_TA0005_Defense_Evasion.md#t1036-masquerading)
- [ ] [T1218.010 — System Binary Proxy Execution: Regsvr32](SO_TA0005_Defense_Evasion.md#t1218.010-system-binary-proxy-execution-regsvr32)
- [ ] [T1218.007 — System Binary Proxy Execution: Msiexec](SO_TA0005_Defense_Evasion.md#t1218.007-system-binary-proxy-execution-msiexec)
- [ ] [T1553.002 — Subvert Trust Controls: Code Signing](SO_TA0005_Defense_Evasion.md#t1553.002-subvert-trust-controls-code-signing)
- [ ] [T1497.001 — Virtualization/Sandbox Evasion: System Checks](SO_TA0005_Defense_Evasion.md#t1497.001-virtualizationsandbox-evasion-system-checks)
- [ ] [T1562.003 — Impair Defenses: Impair Command History Logging](SO_TA0005_Defense_Evasion.md#t1562.003-impair-defenses-impair-command-history-logging)
- [ ] [T1562.001 — Impair Defenses: Disable or Modify Tools](SO_TA0005_Defense_Evasion.md#t1562.001-impair-defenses-disable-or-modify-tools)
- [ ] [T1070.002 — Clear Command History](SO_TA0005_Defense_Evasion.md#t1070.002-clear-command-history)
- [ ] [T1553.001 — Subvert Trust Controls: Gatekeeper Bypass](SO_TA0005_Defense_Evasion.md#t1553.001-subvert-trust-controls-gatekeeper-bypass)
- [ ] [T1027 — Obfuscated Files or Information](SO_TA0005_Defense_Evasion.md#t1027-obfuscated-files-or-information)
- [ ] [T1564.001 — Hide Artifacts: Hidden Files and Directories](SO_TA0005_Defense_Evasion.md#t1564.001-hide-artifacts-hidden-files-and-directories)
- [ ] [T1070.003 — Clear Command History](SO_TA0005_Defense_Evasion.md#t1070.003-clear-command-history)
- [ ] [T1647 — Plist File Modification](SO_TA0005_Defense_Evasion.md#t1647-plist-file-modification)
- [ ] [T1197 — BITS Jobs](SO_TA0005_Defense_Evasion.md#t1197-bits-jobs)
- [ ] [T1222 — File and Directory Permissions Modification](SO_TA0005_Defense_Evasion.md#t1222-file-and-directory-permissions-modification)
- [ ] [T1690 — Prevent Command History Logging](SO_TA0005_Defense_Evasion.md#t1690-prevent-command-history-logging)
- [ ] [T1027.013 — Obfuscated Files or Information: Encrypted/Encoded File](SO_TA0005_Defense_Evasion.md#t1027.013-obfuscated-files-or-information-encryptedencoded-file)
- [ ] [T1036.007 — Masquerading: Double File Extension](SO_TA0005_Defense_Evasion.md#t1036.007-masquerading-double-file-extension)
- [ ] [T1036.008 — Masquerading: Masquerade File Type](SO_TA0005_Defense_Evasion.md#t1036.008-masquerading-masquerade-file-type)
- [ ] [T1564.008 — Hide Artifacts: Email Hiding Rules](SO_TA0005_Defense_Evasion.md#t1564.008-hide-artifacts-email-hiding-rules)
- [ ] [T1574.001 — Hijack Execution Flow: DLL](SO_TA0005_Defense_Evasion.md#t1574.001-hijack-execution-flow-dll)
- [ ] [T1574.007 — Hijack Execution Flow: PATH Environment Variable](SO_TA0005_Defense_Evasion.md#t1574.007-hijack-execution-flow-path-environment-variable)
- [ ] [T1574.011 — Hijack Execution Flow: Services Registry Permissions Weakness](SO_TA0005_Defense_Evasion.md#t1574.011-hijack-execution-flow-services-registry-permissions-weakness)

### TA0006 - Credential Access

- [ ] [T1003.001 — OS Credential Dumping: LSASS Memory](SO_TA0006_Credential_Access.md#t1003.001-os-credential-dumping-lsass-memory)
- [ ] [T1003.003 — OS Credential Dumping: NTDS](SO_TA0006_Credential_Access.md#t1003.003-os-credential-dumping-ntds)
- [ ] [T1552.001 — Credentials in Files](SO_TA0006_Credential_Access.md#t1552.001-credentials-in-files)
- [ ] [T1555.003 — Credentials from Web Browsers](SO_TA0006_Credential_Access.md#t1555.003-credentials-from-web-browsers)
- [ ] [T1110.003 — Password Spraying](SO_TA0006_Credential_Access.md#t1110.003-password-spraying)
- [ ] [T1528 — Steal Application Access Token](SO_TA0006_Credential_Access.md#t1528-steal-application-access-token)
- [ ] [T1003.002 — OS Credential Dumping: Security Account Manager](SO_TA0006_Credential_Access.md#t1003.002-os-credential-dumping-security-account-manager)
- [ ] [T1003.004 — OS Credential Dumping: LSA Secrets](SO_TA0006_Credential_Access.md#t1003.004-os-credential-dumping-lsa-secrets)
- [ ] [T1003.005 — OS Credential Dumping: Cached Domain Credentials](SO_TA0006_Credential_Access.md#t1003.005-os-credential-dumping-cached-domain-credentials)
- [ ] [T1558.003 — Steal or Forge Kerberos Tickets: Kerberoasting](SO_TA0006_Credential_Access.md#t1558.003-steal-or-forge-kerberos-tickets-kerberoasting)
- [ ] [T1558.004 — Steal or Forge Kerberos Tickets: AS-REP Roasting](SO_TA0006_Credential_Access.md#t1558.004-steal-or-forge-kerberos-tickets-as-rep-roasting)
- [ ] [T1110.001 — Brute Force: Password Guessing](SO_TA0006_Credential_Access.md#t1110.001-brute-force-password-guessing)
- [ ] [T1110.004 — Brute Force: Credential Stuffing](SO_TA0006_Credential_Access.md#t1110.004-brute-force-credential-stuffing)
- [ ] [T1552.006 — Unsecured Credentials: Group Policy Preferences](SO_TA0006_Credential_Access.md#t1552.006-unsecured-credentials-group-policy-preferences)
- [ ] [T1003.008 — OS Credential Dumping: /etc/passwd and /etc/shadow](SO_TA0006_Credential_Access.md#t1003.008-os-credential-dumping-etcpasswd-and-etcshadow)
- [ ] [T1552.004 — Unsecured Credentials: Private Keys](SO_TA0006_Credential_Access.md#t1552.004-unsecured-credentials-private-keys)
- [ ] [T1552.003 — Unsecured Credentials: Bash History](SO_TA0006_Credential_Access.md#t1552.003-unsecured-credentials-bash-history)
- [ ] [T1555.001 — Credentials from Password Stores: Keychain](SO_TA0006_Credential_Access.md#t1555.001-credentials-from-password-stores-keychain)
- [ ] [T1556.003 — Modify Authentication Process: Pluggable Authentication Modules](SO_TA0006_Credential_Access.md#t1556.003-modify-authentication-process-pluggable-authentication-modules)
- [ ] [T1040 — Network Sniffing](SO_TA0006_Credential_Access.md#t1040-network-sniffing)
- [ ] [T1056.001 — Input Capture: Keylogging](SO_TA0006_Credential_Access.md#t1056.001-input-capture-keylogging)
- [ ] [T1552.005 — Unsecured Credentials: Cloud Instance Metadata API](SO_TA0006_Credential_Access.md#t1552.005-unsecured-credentials-cloud-instance-metadata-api)
- [ ] [T1555.005 — Credentials from Password Stores: Password Managers](SO_TA0006_Credential_Access.md#t1555.005-credentials-from-password-stores-password-managers)
- [ ] [T1110.002 — Brute Force: Password Cracking](SO_TA0006_Credential_Access.md#t1110.002-brute-force-password-cracking)

### TA0007 - Discovery

- [ ] [T1087.002 — Account Discovery: Domain Account](SO_TA0007_Discovery.md#t1087.002-account-discovery-domain-account)
- [ ] [T1018 — Remote System Discovery](SO_TA0007_Discovery.md#t1018-remote-system-discovery)
- [ ] [T1046 — Network Service Discovery](SO_TA0007_Discovery.md#t1046-network-service-discovery)
- [ ] [T1082 — System Information Discovery](SO_TA0007_Discovery.md#t1082-system-information-discovery)
- [ ] [T1057 — Process Discovery](SO_TA0007_Discovery.md#t1057-process-discovery)
- [ ] [T1083 — File and Directory Discovery](SO_TA0007_Discovery.md#t1083-file-and-directory-discovery)
- [ ] [T1016 — System Network Configuration Discovery](SO_TA0007_Discovery.md#t1016-system-network-configuration-discovery)
- [ ] [T1033 — System Owner/User Discovery](SO_TA0007_Discovery.md#t1033-system-owneruser-discovery)
- [ ] [T1069.002 — Permission Groups Discovery: Domain Groups](SO_TA0007_Discovery.md#t1069.002-permission-groups-discovery-domain-groups)
- [ ] [T1482 — Domain Trust Discovery](SO_TA0007_Discovery.md#t1482-domain-trust-discovery)
- [ ] [T1012 — Query Registry](SO_TA0007_Discovery.md#t1012-query-registry)
- [ ] [T1049 — System Network Connections Discovery](SO_TA0007_Discovery.md#t1049-system-network-connections-discovery)
- [ ] [T1087.001 — Account Discovery: Local Account](SO_TA0007_Discovery.md#t1087.001-account-discovery-local-account)
- [ ] [T1069.001 — Permission Groups Discovery: Local Groups](SO_TA0007_Discovery.md#t1069.001-permission-groups-discovery-local-groups)
- [ ] [T1615 — Group Policy Discovery](SO_TA0007_Discovery.md#t1615-group-policy-discovery)
- [ ] [T1680 — Local Storage Discovery](SO_TA0007_Discovery.md#t1680-local-storage-discovery)
- [ ] [T1654 — Log Enumeration](SO_TA0007_Discovery.md#t1654-log-enumeration)
- [ ] [T1135 — Network Share Discovery](SO_TA0007_Discovery.md#t1135-network-share-discovery)
- [ ] [T1201 — Password Policy Discovery](SO_TA0007_Discovery.md#t1201-password-policy-discovery)
- [ ] [T1518 — Software Discovery](SO_TA0007_Discovery.md#t1518-software-discovery)
- [ ] [T1614 — System Location Discovery](SO_TA0007_Discovery.md#t1614-system-location-discovery)
- [ ] [T1007 — System Service Discovery](SO_TA0007_Discovery.md#t1007-system-service-discovery)
- [ ] [T1124 — System Time Discovery](SO_TA0007_Discovery.md#t1124-system-time-discovery)
- [ ] [T1673 — Virtual Machine Discovery](SO_TA0007_Discovery.md#t1673-virtual-machine-discovery)
- [ ] [T1016.001 — System Network Configuration Discovery: Internet Connection Discovery](SO_TA0007_Discovery.md#t1016.001-system-network-configuration-discovery-internet-connection-discovery)
- [ ] [T1069.003 — Permission Groups Discovery: Cloud Groups](SO_TA0007_Discovery.md#t1069.003-permission-groups-discovery-cloud-groups)
- [ ] [T1120 — Peripheral Device Discovery](SO_TA0007_Discovery.md#t1120-peripheral-device-discovery)
- [ ] [T1652 — Device Driver Discovery](SO_TA0007_Discovery.md#t1652-device-driver-discovery)
- [ ] [T1619 — Cloud Storage Object Discovery](SO_TA0007_Discovery.md#t1619-cloud-storage-object-discovery)

### TA0008 - Lateral Movement

- [ ] [T1021.002 — Remote Services: SMB / Windows Admin Shares](SO_TA0008_Lateral_Movement.md#t1021.002-remote-services-smb-windows-admin-shares)
- [ ] [T1021.006 — Remote Services: Windows Remote Management](SO_TA0008_Lateral_Movement.md#t1021.006-remote-services-windows-remote-management)
- [ ] [T1021.001 — Remote Services: Remote Desktop Protocol](SO_TA0008_Lateral_Movement.md#t1021.001-remote-services-remote-desktop-protocol)
- [ ] [T1021.003 — Remote Services: Distributed Component Object Model](SO_TA0008_Lateral_Movement.md#t1021.003-remote-services-distributed-component-object-model)
- [ ] [T1021.004 — Remote Services: SSH](SO_TA0008_Lateral_Movement.md#t1021.004-remote-services-ssh)
- [ ] [T1570 — Lateral Tool Transfer](SO_TA0008_Lateral_Movement.md#t1570-lateral-tool-transfer)

### TA0009 - Collection

- [ ] [T1560.001 — Archive Collected Data: Archive via Utility](SO_TA0009_Collection.md#t1560.001-archive-collected-data-archive-via-utility)
- [ ] [T1005 — Data from Local System](SO_TA0009_Collection.md#t1005-data-from-local-system)
- [ ] [T1113 — Screen Capture](SO_TA0009_Collection.md#t1113-screen-capture)
- [ ] [T1530 — Data from Cloud Storage](SO_TA0009_Collection.md#t1530-data-from-cloud-storage)
- [ ] [T1115 — Clipboard Data](SO_TA0009_Collection.md#t1115-clipboard-data)
- [ ] [T1039 — Data from Network Shared Drive](SO_TA0009_Collection.md#t1039-data-from-network-shared-drive)
- [ ] [T1123 — Audio Capture](SO_TA0009_Collection.md#t1123-audio-capture)
- [ ] [T1119 — Automated Collection](SO_TA0009_Collection.md#t1119-automated-collection)
- [ ] [T1074 — Data Staged](SO_TA0009_Collection.md#t1074-data-staged)
- [ ] [T1025 — Data from Removable Media](SO_TA0009_Collection.md#t1025-data-from-removable-media)
- [ ] [T1114 — Email Collection](SO_TA0009_Collection.md#t1114-email-collection)
- [ ] [T1125 — Video Capture](SO_TA0009_Collection.md#t1125-video-capture)

### TA0011 - Command and Control

- [ ] [T1105 — Ingress Tool Transfer](SO_TA0011_Command_and_Control.md#t1105-ingress-tool-transfer)
- [ ] [T1071.001 — Application Layer Protocol: Web Protocols](SO_TA0011_Command_and_Control.md#t1071.001-application-layer-protocol-web-protocols)
- [ ] [T1090 — Proxy](SO_TA0011_Command_and_Control.md#t1090-proxy)
- [ ] [T1572 — Protocol Tunneling](SO_TA0011_Command_and_Control.md#t1572-protocol-tunneling)
- [ ] [T1095 — Non-Application Layer Protocol](SO_TA0011_Command_and_Control.md#t1095-non-application-layer-protocol)
- [ ] [T1219 — Remote Access Software](SO_TA0011_Command_and_Control.md#t1219-remote-access-software)
- [ ] [T1571 — Non-Standard Port](SO_TA0011_Command_and_Control.md#t1571-non-standard-port)
- [ ] [T1132 — Data Encoding](SO_TA0011_Command_and_Control.md#t1132-data-encoding)
- [ ] [T1071.004 — Application Layer Protocol: DNS](SO_TA0011_Command_and_Control.md#t1071.004-application-layer-protocol-dns)
- [ ] [T1568.001 — Dynamic Resolution: Fast Flux DNS](SO_TA0011_Command_and_Control.md#t1568.001-dynamic-resolution-fast-flux-dns)
- [ ] [T1568.002 — Dynamic Resolution: Domain Generation Algorithms](SO_TA0011_Command_and_Control.md#t1568.002-dynamic-resolution-domain-generation-algorithms)
- [ ] [T1132.001 — Data Encoding: Standard Encoding](SO_TA0011_Command_and_Control.md#t1132.001-data-encoding-standard-encoding)
- [ ] [T1132.002 — Data Encoding: Non-Standard Encoding](SO_TA0011_Command_and_Control.md#t1132.002-data-encoding-non-standard-encoding)

### TA0010 - Exfiltration

- [ ] [T1041 — Exfiltration Over C2 Channel](SO_TA0010_Exfiltration.md#t1041-exfiltration-over-c2-channel)
- [ ] [T1567.002 — Exfiltration to Cloud Storage](SO_TA0010_Exfiltration.md#t1567.002-exfiltration-to-cloud-storage)
- [ ] [T1048 — Exfiltration Over Alternative Protocol](SO_TA0010_Exfiltration.md#t1048-exfiltration-over-alternative-protocol)
- [ ] [T1020 — Automated Exfiltration](SO_TA0010_Exfiltration.md#t1020-automated-exfiltration)
- [ ] [T1052.001 — Exfiltration Over Physical Medium: Exfiltration over USB](SO_TA0010_Exfiltration.md#t1052.001-exfiltration-over-physical-medium-exfiltration-over-usb)
- [ ] [T1567.001 — Exfiltration Over Web Service: Exfiltration to Code Repository](SO_TA0010_Exfiltration.md#t1567.001-exfiltration-over-web-service-exfiltration-to-code-repository)

### TA0040 - Impact

- [ ] [T1486 — Data Encrypted for Impact](SO_TA0040_Impact.md#t1486-data-encrypted-for-impact)
- [ ] [T1490 — Inhibit System Recovery](SO_TA0040_Impact.md#t1490-inhibit-system-recovery)
- [ ] [T1485 — Data Destruction](SO_TA0040_Impact.md#t1485-data-destruction)
- [ ] [T1489 — Service Stop](SO_TA0040_Impact.md#t1489-service-stop)
- [ ] [T1491.001 — Defacement: Internal Defacement](SO_TA0040_Impact.md#t1491.001-defacement-internal-defacement)
- [ ] [T1498 — Network Denial of Service](SO_TA0040_Impact.md#t1498-network-denial-of-service)
- [ ] [T1496 — Resource Hijacking](SO_TA0040_Impact.md#t1496-resource-hijacking)
