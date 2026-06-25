# MITRE ATT&CK Elastic KQL and Security Onion OQL Detection Library

Professional, portable threat-hunting content mapped to the MITRE ATT&CK Enterprise framework. The library provides Elastic Kibana Query Language (**Elastic KQL**) detections and matching Security Onion Hunt dashboard (**OQL**) queries where Security Onion telemetry is applicable.

The project is structured as an Obsidian-compatible Markdown knowledge base with a generated single-file HTML reference for browsing, sharing, and GitHub publication. Queries use ECS-style fields and are intended for Kibana Discover, Timeline, Lens, Elastic Security rule development, and Security Onion 3.1.0 Hunt workflows.

## Highlights

- MITRE ATT&CK Enterprise tactic and technique mapping
- Elastic KQL queries written with ECS-style fields
- Security Onion-specific coverage for Zeek, Suricata, and Fleet-managed Elastic Agent integrations, including Elastic Defend, Windows, System, Osquery Manager, and Custom Logs
- Security Onion Hunt dashboard OQL versions for Security Onion-focused detections
- Portable HTML export with search, copy buttons, metrics, and ATT&CK matrix coverage
- Obsidian-friendly Markdown files for editing and knowledge-base workflows

## Project Metrics

| Metric | Count |
| --- | ---: |
| ATT&CK tactics covered | 14 |
| ATT&CK technique sections covered | 196 |
| Detection procedures documented | 540 |
| Elastic KQL queries | 540 |
| Security Onion-specific KQL queries | 338 |
| Security Onion Hunt OQL queries | 338 |

> In this project, one documented detection procedure equals one fenced Elastic KQL query block.

## Repository Layout

| File | Purpose |
| --- | --- |
| [`00_Master_KQL_Index.md`](00_Master_KQL_Index.md) | Master index, metrics, tactic module table, and coverage checklist |
| [`SO_TA*.md`](.) | Tactic-specific Markdown modules containing mapped techniques and KQL queries |
| [`MITRE_KQL_Mapping_Portable.html`](MITRE_KQL_Mapping_Portable.html) | Self-contained portable HTML reference |
| [`build_portable_html.py`](build_portable_html.py) | Dependency-free HTML builder |
| [`enterprise-attack.json`](enterprise-attack.json) | Cached MITRE ATT&CK Enterprise STIX bundle used by the HTML matrix |

## Compatibility

This project is designed around the current Security Onion 3.1.0 host-visibility model, which uses Elastic Agent and Fleet-managed integrations. Legacy standalone endpoint collectors are intentionally out of scope for the library.

Security Onion-focused endpoint queries assume data from Fleet-managed integrations such as Elastic Defend, Windows, System, Osquery Manager, and Custom Logs. Network-focused queries assume Security Onion data from Zeek, Suricata, and related parsed fields.

## Tactic Coverage

| Tactic | Module | Technique Sections | Queries |
| --- | --- | ---: | ---: |
| TA0043 Reconnaissance | [`SO_TA0043_Reconnaissance.md`](SO_TA0043_Reconnaissance.md) | 1 | 4 |
| TA0042 Resource Development | [`SO_TA0042_Resource_Development.md`](SO_TA0042_Resource_Development.md) | 0 | 0 |
| TA0001 Initial Access | [`SO_TA0001_Initial_Access.md`](SO_TA0001_Initial_Access.md) | 6 | 18 |
| TA0002 Execution | [`SO_TA0002_Execution.md`](SO_TA0002_Execution.md) | 20 | 48 |
| TA0003 Persistence | [`SO_TA0003_Persistence.md`](SO_TA0003_Persistence.md) | 32 | 63 |
| TA0004 Privilege Escalation | [`SO_TA0004_Privilege_Escalation.md`](SO_TA0004_Privilege_Escalation.md) | 6 | 17 |
| TA0005 Defense Evasion | [`SO_TA0005_Defense_Evasion.md`](SO_TA0005_Defense_Evasion.md) | 34 | 82 |
| TA0006 Credential Access | [`SO_TA0006_Credential_Access.md`](SO_TA0006_Credential_Access.md) | 24 | 62 |
| TA0007 Discovery | [`SO_TA0007_Discovery.md`](SO_TA0007_Discovery.md) | 29 | 88 |
| TA0008 Lateral Movement | [`SO_TA0008_Lateral_Movement.md`](SO_TA0008_Lateral_Movement.md) | 6 | 29 |
| TA0009 Collection | [`SO_TA0009_Collection.md`](SO_TA0009_Collection.md) | 12 | 34 |
| TA0011 Command and Control | [`SO_TA0011_Command_and_Control.md`](SO_TA0011_Command_and_Control.md) | 13 | 44 |
| TA0010 Exfiltration | [`SO_TA0010_Exfiltration.md`](SO_TA0010_Exfiltration.md) | 6 | 25 |
| TA0040 Impact | [`SO_TA0040_Impact.md`](SO_TA0040_Impact.md) | 7 | 26 |

## Portable HTML Reference

The generated HTML file is the easiest way to browse the full project.

Open directly:

```text
MITRE_KQL_Mapping_Portable.html
```

Or preview locally:

```bash
python3 -m http.server 8765 --bind 127.0.0.1
```

Then browse to:

```text
http://127.0.0.1:8765/MITRE_KQL_Mapping_Portable.html
```

The portable HTML includes:

- Search across tactics, techniques, notes, fields, KQL, and OQL
- Copy-to-clipboard buttons for every KQL and OQL query
- Project metrics
- MITRE ATT&CK Enterprise matrix coverage
- Sidebar navigation by tactic

## Rebuild The HTML

After editing Markdown tactic files, rebuild the portable HTML:

```bash
python3 build_portable_html.py
```

The builder is dependency-free and uses Python standard library modules only. It reads the Markdown files, renders the portable HTML, and uses the cached MITRE ATT&CK Enterprise STIX bundle for the matrix.

## Query Dialect

Baseline detection queries are written in Elastic Kibana Query Language:

- Official docs: [Elastic KQL documentation](https://www.elastic.co/docs/reference/query-languages/kql)
- ECS-oriented fields: `event.category`, `event.dataset`, `process.name`, `process.command_line`, `file.path`, `registry.path`, `source.ip`, `destination.ip`, `destination.port`, `rule.name`, and related fields
- Windows path patterns escape literal backslashes, for example:

```kql
file.path:C\:\\Windows\\System32\\Tasks\\*
```

Elastic KQL is a filtering language. For sequence logic, joins, aggregations, thresholds, and correlation, use Elastic Security rule logic, EQL, ES|QL, threshold rules, new terms rules, or rule exceptions.

Many hunting filters intentionally use leading wildcard patterns such as `process.command_line:*EncodedCommand*`. Elastic KQL supports wildcard syntax, but wildcard terms should not be wrapped in double quotes; quoted values are phrase/literal-style values rather than wildcard terms. Escape spaces and special characters when they appear inside wildcard terms, for example `rule.name:*Command\ and\ Control*` or `process.command_line:*jndi\:*`.

Leading wildcard clauses are controlled by Kibana's `query:allowLeadingWildcards` advanced setting. Verify that setting is enabled in the Kibana space where these queries are used; if it is disabled, leading wildcard clauses will not be accepted and must be rewritten as prefix, exact-match, normalized-field, or rule-exception logic.

Elastic's KQL language reference notes that leading wildcards are disallowed by default for performance reasons, while the current Kibana advanced settings reference lists `query:allowLeadingWildcards` as a boolean setting with a default of `true`. Treat this as an environment compatibility check: the queries are valid for Kibana deployments where `query:allowLeadingWildcards` is enabled, and administrators can disable it.

To check this in Security Onion, open **Security Onion Console**, go to **Kibana**, then open **Stack Management** -> **Advanced Settings**. Search for `query:allowLeadingWildcards` and confirm **Allow leading wildcards in query** is enabled. In Kibana, this is a **Space Settings** value, so verify it in each Kibana space where these KQL queries will be used.

Security Onion Hunt dashboard queries are written in Onion Query Language (**OQL**) for Security Onion 3.1.0. OQL starts with Lucene query syntax and supports Hunt/Dashboards segments such as `groupby`, `sortby`, and `table`.

- Official docs: [Security Onion Dashboards/OQL documentation](https://docs.securityonion.net/en/3/main/dashboards/)

## Security Onion Coverage

Queries marked **Security Onion specific** are tailored to telemetry commonly available in Security Onion deployments, including:

- Zeek datasets such as `conn`, `dns`, `http`, `ssl`, and `files`
- Suricata alert data using fields such as `event.module:"Suricata"`, `event.dataset:"alert"`, and `rule.name`
- Endpoint telemetry collected through Fleet-managed Elastic Agent integrations such as Elastic Defend, Windows, System, Osquery Manager, and Custom Logs
- Fields such as `network.community_id`, `log.id.uid`, `source.ip`, `destination.ip`, `destination.port`, and `network.transport`

Security Onion-specific KQL blocks are kept for Elastic/Kibana workflows. Matching **Security Onion Hunt dashboard (OQL)** blocks are provided for Security Onion 3.1.0 SOC Hunt.

These queries may require local field or data stream adjustments depending on the Security Onion version, enabled integrations, and pipeline configuration.

## Important Notes

- These are hunting-grade filters, not guaranteed drop-in production detections.
- Field availability depends on your integrations, ingest pipelines, and data views.
- Tune allowlists for administrators, software deployment tools, EDR activity, scanners, patching systems, and sanctioned cloud applications.
- Multi-tactic techniques are intentionally duplicated where useful.
- TA0042 Resource Development is mostly pre-compromise attacker activity and often requires external telemetry such as threat intelligence, DNS intelligence, certificate transparency, hosting/provider logs, or cloud audit data.

## Suggested Workflow

1. Open the portable HTML or `00_Master_KQL_Index.md`.
2. Choose a tactic or ATT&CK technique.
3. Copy the KQL into Kibana Discover or Timeline.
4. Copy the OQL into Security Onion Hunt when an OQL block is provided.
5. Confirm required fields exist in your data view.
6. Tune the query for your environment.
7. Promote mature hunts into Elastic Security rules or Security Onion detections where appropriate.

## References

- [MITRE ATT&CK Enterprise](https://attack.mitre.org/)
- [Elastic KQL documentation](https://www.elastic.co/docs/reference/query-languages/kql)
- [Elastic Common Schema](https://www.elastic.co/guide/en/ecs/current/index.html)
- [Security Onion Documentation](https://docs.securityonion.net/)
- [Security Onion Elastic Fleet](https://docs.securityonion.net/en/3/main/elastic-fleet/)
- [Security Onion Dashboards/OQL documentation](https://docs.securityonion.net/en/3/main/dashboards/)
- [Security Onion Zeek](https://docs.securityonion.net/en/3/main/zeek/)
- [Security Onion Suricata](https://docs.securityonion.net/en/3/main/suricata/)
- [Security Onion Alert Data Fields](https://docs.securityonion.net/en/3/main/alert-data-fields/)

## Disclaimer

This project is intended for security research, detection engineering, and defensive hunting. Validate all queries in a test environment before production use. Detection logic should be tuned to local telemetry, business context, and known-good administrative activity.
