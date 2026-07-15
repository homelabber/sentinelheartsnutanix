# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2026-07-15

### Added
- **Client source IP extraction** in the collector (`Get-ClientIp`). The
  previously-empty `SourceIp` column is now populated from the Prism v4 audit
  record's `parameters[].ip_address` field, with a fallback that parses the IP
  out of the audit message. Handles `ip:port`, bracketed IPv6, and
  X-Forwarded-For style `client,proxy` values (the originating client IP is
  kept). Verified against live Prism Central 7.5.2 audit payloads.
- **Eight new Sentinel scheduled analytics rules** targeting threat-actor and
  ransomware behavior on the `Nutanix_CL` audit stream. All were validated
  against 30 days of live data (zero false positives on benign traffic) and
  surface the newly-extracted `SourceIp` as an IP entity where available:
  - Failed logins followed by a successful login (brute-force success) — *CredentialAccess*
  - Deletion of snapshots / backups / recovery points (anti-recovery) — *Impact, T1490*
  - Logging / syslog / security control disabled (defense evasion) — *DefenseEvasion, T1562*
  - SSH key added or cluster lockdown disabled (backdoor persistence) — *Persistence, T1098*
  - New user, API key, or service account created (persistence) — *Persistence/PrivEsc, T1136*
  - Password reset for a different user (possible account takeover) — *CredentialAccess, T1098*
  - New replication / remote site / export path created (possible exfiltration) — *Exfiltration, T1537*
  - High volume of management operations by a single actor (velocity) — *Impact, T1485/T1489*

### Changed
- Analytics-rule message matching uses `contains` (case-insensitive substring)
  instead of `has`/`has_any` (term-based) for multi-word phrases, preventing
  over-matching of routine audit-message text (e.g. token-creation records).

### Notes
- No table or DCR redeployment is required for the `SourceIp` fix — the column
  was already declared in the table schema and DCR stream; only the collector
  needed to populate it.

## [0.1.0] - Initial release

### Added
- Nutanix → Microsoft Sentinel connector (Option B, Logs Ingestion API):
  thin PowerShell collector, custom table (`Nutanix_CL`), Data Collection Rule,
  and normalized `Nutanix` saved-search parser.
- Initial set of six scheduled analytics rules covering security/audit
  detections and operational/availability alerts.
- Health workbook and one-shot Azure- and host-side setup scripts.

[0.2.0]: https://github.com/homelabber/sentinelheartsnutanix/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/homelabber/sentinelheartsnutanix/releases/tag/v0.1.0
