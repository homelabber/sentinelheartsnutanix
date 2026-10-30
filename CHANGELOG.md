# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.0] - 2026-10-30

### Added
- **Version inventory collection.** On a configurable interval
  (`-InventoryIntervalHours`, default 6; `0` disables), the collector reads Prism v4
  clustermgmt clusters and hosts and emits `Category = inventory`,
  `OperationType = VERSION` records for AOS, Prism Central and AHV.
- **Prism API key authentication** (`PRISM_API_KEY`, sent as `X-ntnx-api-key`).
  `setup-host.ps1 -PrismApiKey` stores it with DPAPI. Basic auth is still supported.
- `PRISM_CLUSTERMGMT_API_VERSION` setting (default `v4.0`).
- **Seven new scheduled analytics rules** (21 in total):
  - Admin changes with no recorded login (possible auth bypass, CVE-2026-84731 / NXSA-0058). *InitialAccess*
  - Vulnerable or unsupported AOS / Prism Central / AHV version, driven by inventory
    (NXSA-0047/0048/0055/0058; CVE-2026-84731, CVE-2026-31431, CVE-2026-53362,
    CVE-2026-46300). *InitialAccess, PrivilegeEscalation*
  - VM powered off then disk cloned / attached / detached by the same actor
    (offline NTDS.dit theft). *CredentialAccess, Collection*
  - Mass VM power-off or VM failures on a cluster. *Impact*
  - HTML or script injected into a login username (CVE-2024-12223). *InitialAccess, Execution*
  - Firmware, LCM upgrade, BMC/BIOS or certificate change. *Persistence, DefenseEvasion*
  - Akira / ransomware indicators (CISA AA24-109A). *Impact*

### Fixed
- **The collector ingestion-gap rule could never fire for a fully stopped collector.**
  Its 6-hour query period returned no rows once data had been absent for longer than
  that. The query period is now 2 days, and an empty table is treated as a gap.
- **Watermark loss on partial failure.** A failed alerts, events or audits fetch
  previously still advanced the shared `lastRunUtc` watermark, which silently dropped
  data. Each resource now has its own watermark that only advances to the newest record
  actually sent. Existing `lastRunUtc` state is migrated automatically.
- `azuredeploy.json` deployed only the original 6 rules. It is now regenerated from
  `arm/analytics.json` and deploys all 21. `build-azuredeploy.ps1` derives the rule count
  in the template description instead of hard-coding it.
- README character-encoding artifacts (`â€”`).

### Changed
- The Prism password is no longer required when an API key is configured.
- README rewritten to cover the threat coverage, rule catalog, tuning parameters and
  known limitations.

### Notes
- No table or DCR redeployment is required. Redeploy `arm/analytics.json` or
  `azuredeploy.json` to pick up the new and fixed rules.
- The Prism service account or API key needs read access to clustermgmt for the inventory.
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

[0.3.0]: https://github.com/homelabber/sentinelheartsnutanix/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/homelabber/sentinelheartsnutanix/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/homelabber/sentinelheartsnutanix/releases/tag/v0.1.0
