# Sentinel <3 Nutanix

![Version](https://img.shields.io/badge/version-0.3.0-blue) ![License](https://img.shields.io/badge/license-MIT-green) ![Rules](https://img.shields.io/badge/analytics%20rules-21-orange)

A self-hosted connector that ships **Nutanix Prism Central** telemetry (alerts, events, audit logs and, as of 0.3.0, **version inventory**) into **Microsoft Sentinel** through the Azure Monitor **Logs Ingestion API**. It also comes with a detection and visualization pack. Your hyperconverged infrastructure has opinions, and now your SOC can hear them.

Built and verified against **Prism Central 7.5.2** (Nutanix **v4** REST API).

## What's new in 0.3.0

Threat actors read Nutanix security advisories too, and often faster than change-advisory boards do. This release is about catching up with them:

- **Seven new analytics rules (21 in total)** built around current Nutanix advisories and known ransomware tradecraft. See [Threat coverage](#threat-coverage).
- **Version inventory.** Every 6 hours (configurable), the collector records the AOS, Prism Central and AHV versions it sees. Sentinel can then point out the out-of-date ones before an attacker does.
- **API key authentication** for Prism (`X-ntnx-api-key`). Basic auth still works, but it has been moved to "legacy".
- **Per-resource watermarks.** If the audits fetch fails, the collector no longer takes alerts and events down with it. Each stream keeps its own place, and the failed stream retries on the next run with no data lost.
- **The ingestion-gap rule now detects gaps.** It used to look back only 6 hours, so a collector that had been dead for longer was invisible to it: the most important alert of all could never fire. It now looks back 2 days and also fires when the table is completely empty.
- **`azuredeploy.json` is back in sync.** The one-click template now deploys all 21 rules, not only the original 6.

Full details are in [CHANGELOG.md](CHANGELOG.md).

## What's in the box

| Component | Path | Purpose |
|-----------|------|---------|
| One-click Azure deploy | `azuredeploy.json` | DCE + `Nutanix_CL` table + DCR + parser + 21 analytics rules |
| Custom table | `arm/table.json` | `Nutanix_CL` schema (normalized columns + `RawPayload`) |
| Data Collection Rule | `arm/dcr.json` | Stream -> transform -> table |
| Parser function | `arm/parser.json` | `Nutanix` saved function for clean KQL |
| Analytics rules | `arm/analytics.json` | 21 scheduled detections (security + operational) |
| Workbook | `arm/workbook*.json`, `arm/deploy-workbook.ps1` | "Nutanix Health & Security" dashboard |
| Collector | `collector/Send-NutanixToSentinel.ps1` | Polls the Prism v4 API and pushes to Sentinel (incremental, per-resource watermarks) |
| Host setup | `collector/setup-host.ps1`, `collector/run-collector.ps1` | Encrypts secrets (DPAPI) and registers a scheduled task |
| Template builder | `build-azuredeploy.ps1` | Regenerates `azuredeploy.json` from `arm/*` (run it after editing rules) |

## Architecture

```
Nutanix Prism Central (v4 REST API)
        |  (on-prem collector: alerts / events / audits incremental, inventory every N hours)
        v
Azure Monitor Logs Ingestion API  --(DCE)-->  DCR  --(transformKql)-->  Nutanix_CL
        |
        +--> Parser function (Nutanix)
        +--> 21 analytics rules
        +--> Health & Security workbook
```

> **Why a self-hosted collector and not a Codeless (CCP) connector?**
> CCP polls from Microsoft's cloud, which means your Prism endpoint would have to be
> reachable from the internet. Given the advisories below, think hard before doing that.
> This project targets **on-prem / private** Prism deployments, so the collector runs on
> your network with line-of-sight to Prism. The table, DCR and stream are CCP-compatible
> if you later decide otherwise.

## Threat coverage

The rules map to current, publicly documented threats. Advisory references are accurate as of this release. Check the [Nutanix Security Advisories](https://portal.nutanix.com/page/documents/security-advisories/list) and the [CISA KEV catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) for anything newer.

| Threat | What we watch for | Rule(s) |
|--------|-------------------|---------|
| **Prism auth bypass** (NXSA-0058, CVE-2026-84731) | Admin changes from an actor who never logged in, and AOS / PC versions below the fixed release | Admin changes with no recorded login; Vulnerable or unsupported version |
| **AHV kernel privilege escalation** (NXSA-0047 / 0048 / 0055; CVE-2026-31431, CVE-2026-53362, CVE-2026-46300, CISA KEV) | AHV hosts below the fixed release on their train | Vulnerable or unsupported version |
| **Stored XSS via the login field** (CVE-2024-12223) | HTML or script markup in a login username | HTML or script injected into a login username |
| **Akira ransomware** (CISA AA24-109A) and similar | The Akira-associated `itadm` account, ransomware file extensions and ransomware alerts, plus anti-recovery deletes and mass VM power-off | Akira / ransomware indicators; Mass VM power-off; Snapshot / backup deletion |
| **Offline domain controller theft** (power off the DC VM, copy its disk, extract NTDS.dit) | VM power-off followed by a disk clone, attach or detach by the same actor | VM powered off then disk cloned / attached / detached |
| **Persistence & evasion** | SSH keys, lockdown disabled, new accounts / API keys, logging disabled, firmware / BMC / certificate changes | SSH key / lockdown; New user / API key; Logging disabled; Firmware, LCM, BMC/BIOS or certificate change |
| **Your own collector dying quietly** | No data for 2+ hours, or an empty table | Collector ingestion gap |

### All 21 rules

| # | Rule | Severity | Tactic(s) |
|---|------|----------|-----------|
| 1 | Critical or Warning alert raised | High | Impact |
| 2 | Repeated failed audit operations by a user | Medium | CredentialAccess |
| 3 | Identity or security configuration change | Medium | Persistence, PrivilegeEscalation |
| 4 | Destructive VM / host / cluster operation | High | Impact |
| 5 | Availability or hardware alert (critical / warning) | High | Impact |
| 6 | Collector ingestion gap (health) | Low | Impact |
| 7 | Failed logins followed by a successful login (possible brute force) | High | CredentialAccess |
| 8 | Deletion of snapshots / backups / recovery points (anti-recovery) | High | Impact |
| 9 | Logging, syslog, or security control disabled (defense evasion) | High | DefenseEvasion |
| 10 | SSH key added or cluster lockdown disabled (backdoor persistence) | High | Persistence |
| 11 | New user, API key, or service account created | Medium | Persistence, PrivilegeEscalation |
| 12 | Password reset for a different user (possible account takeover) | Medium | CredentialAccess, Persistence |
| 13 | New replication / remote site / export path created (possible exfiltration) | Medium | Exfiltration |
| 14 | High volume of management operations by a single actor (velocity) | Medium | Impact |
| 15 | **New:** Admin changes with no recorded login (possible auth bypass, CVE-2026-84731) | Medium | InitialAccess |
| 16 | **New:** Vulnerable or unsupported AOS / Prism Central / AHV version (inventory) | High | InitialAccess, PrivilegeEscalation |
| 17 | **New:** VM powered off then disk cloned / attached / detached by the same actor | High | CredentialAccess, Collection |
| 18 | **New:** Mass VM power-off or VM failures on a cluster | High | Impact |
| 19 | **New:** HTML or script injected into a login username (CVE-2024-12223) | Medium | InitialAccess, Execution |
| 20 | **New:** Firmware, LCM upgrade, BMC/BIOS or certificate change | Medium | Persistence, DefenseEvasion |
| 21 | **New:** Akira / ransomware indicators | High | Impact |

### Tuning knobs

Most new rules start with `let` statements at the top of the query. Adjust them for your environment and don't fight the rule:

| Rule | Knob | Default |
|------|------|---------|
| Admin changes with no recorded login | `ExcludedActors` (service accounts that use API keys and never "log in") | `dynamic([])` |
| Mass VM power-off | `VmThreshold` | `10` VMs |
| Firmware / LCM / BMC / certificate change | Change window (days / UTC hours), `OnlyOutsideChangeWindow` | Sat-Sun 01:00-06:00, `false` |
| Vulnerable version | `FixedVersions` datatable | Fixed releases from NXSA-0047/0048/0055/0058 |

When Nutanix publishes a new advisory, add a row to the `FixedVersions` datatable. Trains older than the oldest known train are reported as **Unsupported**. Trains that are missing from the table but fall inside the known range are reported as **verify manually**, because the rule won't guess.

## Deploy the Azure side

[![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fhomelabber%2Fsentinelheartsnutanix%2Fmain%2Fazuredeploy.json)

Or with the CLI:

```powershell
az deployment group create -g <rg> --template-file azuredeploy.json `
  --parameters workspaceName=<your-sentinel-workspace>
```

The deployment outputs `dceIngestEndpoint`, `dcrImmutableId` and `streamName`. You'll
need these for the collector. Analytics rules deploy **disabled** by default, because
21 surprise incidents make a bad first impression. Set `enableRules=true` to turn them on,
or enable them one at a time after review.

Upgrading from 0.2.0? Redeploying the template (or `arm/analytics.json`) updates the existing
rules in place and adds the new ones. The table and DCR do not change in this release.

Deploy the workbook separately (its content is large):

```powershell
.\arm\deploy-workbook.ps1 -ResourceGroup <rg> -WorkspaceName <ws> -Location <region>
```

## Set up the collector

1. Create a **Microsoft Entra app registration** (client ID + secret) and grant it the
   **Monitoring Metrics Publisher** role on the DCR (`arm/deploy.ps1` automates this).
2. Create a **Prism Central** service account with a read-only role (Prism Viewer). It needs
   read access to **clustermgmt** (clusters and hosts) for the version inventory. An
   **API key** is preferred over a password.
3. On the collector host (any machine with network access to Prism **and** Azure):

   ```powershell
   cd collector
   # API key (recommended)
   .\setup-host.ps1 `
     -TenantId <tenant> -ClientId <appId> `
     -DceIngestUri <dceIngestEndpoint> -DcrImmutableId <dcrImmutableId> `
     -PrismBaseUrl https://<prism-central> `
     -PrismApiKey (Read-Host -AsSecureString 'Prism API key') -SmokeTest

   # ...or classic username/password (you'll be prompted for the password)
   .\setup-host.ps1 ... -PrismUser svc-sentinel -SmokeTest
   ```

   `setup-host.ps1` encrypts secrets with machine-scoped DPAPI, writes a local config,
   and registers a scheduled task that runs every 10 minutes.

### Collector options

| Setting | Where | Default | Notes |
|---------|-------|---------|-------|
| `-InventoryIntervalHours` | `run-collector.ps1` / collector param | `6` | `0` disables inventory collection |
| `PRISM_API_KEY` | secrets / env | *(unset)* | When set, the API key is used instead of Basic auth |
| `PRISM_CLUSTERMGMT_API_VERSION` | config / env | `v4.0` | Clustermgmt API version used for the inventory |

Inventory records arrive as `Category == "inventory"` and `OperationType == "VERSION"`, with the
product in `SourceEntityType` and the version in `Title`. They are useful outside of security too, for example as an answer to
"which clusters still need that upgrade?"

## Verify

```kusto
Nutanix_CL | sort by TimeGenerated desc | take 50

// Is the inventory flowing?
Nutanix_CL | where Category == "inventory" | summarize arg_max(TimeGenerated, *) by SourceEntityUuid
| project TimeGenerated, NutanixClusterName, Product = SourceEntityType, Version = Title, Message
```

## Requirements

- Microsoft Sentinel-enabled Log Analytics workspace
- Nutanix Prism Central 7.x (v4 API) with a read-only service account or API key
- A host to run the collector (Windows PowerShell 5.1 or PowerShell 7) that can reach
  both Prism (usually TCP 9440, or 443 via a reverse proxy) and Azure (443 outbound)

## Security notes

- Secrets are never committed. `setup-host.ps1` stores them encrypted (DPAPI, machine scope).
- The collector uses OAuth client credentials for Azure and an API key (preferred) or Basic auth for Prism.
- Run only **one** collector host, to avoid double-ingestion (each host keeps its own watermarks).
- Keep Prism off the internet. The advisories above show why.

## Known limitations

Some honest caveats:

- The **inventory** relies on Prism v4 clustermgmt fields (`buildInfo.version`, `clusterFunction`,
  `hypervisor.fullName`). These follow the published v4 schema but haven't been tested against
  every Prism release. If the inventory comes back empty, check `RawPayload` first.
- Several rules match on **audit message text**, and Nutanix rewords these between releases.
  Each rule has been compile-tested and checked against synthetic data. Validate against your
  own audit trail before you page anyone at 3 a.m.
- The vulnerable-version rule is only as current as its `FixedVersions` table. New advisories
  are not imported automatically.

## License

MIT. See [LICENSE](LICENSE).
