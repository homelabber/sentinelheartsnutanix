# Sentinel <3 Nutanix

A self-hosted connector that ships **Nutanix Prism Central** telemetry (alerts, events, and audit logs) into **Microsoft Sentinel** via the Azure Monitor **Logs Ingestion API**, plus a ready-to-use detection and visualization pack.

Built and verified against **Prism Central 7.5.2** (Nutanix **v4** REST API).

## What's in the box

| Component | Path | Purpose |
|-----------|------|---------|
| One-click Azure deploy | `azuredeploy.json` | DCE + `Nutanix_CL` table + DCR + parser + 6 analytics rules |
| Custom table | `arm/table.json` | `Nutanix_CL` schema (normalized columns + `RawPayload`) |
| Data Collection Rule | `arm/dcr.json` | Stream -> transform -> table |
| Parser function | `arm/parser.json` | `Nutanix` saved function for clean KQL |
| Analytics rules | `arm/analytics.json` | 6 scheduled detections (security + operational) |
| Workbook | `arm/workbook*.json`, `arm/deploy-workbook.ps1` | "Nutanix Health & Security" dashboard |
| Collector | `collector/Send-NutanixToSentinel.ps1` | Polls Prism v4 API, pushes to Sentinel (incremental) |
| Host setup | `collector/setup-host.ps1`, `collector/run-collector.ps1` | Encrypts secrets (DPAPI) + registers a scheduled task |

## Architecture

```
Nutanix Prism Central (v4 REST API)
        |  (on-prem collector: alerts/events/audits, incremental)
        v
Azure Monitor Logs Ingestion API  --(DCE)-->  DCR  --(transformKql)-->  Nutanix_CL
        |
        +--> Parser function (Nutanix)
        +--> 6 Analytics rules
        +--> Health & Security workbook
```

> **Why a self-hosted collector and not a Codeless (CCP) connector?**
> CCP polling runs from Microsoft's cloud and requires your Prism endpoint to be
> internet-reachable. This project targets **on-prem / private** Prism deployments,
> so the collector runs on your network with line-of-sight to Prism. The table, DCR,
> and stream are CCP-compatible if you later choose to expose Prism publicly.

## Deploy the Azure side

[![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fhomelabber%2Fsentinelheartsnutanix%2Fmain%2Fazuredeploy.json)

Or with the CLI:

```powershell
az deployment group create -g <rg> --template-file azuredeploy.json `
  --parameters workspaceName=<your-sentinel-workspace>
```

The deployment outputs `dceIngestEndpoint`, `dcrImmutableId`, and `streamName` — you'll
need these for the collector. Analytics rules deploy **disabled** by default; set
`enableRules=true` to turn them on, or enable them individually after review.

Deploy the workbook separately (its content is large):

```powershell
.\arm\deploy-workbook.ps1 -ResourceGroup <rg> -WorkspaceName <ws> -Location <region>
```

## Set up the collector

1. Create a **Microsoft Entra app registration** (client ID + secret) and grant it the
   **Monitoring Metrics Publisher** role on the DCR (`arm/deploy.ps1` automates this).
2. Create a **Prism Central** service account with a read-only role (Prism Viewer).
3. On the collector host (any machine with network access to Prism **and** Azure):

   ```powershell
   cd collector
   .\setup-host.ps1 `
     -TenantId <tenant> -ClientId <appId> `
     -DceIngestUri <dceIngestEndpoint> -DcrImmutableId <dcrImmutableId> `
     -PrismBaseUrl https://<prism-central> -SmokeTest
   ```

   `setup-host.ps1` encrypts secrets with machine-scoped DPAPI, writes a local config,
   and registers a scheduled task that runs every 10 minutes.

## Verify

```kusto
Nutanix_CL | sort by TimeGenerated desc | take 50
```

## Requirements

- Microsoft Sentinel-enabled Log Analytics workspace
- Nutanix Prism Central 7.x (v4 API) with a read-only service account
- A host to run the collector (Windows PowerShell 5.1 or PowerShell 7), reachable to
  both Prism (usually TCP 9440, or 443 via a reverse proxy) and Azure (443 outbound)

## Security notes

- Secrets are never committed. `setup-host.ps1` stores them encrypted (DPAPI, machine scope).
- The collector uses OAuth client credentials for Azure and Basic auth for Prism.
- Run only **one** collector host to avoid double-ingestion (each keeps its own watermark).

## License

MIT — see [LICENSE](LICENSE).
