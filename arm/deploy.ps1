<#
.SYNOPSIS
    One-shot deploy for the Nutanix -> Sentinel connector (Option B) Azure side.

.DESCRIPTION
    Deploys the custom table and the DCR, then grants the collector's Entra app the
    "Monitoring Metrics Publisher" role on the DCR (required to POST via the Logs
    Ingestion API). Prints the DCE ingest URI + DCR immutable id you feed into
    collector/config.example.ps1.

    Requires: Azure CLI (az) logged in with rights to the workspace/RG, and an existing
    Data Collection Endpoint (DCE) in the same region as the workspace.

.NOTES
    This automates the Azure-side setup only. Prism Central config (create the
    svc-sentinel user with a viewer role) is done in Prism.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $ResourceGroup,
    [Parameter(Mandatory)] [string] $Location,               # e.g. eastus  (must match workspace + DCE)
    [Parameter(Mandatory)] [string] $WorkspaceName,
    [Parameter(Mandatory)] [string] $WorkspaceResourceId,    # /subscriptions/.../workspaces/<name>
    [Parameter(Mandatory)] [string] $DceResourceId,          # /subscriptions/.../dataCollectionEndpoints/<name>
    [Parameter(Mandatory)] [string] $CollectorAppObjectId,   # Entra app *service principal* object id
    [string] $TableName = "Nutanix_CL",
    [string] $DcrName   = "dcr-nutanix-sentinel"
)

$ErrorActionPreference = 'Stop'
$armDir = Join-Path $PSScriptRoot '..\arm'

Write-Host "==> Deploying custom table $TableName ..."
az deployment group create `
    --resource-group $ResourceGroup `
    --template-file (Join-Path $armDir 'table.json') `
    --parameters workspaceName=$WorkspaceName tableName=$TableName | Out-Null

Write-Host "==> Deploying DCR $DcrName ..."
$dcrOut = az deployment group create `
    --resource-group $ResourceGroup `
    --template-file (Join-Path $armDir 'dcr.json') `
    --parameters dcrName=$DcrName location=$Location `
                 workspaceResourceId=$WorkspaceResourceId `
                 dataCollectionEndpointId=$DceResourceId `
                 tableName=$TableName `
    --query 'properties.outputs' -o json | ConvertFrom-Json

$immutableId = $dcrOut.dcrImmutableId.value
$streamName  = $dcrOut.streamName.value

# Use core 'az resource show' (no monitor-control-service extension needed).
$dcrResourceId = az resource show `
    --resource-group $ResourceGroup `
    --resource-type "Microsoft.Insights/dataCollectionRules" `
    --name $DcrName --query id -o tsv

Write-Host "==> Granting 'Monitoring Metrics Publisher' on the DCR to the collector app ..."
az role assignment create `
    --assignee-object-id $CollectorAppObjectId `
    --assignee-principal-type ServicePrincipal `
    --role "Monitoring Metrics Publisher" `
    --scope $dcrResourceId | Out-Null

$dceIngest = az resource show --ids $DceResourceId --query "properties.logsIngestion.endpoint" -o tsv

Write-Host ""
Write-Host "===================== FEED THESE INTO config.example.ps1 ====================="
Write-Host "DCE_INGEST_URI   = $dceIngest"
Write-Host "DCR_IMMUTABLE_ID = $immutableId"
Write-Host "DCR_STREAM_NAME  = $streamName"
Write-Host "=============================================================================="
