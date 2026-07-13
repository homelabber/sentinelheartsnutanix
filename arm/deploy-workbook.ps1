<#
.SYNOPSIS
    Deploys the Nutanix Health & Security workbook into the Sentinel workspace.

.DESCRIPTION
    Reads workbook-content.json, substitutes the workspace resource ID, stringifies
    it, and deploys workbook.json with that content as the serializedData parameter.
    The workbook GUID is derived deterministically from the workspace + a fixed seed
    so re-running updates the same workbook instead of creating duplicates.

.EXAMPLE
    .\deploy-workbook.ps1 -ResourceGroup rg-eastus-sentinel -WorkspaceName WanderSentinel -Location eastus
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $ResourceGroup,
    [Parameter(Mandatory)] [string] $WorkspaceName,
    [Parameter(Mandatory)] [string] $Location,
    [string] $DisplayName = "Nutanix Health & Security"
)

$ErrorActionPreference = 'Stop'
$here = $PSScriptRoot

$wsId = az monitor log-analytics workspace show -g $ResourceGroup -n $WorkspaceName --query id -o tsv
if (-not $wsId) { throw "Could not resolve workspace '$WorkspaceName' in '$ResourceGroup'." }

# Deterministic workbook GUID (stable across redeploys for this workspace).
$seed  = "nutanix-health-workbook|$wsId"
$md5   = [System.Security.Cryptography.MD5]::Create()
$hash  = $md5.ComputeHash([Text.Encoding]::UTF8.GetBytes($seed))
$wbId  = ([guid]::new($hash)).ToString()

# Load content, inject workspace id, compact to a single-line string.
$contentPath = Join-Path $here 'workbook-content.json'
$raw = Get-Content $contentPath -Raw
$raw = $raw.Replace('__WORKSPACE_ID__', $wsId)
$serialized = ($raw | ConvertFrom-Json | ConvertTo-Json -Depth 100 -Compress)

# Build a parameters file (avoids CLI length/escaping issues with the large string).
$paramObj = @{
    '$schema'      = 'https://schema.management.azure.com/schemas/2019-04-01/deploymentParameters.json#'
    contentVersion = '1.0.0.0'
    parameters     = @{
        workbookDisplayName = @{ value = $DisplayName }
        workbookId          = @{ value = $wbId }
        location            = @{ value = $Location }
        workspaceResourceId = @{ value = $wsId }
        serializedData      = @{ value = $serialized }
    }
}
$paramFile = Join-Path $env:TEMP 'nutanix-workbook.parameters.json'
$paramObj | ConvertTo-Json -Depth 100 | Set-Content -Path $paramFile -Encoding UTF8

Write-Host "==> Deploying workbook '$DisplayName' (id $wbId) ..."
az deployment group create `
    --resource-group $ResourceGroup `
    --name nutanix-workbook `
    --template-file (Join-Path $here 'workbook.json') `
    --parameters "@$paramFile" `
    --query "properties.provisioningState" -o tsv

Remove-Item $paramFile -ErrorAction SilentlyContinue
Write-Host "Done. Open Microsoft Sentinel -> Workbooks -> '$DisplayName'."
