<#
  Composes a single one-click azuredeploy.json from the validated component templates
  (DCE + table + DCR + parser + analytics rules). Run this whenever the components change.
  The workbook is deployed separately via arm/deploy-workbook.ps1 (its serializedData string
  doesn't embed cleanly in a hand-authored template).
#>
$ErrorActionPreference = 'Stop'
$here = $PSScriptRoot
$arm  = Join-Path $here 'arm'

$table    = (Get-Content (Join-Path $arm 'table.json')     -Raw | ConvertFrom-Json).resources[0]
$dcr      = (Get-Content (Join-Path $arm 'dcr.json')       -Raw | ConvertFrom-Json).resources[0]
$parser   = (Get-Content (Join-Path $arm 'parser.json')    -Raw | ConvertFrom-Json).resources[0]
$rules    = (Get-Content (Join-Path $arm 'analytics.json') -Raw | ConvertFrom-Json).resources

# DCR depends on the DCE + table being created first in this same template.
$dcr | Add-Member -NotePropertyName dependsOn -NotePropertyValue @(
    "[resourceId('Microsoft.Insights/dataCollectionEndpoints', parameters('dceName'))]",
    "[resourceId('Microsoft.OperationalInsights/workspaces/tables', parameters('workspaceName'), parameters('tableName'))]"
) -Force

# Analytics rules depend on the table existing. Also inline the apiVersion, since the
# source analytics.json used a variables('apiVersion') reference that isn't carried here.
foreach ($r in $rules) {
    if ($r.apiVersion -eq "[variables('apiVersion')]") { $r.apiVersion = '2023-02-01' }
    $r | Add-Member -NotePropertyName dependsOn -NotePropertyValue @(
        "[resourceId('Microsoft.OperationalInsights/workspaces/tables', parameters('workspaceName'), parameters('tableName'))]"
    ) -Force
}

$dce = [ordered]@{
    type       = 'Microsoft.Insights/dataCollectionEndpoints'
    apiVersion = '2023-03-11'
    name       = "[parameters('dceName')]"
    location   = "[parameters('location')]"
    properties = [ordered]@{ networkAcls = [ordered]@{ publicNetworkAccess = 'Enabled' } }
}

$resources = @($dce, $table, $dcr, $parser) + $rules

$template = [ordered]@{
    '$schema'      = 'https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#'
    contentVersion = '1.0.0.0'
    metadata       = [ordered]@{ description = "One-click deploy of the Nutanix -> Microsoft Sentinel data pipeline: Data Collection Endpoint, Nutanix_CL custom table, Data Collection Rule, the Nutanix parser function, and $(@($rules).Count) analytics rules. Deploy the workbook separately with arm/deploy-workbook.ps1, and run the on-prem collector (collector/) to feed data in." }
    parameters     = [ordered]@{
        workspaceName            = [ordered]@{ type='string';  metadata=@{ description='Name of the existing Sentinel-enabled Log Analytics workspace.' } }
        location                 = [ordered]@{ type='string';  defaultValue='[resourceGroup().location]'; metadata=@{ description='Region. Must match the workspace.' } }
        dceName                  = [ordered]@{ type='string';  defaultValue='dce-nutanix'; metadata=@{ description='Name for the Data Collection Endpoint to create.' } }
        dcrName                  = [ordered]@{ type='string';  defaultValue='dcr-nutanix-sentinel'; metadata=@{ description='Name for the Data Collection Rule.' } }
        tableName                = [ordered]@{ type='string';  defaultValue='Nutanix_CL'; metadata=@{ description='Custom table name (must end in _CL).' } }
        retentionInDays          = [ordered]@{ type='int';     defaultValue=90 }
        totalRetentionInDays     = [ordered]@{ type='int';     defaultValue=90 }
        enableRules              = [ordered]@{ type='bool';    defaultValue=$false; metadata=@{ description='Deploy analytics rules enabled (true) or disabled for review (false).' } }
        workspaceResourceId      = [ordered]@{ type='string';  defaultValue="[resourceId('Microsoft.OperationalInsights/workspaces', parameters('workspaceName'))]"; metadata=@{ description='Auto-derived; leave as default.' } }
        dataCollectionEndpointId = [ordered]@{ type='string';  defaultValue="[resourceId('Microsoft.Insights/dataCollectionEndpoints', parameters('dceName'))]"; metadata=@{ description='Auto-derived; leave as default.' } }
    }
    resources      = $resources
    outputs        = [ordered]@{
        dceIngestEndpoint = [ordered]@{ type='string'; value="[reference(resourceId('Microsoft.Insights/dataCollectionEndpoints', parameters('dceName')), '2023-03-11').logsIngestion.endpoint]" }
        dcrImmutableId    = [ordered]@{ type='string'; value="[reference(resourceId('Microsoft.Insights/dataCollectionRules', parameters('dcrName')), '2023-03-11').immutableId]" }
        streamName        = [ordered]@{ type='string'; value='Custom-NutanixInbound' }
    }
}

$out = Join-Path $here 'azuredeploy.json'
$template | ConvertTo-Json -Depth 100 | Set-Content -Path $out -Encoding UTF8
Write-Host "Wrote $out"
