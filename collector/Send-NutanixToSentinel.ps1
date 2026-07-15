<#
.SYNOPSIS
    Nutanix -> Microsoft Sentinel collector (Option B: Logs Ingestion API).

.DESCRIPTION
    Polls the Nutanix Prism Central v4 REST API (monitoring/serviceability) for
    alerts, events, and audit records, normalizes them to the Custom-NutanixInbound
    stream schema, and POSTs them to the Azure Monitor Logs Ingestion API. A watermark
    file makes each run incremental. Verified against Prism Central 7.5.2 (API v4.0).

    This collector is deliberately "thin": its only jobs are (1) pull from Prism,
    (2) normalize, (3) push to the DCR ingestion endpoint. When you later migrate to
    a Codeless Connector Platform (CCP) connector, you delete this script and describe
    the same Prism REST call declaratively in the connector's pollingConfig -- the
    table schema, DCR, and transformKql all carry over unchanged.

.NOTES
    Auth to Azure: Microsoft Entra app (client credentials), scope https://monitor.azure.com//.default
    Auth to Prism: basic auth (username/password) or session; adjust as your environment requires.

    Configure via environment variables (recommended) or edit the $Config block below.
    Do NOT commit secrets. Prefer a Key Vault / managed identity when running in Azure.
#>

[CmdletBinding()]
param(
    [string] $StatePath = (Join-Path $PSScriptRoot 'state.json'),
    [int]    $LookbackMinutes = 60,
    [switch] $WhatIfNoSend
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# ------------------------------------------------------------------------------------
# Configuration (env vars take precedence; fall back to inline placeholders)
# ------------------------------------------------------------------------------------
$Config = [ordered]@{
    # --- Microsoft Entra app for Azure Monitor auth ---
    TenantId       = $env:AAD_TENANT_ID
    ClientId       = $env:AAD_CLIENT_ID
    ClientSecret   = $env:AAD_CLIENT_SECRET

    # --- DCR ingestion target (outputs from arm/dcr.json) ---
    DceIngestUri   = $env:DCE_INGEST_URI      # e.g. https://<dce-name>-<hash>.<region>.ingest.monitor.azure.com
    DcrImmutableId = $env:DCR_IMMUTABLE_ID    # e.g. dcr-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
    StreamName     = ($env:DCR_STREAM_NAME, 'Custom-NutanixInbound' | Where-Object { $_ })[0]

    # --- Nutanix Prism Central (v4 REST API; PC 7.x) ---
    PrismBaseUrl   = $env:PRISM_BASE_URL      # e.g. https://prism-central.example.local:9440
    PrismUser      = $env:PRISM_USER
    PrismPassword  = $env:PRISM_PASSWORD
    PrismInsecure  = [bool]($env:PRISM_INSECURE_TLS)   # set to any value to skip cert validation (lab only)
    # monitoring namespace API version. v4.0 is GA on PC 7.5.2; v4.1/v4.2 also served on newer builds.
    PrismApiVer    = ($env:PRISM_API_VERSION, 'v4.0' | Where-Object { $_ })[0]
    PageLimit      = 100                        # v4 max page size
}

foreach ($k in 'TenantId','ClientId','ClientSecret','DceIngestUri','DcrImmutableId','PrismBaseUrl','PrismUser','PrismPassword') {
    if ([string]::IsNullOrWhiteSpace($Config[$k])) {
        throw "Missing required configuration: $k. Set the corresponding environment variable."
    }
}

# Lab-only: allow self-signed Prism certs when PRISM_INSECURE_TLS is set.
if ($Config.PrismInsecure) {
    try { [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true } } catch {}
}

# ------------------------------------------------------------------------------------
# Azure Monitor bearer token (client credentials)
# ------------------------------------------------------------------------------------
function Get-AzMonitorToken {
    param($TenantId, $ClientId, $ClientSecret)
    $body = @{
        client_id     = $ClientId
        client_secret = $ClientSecret
        scope         = 'https://monitor.azure.com//.default'
        grant_type    = 'client_credentials'
    }
    $uri = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"
    $resp = Invoke-RestMethod -Method Post -Uri $uri -Body $body -ContentType 'application/x-www-form-urlencoded'
    return $resp.access_token
}

# ------------------------------------------------------------------------------------
# Prism Central fetch helpers
# ------------------------------------------------------------------------------------
function Get-Prop {
    # Null-safe property read: returns $null instead of throwing under StrictMode
    # when a v4 'omitempty' field is absent from the JSON object.
    param($Object, [string]$Name)
    if ($null -ne $Object -and $Object.PSObject.Properties[$Name]) {
        return $Object.PSObject.Properties[$Name].Value
    }
    return $null
}

function Invoke-PrismApi {
    # GET wrapper with retry/backoff for HTTP 429 (Prism rate limiting).
    param($Uri, $Headers, [int]$MaxRetries = 4)
    $attempt = 0
    while ($true) {
        try {
            return Invoke-RestMethod -Method Get -Uri $Uri -Headers $Headers -TimeoutSec 60
        } catch {
            $code = if ($_.Exception.Response) { [int]$_.Exception.Response.StatusCode } else { 0 }
            if ($code -eq 429 -and $attempt -lt $MaxRetries) {
                $wait = [Math]::Pow(2, $attempt) * 2
                Write-Host "    429 rate-limited; backing off $wait s ..."
                Start-Sleep -Seconds $wait
                $attempt++
                continue
            }
            throw
        }
    }
}

function Get-ClientIp {
    <#
        Extract the originating client IP from a Prism v4 audit record.
        Verified on PC 7.5.2: audit records carry the client address in
        parameters[] as { paramName: 'ip_address', paramValue.stringValue: '<ip>[:<port>]' },
        and the same 'ip:port' is embedded in the message ("... from <ip>:<port> ...").
        We prefer the structured parameter, strip any trailing :port, and fall back to
        a regex over the message. Alerts/events have no client IP, so this returns ''.
    #>
    param($Entity)

    $raw = $null
    $params = Get-Prop $Entity 'parameters'
    if ($params) {
        foreach ($p in @($params)) {
            if ((Get-Prop $p 'paramName') -eq 'ip_address') {
                $pv = Get-Prop $p 'paramValue'
                $raw = Get-Prop $pv 'stringValue'
                break
            }
        }
    }
    if (-not $raw) {
        # Fallback: pull "from <ip>[:port]" out of the free-text message.
        $msg = Get-Prop $Entity 'message'
        if ($msg -and ($msg -match 'from\s+(?<ip>(\d{1,3}\.){3}\d{1,3}|[0-9a-fA-F:]+)(?::\d+)?')) {
            $raw = $Matches['ip']
        }
    }
    if (-not $raw) { return '' }

    $raw = ([string]$raw).Trim()
    # IPv4 with a trailing :port -> strip the port. Bracketed IPv6 [::1]:port -> unwrap.
    if ($raw -match '^\[(?<ip>[0-9a-fA-F:]+)\](?::\d+)?$') { return $Matches['ip'] }
    if ($raw -match '^(?<ip>(\d{1,3}\.){3}\d{1,3})(?::\d+)?$') { return $Matches['ip'] }
    return $raw
}

function Get-PrismAuthHeader {
    param($User, $Password)
    $pair  = "{0}:{1}" -f $User, $Password
    $b64   = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes($pair))
    return @{ Authorization = "Basic $b64"; 'Accept' = 'application/json'; 'Content-Type' = 'application/json' }
}

function Invoke-PrismV4List {
    <#
        Nutanix Prism Central v4 "list" endpoints are GET with OData paging:
          /api/monitoring/<ver>/serviceability/{alerts|events|audits}
        Query params: $page (0-based), $limit (<=100), $filter, $orderby, $select.
        Response envelope: { data: [...], metadata: { totalAvailableResults, ... } }.
        We order by creationTime desc and stop early once records fall at/under the
        watermark, so we don't depend on server-side $filter support for a given build.
    #>
    param($BaseUrl, $Headers, [string]$Resource, [string]$ApiVersion, [int]$Limit, [datetime]$Watermark)

    $all  = New-Object System.Collections.Generic.List[object]
    $page = 0
    $total = 0
    do {
        $q = "`$page=$page&`$limit=$Limit&`$orderby=" + [uri]::EscapeDataString('creationTime desc')
        $uri  = "$BaseUrl/api/monitoring/$ApiVersion/serviceability/$Resource`?$q"
        $resp = Invoke-PrismApi -Uri $uri -Headers $Headers
        $data = @(Get-Prop $resp 'data')
        if ($data.Count -eq 0) { break }
        $all.AddRange($data)
        # Stop paging as soon as the oldest item on this page is at/older than the watermark.
        $oldest = Get-Prop $data[-1] 'creationTime'
        if ($oldest -and ([datetime]$oldest) -le $Watermark) { break }
        $meta  = Get-Prop $resp 'metadata'
        $total = [int](Get-Prop $meta 'totalAvailableResults')
        $page++
        Start-Sleep -Milliseconds 400   # gentle throttle to avoid 429
    } while ($data.Count -eq $Limit -and ($page * $Limit) -lt $total)
    return $all
}

# ------------------------------------------------------------------------------------
# Normalization -> Custom-NutanixInbound stream schema (Nutanix v4 serviceability models)
# ------------------------------------------------------------------------------------
function ConvertTo-NutanixRecord {
    param($Entity, [ValidateSet('alert','event','audit')][string]$Category, [string]$IngestId)

    # creationTime is ISO 8601 (UTC) in v4. Fall back to now if a record omits it.
    $created = Get-Prop $Entity 'creationTime'
    $time = if ($created) { ([datetimeoffset]$created).UtcDateTime } else { (Get-Date).ToUniversalTime() }

    # Cluster identity: alerts/events expose clusterName/clusterUUID; audits use clusterReference{}.
    $clusterRef  = Get-Prop $Entity 'clusterReference'
    $clusterName = Get-Prop $Entity 'clusterName'
    if (-not $clusterName) { $clusterName = Get-Prop $clusterRef 'name' }
    $clusterUuid = Get-Prop $Entity 'clusterUUID'
    if (-not $clusterUuid) { $clusterUuid = Get-Prop $clusterRef 'extId' }

    # The "operation/type" field differs per record type (verified on PC 7.5.2):
    #   alert -> alertType | event -> eventType | audit -> operationType
    $opType = switch ($Category) {
        'alert' { Get-Prop $Entity 'alertType' }
        'event' { Get-Prop $Entity 'eventType' }
        'audit' { Get-Prop $Entity 'operationType' }
    }

    # Severity: only alerts carry it. Audits expose a status; events default to info.
    $severity = switch ($Category) {
        'alert' { Get-Prop $Entity 'severity' }
        'audit' { $s = Get-Prop $Entity 'status'; if ($s) { $s } else { 'info' } }
        default { 'info' }
    }

    $srcEntity = Get-Prop $Entity 'sourceEntity'
    $userRef   = Get-Prop $Entity 'userReference'
    $actor     = Get-Prop $userRef 'name'
    if (-not $actor) { $actor = Get-Prop $Entity 'acknowledgedByUsername' }

    $title = Get-Prop $Entity 'title'
    if (-not $title) { $title = (Get-Prop $srcEntity 'name'), $opType | Where-Object { $_ } | Select-Object -First 1 }

    [pscustomobject]@{
        TimeGenerated      = $time.ToString('o')
        Category           = $Category
        NutanixClusterName = [string]$clusterName
        NutanixClusterUuid = [string]$clusterUuid
        SourceEntityType   = [string](Get-Prop $srcEntity 'type')
        SourceEntityUuid   = [string](Get-Prop $srcEntity 'extId')
        OperationType      = [string]$opType
        Severity           = [string]$severity
        Title              = [string]$title
        Message            = [string](Get-Prop $Entity 'message')
        ActorUser          = [string]$actor
        SourceIp           = [string](Get-ClientIp -Entity $Entity)
        AffectedEntities   = @(Get-Prop $Entity 'affectedEntities')
        RawPayload         = $Entity
        IngestId           = $IngestId
    }
}

# ------------------------------------------------------------------------------------
# Send to Logs Ingestion API (batched, <1MB per request)
# ------------------------------------------------------------------------------------
function Send-Batch {
    # $Items is a list of already-serialized per-record JSON strings.
    # We assemble the array manually ('[' + a,b,c + ']') to avoid a Windows
    # PowerShell 5.1 bug where ConvertTo-Json throws "Argument types do not match"
    # on large arrays of deeply-nested objects.
    param($Items, $Uri, $Headers)
    if ($Items.Count -eq 0) { return 0 }
    $json = '[' + ($Items -join ',') + ']'
    if ($WhatIfNoSend) {
        $kb = [Math]::Round([Text.Encoding]::UTF8.GetByteCount($json) / 1KB, 1)
        Write-Host "  [WhatIf] would POST $($Items.Count) records ($kb KB)"
        return $Items.Count
    }
    Invoke-RestMethod -Method Post -Uri $Uri -Headers $Headers -Body $json | Out-Null
    return $Items.Count
}

function Send-ToLogsIngestion {
    param($Records, $Token, $DceIngestUri, $DcrImmutableId, $StreamName)
    $list = @($Records)
    if ($list.Count -eq 0) { return 0 }

    $uri     = "$DceIngestUri/dataCollectionRules/$DcrImmutableId/streams/$StreamName`?api-version=2023-01-01"
    $headers = @{ Authorization = "Bearer $Token"; 'Content-Type' = 'application/json' }
    $maxBytes = 900KB     # stay safely under the 1 MB Logs Ingestion API limit

    $sent = 0
    $batch = New-Object System.Collections.Generic.List[string]
    $batchBytes = 2       # opening/closing []
    foreach ($r in $list) {
        # Per-record serialization works reliably; the array-level call does not (see Send-Batch).
        $recJson  = ConvertTo-Json -InputObject $r -Depth 20 -Compress
        $recBytes = [Text.Encoding]::UTF8.GetByteCount($recJson)
        if ($batch.Count -gt 0 -and ($batchBytes + $recBytes + 1) -ge $maxBytes) {
            $sent += Send-Batch -Items $batch -Uri $uri -Headers $headers
            $batch.Clear(); $batchBytes = 2
        }
        $batch.Add($recJson)
        $batchBytes += $recBytes + 1   # +1 for the comma separator
    }
    $sent += Send-Batch -Items $batch -Uri $uri -Headers $headers
    return $sent
}

# ------------------------------------------------------------------------------------
# State (watermark) handling
# ------------------------------------------------------------------------------------
$state = if (Test-Path $StatePath) { Get-Content $StatePath -Raw | ConvertFrom-Json } else { $null }
$watermark = if ($state -and $state.lastRunUtc) { [datetime]$state.lastRunUtc } else { (Get-Date).ToUniversalTime().AddMinutes(-$LookbackMinutes) }
$ingestId = [guid]::NewGuid().ToString()
Write-Host "Watermark (UTC): $($watermark.ToString('o'))  IngestId: $ingestId"

# ------------------------------------------------------------------------------------
# Main
# ------------------------------------------------------------------------------------
$prismHeaders = Get-PrismAuthHeader -User $Config.PrismUser -Password $Config.PrismPassword
$token = Get-AzMonitorToken -TenantId $Config.TenantId -ClientId $Config.ClientId -ClientSecret $Config.ClientSecret

$records = New-Object System.Collections.Generic.List[object]

# v4 serviceability endpoints (Prism Central 7.x): alerts, events, audits.
$resources = @{ alerts = 'alert'; events = 'event'; audits = 'audit' }
foreach ($res in $resources.Keys) {
    $category = $resources[$res]
    try {
        $items = Invoke-PrismV4List -BaseUrl $Config.PrismBaseUrl -Headers $prismHeaders `
                    -Resource $res -ApiVersion $Config.PrismApiVer -Limit $Config.PageLimit -Watermark $watermark
        $ok = 0; $bad = 0
        foreach ($it in $items) {
            try { $records.Add((ConvertTo-NutanixRecord -Entity $it -Category $category -IngestId $ingestId)); $ok++ }
            catch { $bad++ }
        }
        Write-Host "  $res : fetched $($items.Count) (normalized $ok, skipped $bad)"
    } catch {
        Write-Warning "  $res fetch failed (check API version '$($Config.PrismApiVer)' / permissions): $($_.Exception.Message)"
    }
}

# Incremental filter by watermark on the normalized TimeGenerated.
$new = @($records | Where-Object { [datetime]$_.TimeGenerated -gt $watermark })
Write-Host "Fetched $($records.Count) records; $($new.Count) newer than watermark."

$sent = Send-ToLogsIngestion -Records $new -Token $token -DceIngestUri $Config.DceIngestUri -DcrImmutableId $Config.DcrImmutableId -StreamName $Config.StreamName
Write-Host "Sent $sent records to Logs Ingestion API."

# Advance watermark only after a successful send.
@{ lastRunUtc = (Get-Date).ToUniversalTime().ToString('o'); lastIngestId = $ingestId; lastSent = $sent } |
    ConvertTo-Json | Set-Content -Path $StatePath -Encoding UTF8
Write-Host "State saved to $StatePath"
