<#
.SYNOPSIS
    One-shot setup for running the Nutanix -> Sentinel collector on a dedicated host.

.DESCRIPTION
    Run this ONCE on the machine that will run the collector. It:
      1. Runs preflight checks (PowerShell, TLS 1.2, network line-of-sight to Prism,
         Entra login, and the DCE ingestion endpoint).
      2. Encrypts the client secret + Prism API key or password with machine-scoped DPAPI to
         secrets.dat (unreadable if copied to another machine).
      3. Writes non-secret settings to host-config.psd1.
      4. Locks down ACLs on both files.
      5. Registers a scheduled task that runs run-collector.ps1 on an interval.
      6. Optionally runs a -SmokeTest (dry run) at the end.

    The Azure objects (Entra app, DCR, table, role assignment) are per-tenant and
    already exist -- this script does NOT create anything in Azure. It only wires up
    THIS host to use them.

.EXAMPLE
    .\setup-host.ps1 `
        -TenantId       "<tenant-guid>" `
        -ClientId       "9428ab8d-5116-436c-a4b4-8801c2df2db8" `
        -DceIngestUri   "https://dce-nutanix-b00p.eastus-1.ingest.monitor.azure.com" `
        -DcrImmutableId "dcr-a2ce90ea43914087ace1acf2b8e9ff78" `
        -PrismBaseUrl   "https://cthulhu.wandering.cloud" `
        -SmokeTest
    # You'll be securely prompted for the client secret and Prism password.

.EXAMPLE
    # Preferred: authenticate to Prism Central with a service-account API key instead.
    .\setup-host.ps1 -TenantId "<tenant-guid>" -ClientId "<app-id>" `
        -DceIngestUri "<dce-uri>" -DcrImmutableId "<dcr-id>" -PrismBaseUrl "<pc-url>" `
        -PrismApiKey (Read-Host "Prism API key" -AsSecureString)

.NOTES
    Run from an elevated PowerShell (Administrator) so it can register a task that
    runs as SYSTEM and lock down file ACLs.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $TenantId,
    [Parameter(Mandatory)] [string] $ClientId,
    [Parameter(Mandatory)] [string] $DceIngestUri,
    [Parameter(Mandatory)] [string] $DcrImmutableId,
    [Parameter(Mandatory)] [string] $PrismBaseUrl,

    [string]       $StreamName      = 'Custom-NutanixInbound',
    [string]       $PrismUser       = 'svc-sentinel',
    [string]       $PrismApiVersion = 'v4.0',
    [switch]       $PrismInsecureTls,

    [securestring] $ClientSecret,
    [securestring] $PrismPassword,
    [securestring] $PrismApiKey,     # PC service-account API key; when set, no password is needed

    [int]          $IntervalMinutes = 10,
    [string]       $TaskName        = 'Nutanix-Sentinel-Collector',
    [string]       $RunAsUser       = 'NT AUTHORITY\SYSTEM',

    [switch]       $SkipConnectivityTest,
    [switch]       $SmokeTest
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$here      = $PSScriptRoot
$collector = Join-Path $here 'Send-NutanixToSentinel.ps1'
$runner    = Join-Path $here 'run-collector.ps1'
$configOut = Join-Path $here 'host-config.psd1'
$secretsOut= Join-Path $here 'secrets.dat'

Write-Host "=== Nutanix -> Sentinel collector host setup ===`n" -ForegroundColor Cyan

# ------------------------------------------------------------------------------------
# 1. Preflight
# ------------------------------------------------------------------------------------
Write-Host "[1/6] Preflight checks ..."

foreach ($f in @($collector, $runner)) {
    if (-not (Test-Path $f)) { throw "Missing required file: $f. Copy the whole 'collector' folder to this machine." }
}

Write-Host "  PowerShell edition: $($PSVersionTable.PSEdition) $($PSVersionTable.PSVersion)"
# Force TLS 1.2 for the connectivity probes and for the collector's REST calls.
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# Prompt for secrets if not supplied on the command line.
if (-not $ClientSecret)  { $ClientSecret  = Read-Host "  Enter the Entra app CLIENT SECRET" -AsSecureString }
if (-not $PrismApiKey -and -not $PrismPassword) { $PrismPassword = Read-Host "  Enter the Prism password for '$PrismUser'" -AsSecureString }

function Get-PlainText { param([securestring]$s)
    $b = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($s)
    try { [Runtime.InteropServices.Marshal]::PtrToStringBSTR($b) }
    finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($b) }
}

if (-not $SkipConnectivityTest) {
    $targets = @(
        @{ Name = 'Prism Central'; Host = ([uri]$PrismBaseUrl).Host },
        @{ Name = 'Entra login';   Host = 'login.microsoftonline.com' },
        @{ Name = 'DCE ingest';    Host = ([uri]$DceIngestUri).Host }
    )
    foreach ($t in $targets) {
        $ok = (Test-NetConnection -ComputerName $t.Host -Port 443 -WarningAction SilentlyContinue).TcpTestSucceeded
        $mark = if ($ok) { 'OK ' } else { 'FAIL' }
        $color = if ($ok) { 'Green' } else { 'Red' }
        Write-Host ("  [{0}] 443 -> {1} ({2})" -f $mark, $t.Name, $t.Host) -ForegroundColor $color
        if (-not $ok -and $t.Name -eq 'Prism Central') {
            Write-Warning "  This host cannot reach Prism at $($t.Host):443. If Prism is on a private LAN, ensure this machine has a route/VPN."
        }
    }
}

# ------------------------------------------------------------------------------------
# 2. Encrypt secrets (machine-scoped DPAPI)
# ------------------------------------------------------------------------------------
Write-Host "`n[2/6] Encrypting secrets (machine-scoped DPAPI) ..."
Add-Type -AssemblyName System.Security -ErrorAction SilentlyContinue
function Protect-Value { param([string]$Plain)
    $bytes = [Text.Encoding]::UTF8.GetBytes($Plain)
    $enc   = [Security.Cryptography.ProtectedData]::Protect(
        $bytes, $null, [Security.Cryptography.DataProtectionScope]::LocalMachine)
    return [Convert]::ToBase64String($enc)
}

$secretsObj = [ordered]@{
    ClientSecret  = Protect-Value (Get-PlainText $ClientSecret)
}
if ($PrismApiKey)   { $secretsObj.PrismApiKey   = Protect-Value (Get-PlainText $PrismApiKey) }
if ($PrismPassword) { $secretsObj.PrismPassword = Protect-Value (Get-PlainText $PrismPassword) }
$secretsObj | ConvertTo-Json | Set-Content -Path $secretsOut -Encoding UTF8
Write-Host "  Wrote $secretsOut"

# ------------------------------------------------------------------------------------
# 3. Write non-secret config
# ------------------------------------------------------------------------------------
Write-Host "`n[3/6] Writing host-config.psd1 ..."
$psd = @"
@{
    TenantId         = '$TenantId'
    ClientId         = '$ClientId'
    DceIngestUri     = '$DceIngestUri'
    DcrImmutableId   = '$DcrImmutableId'
    StreamName       = '$StreamName'
    PrismBaseUrl     = '$PrismBaseUrl'
    PrismUser        = '$PrismUser'
    PrismApiVersion  = '$PrismApiVersion'
    PrismInsecureTls = `$$([bool]$PrismInsecureTls)
}
"@
Set-Content -Path $configOut -Value $psd -Encoding UTF8
Write-Host "  Wrote $configOut"

# ------------------------------------------------------------------------------------
# 4. Lock down ACLs on the sensitive files
# ------------------------------------------------------------------------------------
Write-Host "`n[4/6] Restricting file permissions ..."
foreach ($f in @($secretsOut, $configOut)) {
    try {
        icacls $f /inheritance:r /grant:r "SYSTEM:F" "Administrators:F" | Out-Null
        Write-Host "  Locked $f (SYSTEM + Administrators only)"
    } catch {
        Write-Warning "  Could not tighten ACL on $f : $($_.Exception.Message)"
    }
}

# ------------------------------------------------------------------------------------
# 5. Register the scheduled task
# ------------------------------------------------------------------------------------
Write-Host "`n[5/6] Registering scheduled task '$TaskName' (every $IntervalMinutes min, run as $RunAsUser) ..."
$psExe   = (Get-Command powershell.exe).Source
$argLine = "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$runner`""
$action  = New-ScheduledTaskAction -Execute $psExe -Argument $argLine -WorkingDirectory $here
$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) `
            -RepetitionInterval (New-TimeSpan -Minutes $IntervalMinutes)
$settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -MultipleInstances IgnoreNew `
            -ExecutionTimeLimit (New-TimeSpan -Minutes 30) -RestartCount 2 -RestartInterval (New-TimeSpan -Minutes 2)
$principal = New-ScheduledTaskPrincipal -UserId $RunAsUser -LogonType ServiceAccount -RunLevel Highest

Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger `
    -Settings $settings -Principal $principal -Force | Out-Null
Write-Host "  Task registered." -ForegroundColor Green

# ------------------------------------------------------------------------------------
# 6. Optional smoke test
# ------------------------------------------------------------------------------------
if ($SmokeTest) {
    Write-Host "`n[6/6] Smoke test (dry run, 2h lookback) ..." -ForegroundColor Cyan
    & $runner -WhatIfNoSend -LookbackMinutes 120
} else {
    Write-Host "`n[6/6] Skipped smoke test (pass -SmokeTest to run one)."
}

Write-Host "`n=== Setup complete ===" -ForegroundColor Cyan
Write-Host "Run now on demand : Start-ScheduledTask -TaskName '$TaskName'"
Write-Host "Check last result : Get-ScheduledTaskInfo -TaskName '$TaskName'"
Write-Host "Manual dry run    : .\run-collector.ps1 -WhatIfNoSend -LookbackMinutes 120"
Write-Host "IMPORTANT: run only ONE collector host to avoid double-ingestion."
