<#
.SYNOPSIS
    Wrapper that the scheduled task runs. Loads host-config.psd1, decrypts
    secrets.dat (machine-scoped DPAPI), populates the environment variables the
    collector expects, then invokes Send-NutanixToSentinel.ps1.

.DESCRIPTION
    Keeps secrets off the command line and out of plaintext config. Secrets are
    encrypted with DataProtectionScope.LocalMachine so any account on THIS machine
    (including the task's run-as account or SYSTEM) can decrypt them, but they are
    useless if copied to another machine.

    Do not run this by hand for setup -- run setup-host.ps1 once first. You can run
    this manually afterward to test (it behaves exactly like the scheduled task).

.PARAMETER WhatIfNoSend
    Pass through to the collector: fetch from Prism and show what WOULD be sent,
    without POSTing to Azure.

.PARAMETER LookbackMinutes
    Pass through to the collector for the first run when no state.json exists.
#>
[CmdletBinding()]
param(
    [switch] $WhatIfNoSend,
    [int]    $LookbackMinutes = 60
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$here        = $PSScriptRoot
$configPath  = Join-Path $here 'host-config.psd1'
$secretsPath = Join-Path $here 'secrets.dat'
$collector   = Join-Path $here 'Send-NutanixToSentinel.ps1'

foreach ($p in @($configPath, $secretsPath, $collector)) {
    if (-not (Test-Path $p)) { throw "Required file not found: $p. Run setup-host.ps1 first." }
}

# Windows PowerShell 5.1 and PowerShell 7 both ship ProtectedData via System.Security.
Add-Type -AssemblyName System.Security -ErrorAction SilentlyContinue

function Unprotect-Value {
    param([string] $Base64)
    $enc = [Convert]::FromBase64String($Base64)
    $dec = [System.Security.Cryptography.ProtectedData]::Unprotect(
        $enc, $null, [System.Security.Cryptography.DataProtectionScope]::LocalMachine)
    return [System.Text.Encoding]::UTF8.GetString($dec)
}

# --- Load non-secret config (a PowerShell data file: safe to read, no code execution) ---
$cfg = Import-PowerShellDataFile -Path $configPath

# --- Load + decrypt secrets ---
$secretsJson = Get-Content $secretsPath -Raw
$secrets     = $secretsJson | ConvertFrom-Json

# --- Populate environment for the collector ---
$env:AAD_TENANT_ID     = $cfg.TenantId
$env:AAD_CLIENT_ID     = $cfg.ClientId
$env:AAD_CLIENT_SECRET = Unprotect-Value $secrets.ClientSecret
$env:DCE_INGEST_URI    = $cfg.DceIngestUri
$env:DCR_IMMUTABLE_ID  = $cfg.DcrImmutableId
$env:DCR_STREAM_NAME   = $cfg.StreamName
$env:PRISM_BASE_URL    = $cfg.PrismBaseUrl
$env:PRISM_USER        = $cfg.PrismUser
$env:PRISM_PASSWORD    = Unprotect-Value $secrets.PrismPassword
$env:PRISM_API_VERSION = $cfg.PrismApiVersion
if ($cfg.ContainsKey('PrismInsecureTls') -and $cfg.PrismInsecureTls) { $env:PRISM_INSECURE_TLS = '1' }

try {
    & $collector -WhatIfNoSend:$WhatIfNoSend -LookbackMinutes $LookbackMinutes
}
finally {
    # Scrub secrets from the environment of this process before exit.
    Remove-Item Env:AAD_CLIENT_SECRET, Env:PRISM_PASSWORD -ErrorAction SilentlyContinue
}
