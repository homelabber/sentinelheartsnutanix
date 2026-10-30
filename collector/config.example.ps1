# Nutanix -> Sentinel connector (Option B) configuration.
# Copy to a private location and load before running the collector. DO NOT COMMIT with real values.

# --- Microsoft Entra app (client credentials) used to call the Logs Ingestion API ---
$env:AAD_TENANT_ID     = "<tenant-guid>"
$env:AAD_CLIENT_ID     = "<app-registration-client-id>"
$env:AAD_CLIENT_SECRET = "<app-client-secret>"

# --- DCR ingestion target (from `az deployment ... outputs` of arm/dcr.json) ---
$env:DCE_INGEST_URI    = "https://<dce-name>-<hash>.<region>.ingest.monitor.azure.com"
$env:DCR_IMMUTABLE_ID  = "dcr-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
$env:DCR_STREAM_NAME   = "Custom-NutanixInbound"

# --- Nutanix Prism Central (v4 REST API; verified on PC 7.5.2) ---
$env:PRISM_BASE_URL    = "https://prism-central.example.local:9440"
# Preferred: a Prism Central service-account API key (sent as X-ntnx-api-key).
# $env:PRISM_API_KEY   = "<prism-api-key>"
# Fallback: basic auth (ignored when PRISM_API_KEY is set).
$env:PRISM_USER        = "svc-sentinel"
$env:PRISM_PASSWORD    = "<prism-password>"
# monitoring namespace API version. v4.0 is GA on 7.5.2; set v4.1/v4.2 only if your build serves them.
$env:PRISM_API_VERSION = "v4.0"
# clustermgmt namespace API version, used for the AOS/PC/AHV version inventory.
$env:PRISM_CLUSTERMGMT_API_VERSION = "v4.0"
# Lab only: set to skip TLS validation for self-signed Prism certs. Leave unset in production.
# $env:PRISM_INSECURE_TLS = "1"
