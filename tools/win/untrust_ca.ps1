# Remove the mitmproxy CA from the CURRENT-USER root store (undo of
# trust_ca.ps1). Reads the SHA1 thumbprint saved by trust_ca.ps1 and deletes
# exactly that cert. Falls back to listing mitmproxy certs if the thumbprint
# file is missing.
#
# Usage:
#   powershell -ExecutionPolicy Bypass -File untrust_ca.ps1
param(
    [string]$ThumbFile = (Join-Path $env:USERPROFILE "site-mimic-capture\mitm_ca_thumbprint.txt")
)

if (Test-Path $ThumbFile) {
    $hash = (Get-Content $ThumbFile -Raw).Trim()
    if ($hash -match '^[0-9a-f]{40}$') {
        Write-Output "Removing mitm CA (sha1=$hash) from current-user Root store"
        & certutil -user -delstore Root $hash
        Remove-Item $ThumbFile -ErrorAction SilentlyContinue
        Write-Output "Done. mitm CA no longer trusted."
    } else {
        Write-Output "Saved thumbprint looks invalid: '$hash'. Listing mitmproxy certs in Root:"
        & certutil -user -store Root | Select-String -Pattern "mitmproxy" -Context 2,8
    }
} else {
    Write-Output "No saved thumbprint at $ThumbFile. mitmproxy certs in current-user Root:"
    & certutil -user -store Root | Select-String -Pattern "mitmproxy" -Context 2,8
    Write-Output "If a mitmproxy cert is listed, delete it with:"
    Write-Output "  certutil -user -delstore Root <sha1-without-spaces>"
}
