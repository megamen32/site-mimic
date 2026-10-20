# Trust the mitmproxy CA in the CURRENT-USER root store (no admin needed,
# fully reversible). Chrome trusts the current-user Root store, so this is
# enough to intercept HTTPS for a capture session.
#
# Run AFTER mitmdump has generated the CA (any mitmdump run creates
# ~\.mitmproxy\mitmproxy-ca-cert.cer). Removes nothing pre-existing; only
# ADDS the mitm CA. To undo, run untrust_ca.ps1.
#
# Usage:
#   powershell -ExecutionPolicy Bypass -File trust_ca.ps1
#   powershell -ExecutionPolicy Bypass -File trust_ca.ps1 -CerPath D:\ca.cer
param(
    [string]$CerPath = (Join-Path $env:USERPROFILE ".mitmproxy\mitmproxy-ca-cert.cer"),
    [string]$ThumbFile = (Join-Path $env:USERPROFILE "site-mimic-capture\mitm_ca_thumbprint.txt")
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path $CerPath)) {
    Write-Error "mitm CA not found at $CerPath. Run mitmdump once first to generate it."
    exit 1
}

Write-Output "Adding mitm CA to current-user Root store: $CerPath"
$out = & certutil -user -addstore Root $CerPath
$out | ForEach-Object { Write-Output $_ }

# Capture the SHA1 thumbprint so untrust_ca.ps1 can delete exactly this cert.
$hashLine = $out | Where-Object { $_ -match 'Cert Hash\(sha1\)' } | Select-Object -First 1
if ($hashLine -and $hashLine -match ':\s*([0-9a-fA-F ]{19,})') {
    $hash = ($matches[1] -replace ' ', '').ToLower()
    $null = New-Item -ItemType Directory -Force -Path (Split-Path $ThumbFile)
    Set-Content -Path $ThumbFile -Value $hash -Encoding ascii
    Write-Output "OK: saved sha1=$hash to $ThumbFile"
    Write-Output "Chrome sees the CA on next launch. To remove later: untrust_ca.ps1"
} else {
    Write-Output "WARN: could not parse SHA1 for auto-removal. To remove manually:"
    Write-Output "  certutil -user -store Root | findstr /I mitmproxy"
    Write-Output "  certutil -user -delstore Root <sha1-without-spaces>"
}
