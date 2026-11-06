$ErrorActionPreference = 'Stop'
$samplePath = Join-Path $PSScriptRoot 'sample-data.json'
$body = Get-Content -Raw -LiteralPath $samplePath
$response = Invoke-RestMethod `
    -Method Post `
    -Uri 'http://127.0.0.1:7071/api/analyze' `
    -ContentType 'application/json' `
    -Body $body

if ($response.verdict -notin @('low_concern', 'review', 'high_risk')) {
    throw "POST /api/analyze returned an unexpected response: $($response | ConvertTo-Json -Compress)"
}

Write-Host "PASS POST /api/analyze (HTTP 200): verdict=$($response.verdict); model=$($response.model)"
