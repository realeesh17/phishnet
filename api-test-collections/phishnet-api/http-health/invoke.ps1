$ErrorActionPreference = 'Stop'
$response = Invoke-RestMethod -Method Get -Uri 'http://127.0.0.1:7071/health'

if ($response.status -ne 'ok') {
    throw "GET /health returned an unexpected response: $($response | ConvertTo-Json -Compress)"
}

Write-Host 'PASS GET /health (HTTP 200): status=ok'
