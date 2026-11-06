$ErrorActionPreference = 'Stop'
$response = Invoke-RestMethod -Method Get -Uri 'http://127.0.0.1:7071/api/health'

if ($response.status -ne 'healthy') {
    throw "GET /api/health returned an unexpected response: $($response | ConvertTo-Json -Compress)"
}

Write-Host "PASS GET /api/health (HTTP 200): status=$($response.status)"
