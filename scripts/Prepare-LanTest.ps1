param([Parameter(Mandatory=$true)][string]$ServerAddress)
$ErrorActionPreference = 'Stop'
& (Join-Path $PSScriptRoot 'directlan-cert.exe') -address $ServerAddress -out (Join-Path $PSScriptRoot 'test-server')
if ($LASTEXITCODE) { throw 'Certificate preparation failed.' }
Write-Host "Coordinator URL: https://${ServerAddress}:4433"
Write-Host 'Copy test-server\ca.pem to the second PC. Do not copy server-key.pem.'
