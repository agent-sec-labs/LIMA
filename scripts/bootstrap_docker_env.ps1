[CmdletBinding()]
param(
    [switch]$Force
)

$ErrorActionPreference = 'Stop'
$projectRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$envPath = Join-Path $projectRoot '.env'

if ((Test-Path -LiteralPath $envPath) -and -not $Force) {
    throw ".env already exists at $envPath. Use -Force only if rotating all local credentials is intended."
}

function New-RandomBase64([int]$byteCount) {
    $bytes = New-Object byte[] $byteCount
    $generator = [Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $generator.GetBytes($bytes)
    }
    finally {
        $generator.Dispose()
    }
    return [Convert]::ToBase64String($bytes)
}

function New-RandomUrlToken([int]$byteCount) {
    return (New-RandomBase64 $byteCount).TrimEnd('=').Replace('+', '-').Replace('/', '_')
}

$authSecret = New-RandomBase64 48
$adminPassword = New-RandomUrlToken 24
$postgresPassword = New-RandomUrlToken 24

$content = @"
# Generated locally by scripts/bootstrap_docker_env.ps1. Do not commit this file.
LIMA_POSTGRES_PASSWORD=$postgresPassword
LIMA_AUTH_REQUIRED=true
LIMA_AUTH_SECRET=$authSecret
LIMA_BOOTSTRAP_ADMIN_USERNAME=admin
LIMA_BOOTSTRAP_ADMIN_PASSWORD=$adminPassword
LIMA_LLM_PROVIDER=local
LIMA_HTTP_PORT=18080
LIMA_PUBLIC_BASE_URL=http://127.0.0.1:18080
"@

[IO.File]::WriteAllText($envPath, $content, [Text.UTF8Encoding]::new($false))

Write-Output "Created $envPath"
Write-Output 'Local dashboard: http://127.0.0.1:18080'
Write-Output 'Username: admin'
Write-Output "Password: $adminPassword"
Write-Output 'Save the password in a password manager. Remote LLM access remains disabled.'
