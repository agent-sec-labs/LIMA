[CmdletBinding()]
param(
    [string]$Image = 'lima:test'
)

$ErrorActionPreference = 'Stop'
$projectRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$limaScript = Join-Path $projectRoot 'scripts/lima.ps1'
$marker = 'lima-volume-regression-marker'
$dockerApplication = @(Get-Command docker -CommandType Application -ErrorAction Stop)[0].Source

function Invoke-DockerApplication {
    param([Parameter(ValueFromRemainingArguments = $true)][object[]]$DockerArguments)

    & $dockerApplication @DockerArguments
    if ($LASTEXITCODE -ne 0) {
        throw "Docker command failed with exit code ${LASTEXITCODE}: docker $DockerArguments"
    }
}

function Test-DockerVolumeExists([string]$VolumeName) {
    $nameFilter = 'name=^{0}$' -f [regex]::Escape($VolumeName)
    $matches = @(& $dockerApplication volume ls --quiet --filter $nameFilter)
    if ($LASTEXITCODE -ne 0) {
        throw "Unable to check whether Docker volume '$VolumeName' exists."
    }
    return $matches -contains $VolumeName
}

do {
    $suffix = [Guid]::NewGuid().ToString('N')
    $volumeNames = @(
        "lima-regression-postgres-$suffix",
        "lima-regression-redis-$suffix"
    )
    $hasCollision = $false
    foreach ($volumeName in $volumeNames) {
        if (Test-DockerVolumeExists $volumeName) {
            $hasCollision = $true
            break
        }
    }
} while ($hasCollision)
$cleanupVolumeNames = @($volumeNames)
$testFailure = $null
$cleanupFailures = @()

$tokens = $null
$parseErrors = $null
$scriptAst = [System.Management.Automation.Language.Parser]::ParseFile(
    $limaScript,
    [ref]$tokens,
    [ref]$parseErrors
)
if ($parseErrors.Count -gt 0) {
    throw "Unable to parse ${limaScript}: $parseErrors"
}
$functionAst = $scriptAst.Find({
    param($node)
    $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -eq 'Ensure-LimaDataVolumes'
}, $true)
if ($null -eq $functionAst) {
    throw "Ensure-LimaDataVolumes was not found in '$limaScript'."
}
Invoke-Expression $functionAst.Extent.Text

try {
    Ensure-LimaDataVolumes -VolumeNames $volumeNames

    foreach ($volumeName in $volumeNames) {
        Invoke-DockerApplication volume inspect $volumeName | Out-Null
        Invoke-DockerApplication run --rm --user 0:0 `
            --volume "${volumeName}:/data" `
            --entrypoint python $Image -c `
            "from pathlib import Path; Path('/data/marker').write_text('$marker', encoding='utf-8')"
    }

    Ensure-LimaDataVolumes -VolumeNames $volumeNames

    foreach ($volumeName in $volumeNames) {
        $actualMarker = Invoke-DockerApplication run --rm --user 0:0 `
            --volume "${volumeName}:/data" `
            --entrypoint python $Image -c `
            "from pathlib import Path; print(Path('/data/marker').read_text(encoding='utf-8'))"
        if ($actualMarker.Trim() -ne $marker) {
            throw "Repeated volume initialization did not preserve data in '$volumeName'."
        }
    }

}
catch {
    $testFailure = $_
}
finally {
    foreach ($volumeName in $cleanupVolumeNames) {
        try {
            if (-not (Test-DockerVolumeExists $volumeName)) {
                continue
            }
            & $dockerApplication volume rm --force $volumeName *> $null
            if ($LASTEXITCODE -ne 0) {
                $cleanupFailures += "Unable to remove Docker volume '$volumeName'."
            }
        }
        catch {
            $cleanupFailures += "Unable to clean up Docker volume '$volumeName': $($_.Exception.Message)"
        }
    }
}

if ($null -ne $testFailure) {
    if ($cleanupFailures.Count -gt 0) {
        Write-Error ($cleanupFailures -join [Environment]::NewLine) -ErrorAction Continue
    }
    throw $testFailure
}
if ($cleanupFailures.Count -gt 0) {
    throw ($cleanupFailures -join [Environment]::NewLine)
}
Write-Output 'Docker volume creation and idempotent reuse regression test passed.'
