[CmdletBinding()]
param(
    [ValidateSet('bootstrap', 'validate', 'build', 'test', 'scan', 'repair-eval', 'real-eval', 'llm-probe', 'llm-eval', 'popular-eval', 'popular-llm-eval', 'calibration-eval', 'calibration-llm-eval', 'up', 'down', 'logs', 'ps')]
    [string]$Action = 'up',
    [string]$Repository = '',
    [string]$Output = '',
    [ValidateSet('json', 'markdown')]
    [string]$Format = 'markdown',
    [ValidateSet('auto', 'off', 'required')]
    [string]$Sast = 'required',
    [ValidateSet('on', 'off')]
    [string]$Dataflow = 'on',
    [ValidateSet('never', 'low', 'medium', 'high', 'critical')]
    [string]$FailOn = 'never',
    [switch]$VerifiedOnly,
    [string[]]$ExcludeDir = @()
)

$ErrorActionPreference = 'Stop'
$projectRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$envPath = Join-Path $projectRoot '.env'

function Import-LegacyLimaEnvironment([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path)) { return }
    $fileValues = @{}
    foreach ($rawLine in Get-Content -LiteralPath $Path) {
        $line = $rawLine.Trim()
        if (-not $line -or $line.StartsWith('#') -or -not $line.Contains('=')) { continue }
        $key, $value = $line.Split('=', 2)
        $fileValues[$key.Trim()] = $value.Trim()
    }
    foreach ($legacyKey in @($fileValues.Keys | Where-Object { $_.StartsWith('EVOAGENT_') })) {
        $newKey = 'LIMA_' + $legacyKey.Substring('EVOAGENT_'.Length)
        $processValue = [Environment]::GetEnvironmentVariable($newKey, 'Process')
        if (-not $processValue -and -not $fileValues.ContainsKey($newKey)) {
            [Environment]::SetEnvironmentVariable($newKey, $fileValues[$legacyKey], 'Process')
        }
    }
}

function Ensure-LimaDataVolumes(
    [string[]]$VolumeNames = @(
        'security-agent_postgres_data',
        'security-agent_redis_data'
    )
) {
    foreach ($volumeName in $VolumeNames) {
        docker volume create $volumeName | Out-Null
        if ($LASTEXITCODE -ne 0) {
            throw "Unable to create or reuse the LIMA compatibility volume '$volumeName'."
        }
    }
}

Push-Location $projectRoot
try {
    if ($Action -eq 'bootstrap') {
        & (Join-Path $PSScriptRoot 'bootstrap_docker_env.ps1')
        return
    }

    if (-not (Test-Path -LiteralPath $envPath)) {
        throw 'Missing .env. Run: powershell -ExecutionPolicy Bypass -File scripts/lima.ps1 bootstrap'
    }
    Import-LegacyLimaEnvironment $envPath

    switch ($Action) {
        'validate' { docker compose config --quiet }
        'build' { docker compose build lima }
        'test' {
            docker build --target test --tag lima:test .
            if ($LASTEXITCODE -eq 0) {
                docker run --rm --read-only --tmpfs /tmp:rw,size=256m lima:test
            }
        }
        'scan' {
            if (-not $Repository) {
                throw "The scan action requires -Repository <path>."
            }
            $repositoryItem = Get-Item -LiteralPath $Repository -ErrorAction Stop
            if (-not $repositoryItem.PSIsContainer) {
                throw "Repository must be a directory: $Repository"
            }
            $repositoryPath = $repositoryItem.FullName
            if (-not $Output) {
                $extension = if ($Format -eq 'json') { 'json' } else { 'md' }
                $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
                $Output = Join-Path $projectRoot "output\repository-audit-$stamp.$extension"
            }
            elseif (-not [IO.Path]::IsPathRooted($Output)) {
                $Output = Join-Path $projectRoot $Output
            }
            $outputPath = [IO.Path]::GetFullPath($Output)
            $outputDirectory = Split-Path -Parent $outputPath
            New-Item -ItemType Directory -Path $outputDirectory -Force | Out-Null
            $outputName = Split-Path -Leaf $outputPath
            $repositoryMount = "type=bind,source=$repositoryPath,target=/workspace,readonly"
            $outputMount = "type=bind,source=$outputDirectory,target=/output"
            $scanArguments = @(
                'scripts/scan_repository.py', '/workspace', '--sast', $Sast,
                '--dataflow', $Dataflow,
                '--format', $Format, '--output', "/output/$outputName",
                '--fail-on', $FailOn
            )
            if ($VerifiedOnly) {
                $scanArguments += '--verified-only'
            }
            $normalizedExcludeDirectories = @(
                $ExcludeDir | ForEach-Object { $_ -split ',' } | ForEach-Object { $_.Trim() } |
                    Where-Object { $_ }
            )
            foreach ($directory in $normalizedExcludeDirectories) {
                $scanArguments += @('--exclude-dir', $directory)
            }

            docker compose build lima
            if ($LASTEXITCODE -eq 0) {
                docker run --rm --network none --read-only `
                    --tmpfs /tmp:rw,size=256m --cap-drop ALL `
                    --security-opt no-new-privileges:true `
                    --mount $repositoryMount --mount $outputMount `
                    lima:local python $scanArguments
            }
            if ($LASTEXITCODE -eq 0) {
                Write-Output "Repository audit written to $outputPath"
            }
        }
        'repair-eval' {
            if (-not $Output) {
                $extension = if ($Format -eq 'json') { 'json' } else { 'md' }
                $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
                $Output = Join-Path $projectRoot "output\repair-evaluation-$stamp.$extension"
            }
            elseif (-not [IO.Path]::IsPathRooted($Output)) {
                $Output = Join-Path $projectRoot $Output
            }
            $outputPath = [IO.Path]::GetFullPath($Output)
            $outputDirectory = Split-Path -Parent $outputPath
            New-Item -ItemType Directory -Path $outputDirectory -Force | Out-Null
            $outputName = Split-Path -Leaf $outputPath
            $outputMount = "type=bind,source=$outputDirectory,target=/output"
            docker compose build lima
            if ($LASTEXITCODE -eq 0) {
                docker run --rm --network none --read-only `
                    --tmpfs /tmp:rw,size=64m --cap-drop ALL `
                    --security-opt no-new-privileges:true `
                    --mount $outputMount lima:local python `
                    scripts/run_repair_evaluation.py --format $Format `
                    --output "/output/$outputName" --min-constraint-accuracy 1.0
            }
            if ($LASTEXITCODE -eq 0) {
                Write-Output "Repair evaluation written to $outputPath"
            }
        }
        'real-eval' {
            $resultDirectory = if ($Output) {
                if ([IO.Path]::IsPathRooted($Output)) { $Output } else { Join-Path $projectRoot $Output }
            } else {
                Join-Path $projectRoot 'output'
            }
            $resultDirectory = [IO.Path]::GetFullPath($resultDirectory)
            New-Item -ItemType Directory -Path $resultDirectory -Force | Out-Null
            $outputMount = "type=bind,source=$resultDirectory,target=/output"
            $cacheVolume = 'lima-real-eval-cache'
            $null = docker volume create $cacheVolume
            if ($LASTEXITCODE -eq 0) {
                docker build --target real-eval --tag lima:real-eval .
            }
            if ($LASTEXITCODE -eq 0) {
                docker run --rm --user 0:0 --read-only --tmpfs /tmp:rw,size=256m `
                    --cap-drop ALL --security-opt no-new-privileges:true `
                    --mount "type=volume,source=$cacheVolume,target=/cache" `
                    --mount $outputMount lima:real-eval python `
                    scripts/run_real_world_evaluation.py --mode fetch `
                    --cache /cache --output /output/real-world-fetch.json
            }
            if ($LASTEXITCODE -eq 0) {
                docker run --rm --network none --read-only --tmpfs /tmp:rw,size=256m `
                    --cap-drop ALL --security-opt no-new-privileges:true `
                    --mount "type=volume,source=$cacheVolume,target=/cache,readonly" `
                    --mount $outputMount lima:real-eval python `
                    scripts/run_real_world_evaluation.py --mode deterministic `
                    --dataflow off --cache /cache `
                    --output /output/real-world-fast-baseline.json
            }
            if ($LASTEXITCODE -eq 0) {
                docker run --rm --network none --read-only --tmpfs /tmp:rw,size=256m `
                    --cap-drop ALL --security-opt no-new-privileges:true `
                    --mount "type=volume,source=$cacheVolume,target=/cache,readonly" `
                    --mount $outputMount lima:real-eval python `
                    scripts/run_real_world_evaluation.py --mode retrieval `
                    --dataflow off --cache /cache `
                    --output /output/real-world-retrieval.json
            }
            if ($LASTEXITCODE -eq 0) {
                docker run --rm --network none --read-only --tmpfs /tmp:rw,size=64m `
                    --cap-drop ALL --security-opt no-new-privileges:true `
                    -e LIMA_ISOLATED_REAL_PROJECT_TESTS=1 `
                    --mount "type=volume,source=$cacheVolume,target=/cache,readonly" `
                    --mount $outputMount lima:real-eval python `
                    scripts/run_real_world_evaluation.py --mode oracle `
                    --cache /cache --output /output/real-world-oracles.json
            }
            if ($LASTEXITCODE -eq 0) {
                Write-Output "Real-world baseline and Oracle reports written to $resultDirectory"
            }
        }
        'llm-probe' {
            docker build --target real-eval --tag lima:real-eval .
            if ($LASTEXITCODE -eq 0) {
                docker run --rm --read-only --tmpfs /tmp:rw,size=64m `
                    --cap-drop ALL --security-opt no-new-privileges:true `
                    --env-file $envPath lima:real-eval python `
                    scripts/probe_llm_triage.py
            }
        }
        'llm-eval' {
            $resultDirectory = if ($Output) {
                if ([IO.Path]::IsPathRooted($Output)) { $Output } else { Join-Path $projectRoot $Output }
            } else {
                Join-Path $projectRoot 'output'
            }
            $resultDirectory = [IO.Path]::GetFullPath($resultDirectory)
            New-Item -ItemType Directory -Path $resultDirectory -Force | Out-Null
            $outputMount = "type=bind,source=$resultDirectory,target=/output"
            $cacheVolume = 'lima-real-eval-cache'
            $null = docker volume create $cacheVolume
            if ($LASTEXITCODE -eq 0) {
                docker build --target real-eval --tag lima:real-eval .
            }
            if ($LASTEXITCODE -eq 0) {
                docker run --rm --network none --read-only `
                    --cap-drop ALL --security-opt no-new-privileges:true `
                    --env-file $envPath lima:real-eval python -c `
                    "from lima.config import Settings; resolved = Settings.from_env().resolved_llm(); assert resolved, 'LLM mode is not configured'"
            }
            if ($LASTEXITCODE -eq 0) {
                docker run --rm --user 0:0 --read-only --tmpfs /tmp:rw,size=256m `
                    --cap-drop ALL --security-opt no-new-privileges:true `
                    --mount "type=volume,source=$cacheVolume,target=/cache" `
                    --mount $outputMount lima:real-eval python `
                    scripts/run_real_world_evaluation.py --mode fetch `
                    --cache /cache --output /output/real-world-fetch.json
            }
            if ($LASTEXITCODE -eq 0) {
                docker run --rm --read-only --tmpfs /tmp:rw,size=256m `
                    --cap-drop ALL --security-opt no-new-privileges:true `
                    --env-file $envPath `
                    --mount "type=volume,source=$cacheVolume,target=/cache,readonly" `
                    --mount $outputMount lima:real-eval python `
                    scripts/run_real_world_evaluation.py --mode llm-retrieval --dataflow off `
                    --cache /cache --output /output/real-world-llm-retrieval-ab.json
            }
            if ($LASTEXITCODE -eq 0) {
                Write-Output "Real LLM retrieval A/B report written to $resultDirectory\real-world-llm-retrieval-ab.json"
            }
        }
        'popular-eval' {
            $resultDirectory = if ($Output) {
                if ([IO.Path]::IsPathRooted($Output)) { $Output } else { Join-Path $projectRoot $Output }
            } else {
                Join-Path $projectRoot 'output\v1.4-popular-holdout'
            }
            $resultDirectory = [IO.Path]::GetFullPath($resultDirectory)
            New-Item -ItemType Directory -Path $resultDirectory -Force | Out-Null
            $outputMount = "type=bind,source=$resultDirectory,target=/output"
            $cacheVolume = 'lima-popular-holdout-cache-v1'
            $dataset = '/app/evaluation_data/popular_external_holdout.json'
            $null = docker volume create $cacheVolume
            if ($LASTEXITCODE -eq 0) {
                docker build --target real-eval --tag lima:real-eval .
            }
            if ($LASTEXITCODE -eq 0) {
                docker run --rm --user 0:0 --read-only --tmpfs /tmp:rw,size=256m `
                    --cap-drop ALL --security-opt no-new-privileges:true `
                    --mount "type=volume,source=$cacheVolume,target=/cache" `
                    --mount $outputMount lima:real-eval python `
                    scripts/run_real_world_evaluation.py --mode fetch --dataset $dataset `
                    --cache /cache --output /output/popular-fetch.json
            }
            if ($LASTEXITCODE -eq 0) {
                docker run --rm --network none --read-only --tmpfs /tmp:rw,size=256m `
                    --cap-drop ALL --security-opt no-new-privileges:true `
                    --mount "type=volume,source=$cacheVolume,target=/cache,readonly" `
                    --mount $outputMount lima:real-eval python `
                    scripts/run_real_world_evaluation.py --mode retrieval --dataflow off `
                    --dataset $dataset --cache /cache `
                    --output /output/popular-retrieval-baseline.json
            }
            if ($LASTEXITCODE -eq 0) {
                Write-Output "Popular external-holdout baseline written to $resultDirectory\popular-retrieval-baseline.json"
            }
        }
        'popular-llm-eval' {
            $resultDirectory = if ($Output) {
                if ([IO.Path]::IsPathRooted($Output)) { $Output } else { Join-Path $projectRoot $Output }
            } else {
                Join-Path $projectRoot 'output\v1.4-popular-holdout'
            }
            $resultDirectory = [IO.Path]::GetFullPath($resultDirectory)
            New-Item -ItemType Directory -Path $resultDirectory -Force | Out-Null
            $outputMount = "type=bind,source=$resultDirectory,target=/output"
            $cacheVolume = 'lima-popular-holdout-cache-v1'
            $dataset = '/app/evaluation_data/popular_external_holdout.json'
            $null = docker volume create $cacheVolume
            if ($LASTEXITCODE -eq 0) {
                docker build --target real-eval --tag lima:real-eval .
            }
            if ($LASTEXITCODE -eq 0) {
                docker run --rm --network none --read-only `
                    --cap-drop ALL --security-opt no-new-privileges:true `
                    --env-file $envPath lima:real-eval python -c `
                    "from lima.config import Settings; resolved = Settings.from_env().resolved_llm(); assert resolved, 'LLM mode is not configured'"
            }
            if ($LASTEXITCODE -eq 0) {
                docker run --rm --user 0:0 --read-only --tmpfs /tmp:rw,size=256m `
                    --cap-drop ALL --security-opt no-new-privileges:true `
                    --mount "type=volume,source=$cacheVolume,target=/cache" `
                    --mount $outputMount lima:real-eval python `
                    scripts/run_real_world_evaluation.py --mode fetch --dataset $dataset `
                    --cache /cache --output /output/popular-fetch.json
            }
            if ($LASTEXITCODE -eq 0) {
                docker run --rm --read-only --tmpfs /tmp:rw,size=256m `
                    --cap-drop ALL --security-opt no-new-privileges:true `
                    --env-file $envPath `
                    --mount "type=volume,source=$cacheVolume,target=/cache,readonly" `
                    --mount $outputMount lima:real-eval python `
                    scripts/run_real_world_evaluation.py --mode llm-retrieval --dataflow off `
                    --dataset $dataset --cache /cache `
                    --output /output/popular-llm-retrieval.json
            }
            if ($LASTEXITCODE -eq 0) {
                Write-Output "Popular external-holdout LLM report written to $resultDirectory\popular-llm-retrieval.json"
            }
        }
        'calibration-eval' {
            $resultDirectory = if ($Output) {
                if ([IO.Path]::IsPathRooted($Output)) { $Output } else { Join-Path $projectRoot $Output }
            } else {
                Join-Path $projectRoot 'output\v1.5-popular-calibration'
            }
            $resultDirectory = [IO.Path]::GetFullPath($resultDirectory)
            New-Item -ItemType Directory -Path $resultDirectory -Force | Out-Null
            $outputMount = "type=bind,source=$resultDirectory,target=/output"
            $cacheVolume = 'lima-popular-holdout-cache-v1'
            $dataset = '/app/evaluation_data/popular_calibration_v1.json'
            $null = docker volume create $cacheVolume
            if ($LASTEXITCODE -eq 0) {
                docker build --target real-eval --tag lima:real-eval .
            }
            if ($LASTEXITCODE -eq 0) {
                docker run --rm --user 0:0 --read-only --tmpfs /tmp:rw,size=256m `
                    --cap-drop ALL --security-opt no-new-privileges:true `
                    --mount "type=volume,source=$cacheVolume,target=/cache" `
                    --mount $outputMount lima:real-eval python `
                    scripts/run_real_world_evaluation.py --mode fetch --dataset $dataset `
                    --cache /cache --output /output/calibration-fetch.json
            }
            if ($LASTEXITCODE -eq 0) {
                docker run --rm --network none --read-only --tmpfs /tmp:rw,size=256m `
                    --cap-drop ALL --security-opt no-new-privileges:true `
                    --mount "type=volume,source=$cacheVolume,target=/cache,readonly" `
                    --mount $outputMount lima:real-eval python `
                    scripts/run_real_world_evaluation.py --mode retrieval --dataflow off `
                    --dataset $dataset --cache /cache `
                    --output /output/calibration-retrieval.json
            }
            if ($LASTEXITCODE -eq 0) {
                Write-Output "Calibration baseline written to $resultDirectory\calibration-retrieval.json"
            }
        }
        'calibration-llm-eval' {
            $resultDirectory = if ($Output) {
                if ([IO.Path]::IsPathRooted($Output)) { $Output } else { Join-Path $projectRoot $Output }
            } else {
                Join-Path $projectRoot 'output\v1.5-popular-calibration'
            }
            $resultDirectory = [IO.Path]::GetFullPath($resultDirectory)
            New-Item -ItemType Directory -Path $resultDirectory -Force | Out-Null
            $outputMount = "type=bind,source=$resultDirectory,target=/output"
            $cacheVolume = 'lima-popular-holdout-cache-v1'
            $dataset = '/app/evaluation_data/popular_calibration_v1.json'
            $null = docker volume create $cacheVolume
            if ($LASTEXITCODE -eq 0) {
                docker build --target real-eval --tag lima:real-eval .
            }
            if ($LASTEXITCODE -eq 0) {
                docker run --rm --network none --read-only `
                    --cap-drop ALL --security-opt no-new-privileges:true `
                    --env-file $envPath lima:real-eval python -c `
                    "from lima.config import Settings; resolved = Settings.from_env().resolved_llm(); assert resolved, 'LLM mode is not configured'"
            }
            if ($LASTEXITCODE -eq 0) {
                docker run --rm --user 0:0 --read-only --tmpfs /tmp:rw,size=256m `
                    --cap-drop ALL --security-opt no-new-privileges:true `
                    --mount "type=volume,source=$cacheVolume,target=/cache" `
                    --mount $outputMount lima:real-eval python `
                    scripts/run_real_world_evaluation.py --mode fetch --dataset $dataset `
                    --cache /cache --output /output/calibration-fetch.json
            }
            if ($LASTEXITCODE -eq 0) {
                docker run --rm --read-only --tmpfs /tmp:rw,size=256m `
                    --cap-drop ALL --security-opt no-new-privileges:true `
                    --env-file $envPath `
                    --mount "type=volume,source=$cacheVolume,target=/cache,readonly" `
                    --mount $outputMount lima:real-eval python `
                    scripts/run_real_world_evaluation.py --mode llm-retrieval --dataflow off `
                    --dataset $dataset --cache /cache `
                    --output /output/calibration-llm-retrieval.json
            }
            if ($LASTEXITCODE -eq 0) {
                Write-Output "Calibration LLM report written to $resultDirectory\calibration-llm-retrieval.json"
            }
        }
        'up' {
            Ensure-LimaDataVolumes
            docker compose up --build --detach
            if ($LASTEXITCODE -eq 0) { docker compose ps }
        }
        'down' { docker compose down }
        'logs' { docker compose logs --follow --tail 200 lima }
        'ps' { docker compose ps }
    }

    if ($LASTEXITCODE -ne 0) {
        throw "Docker action '$Action' failed with exit code $LASTEXITCODE."
    }
}
finally {
    Pop-Location
}
