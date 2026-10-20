$ErrorActionPreference = 'Stop'
$env:GIT_TERMINAL_PROMPT = '0'
$env:GCM_INTERACTIVE = 'never'
$credentialLines = "protocol=https`nhost=github.com`npath=agent-sec-labs/LIMA.git`n`n" | & git -c credential.interactive=never credential fill 2>$null
$credentialParts = @{}
foreach ($line in $credentialLines) {
    $pair = $line -split '=', 2
    if ($pair.Count -eq 2) { $credentialParts[$pair[0]] = $pair[1] }
}
if (-not $credentialParts['password']) { throw 'No non-interactive GitHub credential available' }
$requestHeaders = @{ Authorization = ('Bearer ' + $credentialParts['password']); Accept = 'application/vnd.github+json'; 'X-GitHub-Api-Version' = '2022-11-28' }
$apiRoot = 'https://api.github.com/repos/agent-sec-labs/LIMA'
try {
    $labels = @(Invoke-RestMethod -Method Get -Uri ($apiRoot + '/labels?per_page=100') -Headers $requestHeaders)
    if (-not ($labels | Where-Object name -EQ 'phase:post-competition')) {
        $payload = @{ name = 'phase:post-competition'; color = 'C5DEF5'; description = '赛后开发；不纳入本届比赛提交或代码冻结门禁' } | ConvertTo-Json -Compress
        $created = Invoke-RestMethod -Method Post -Uri ($apiRoot + '/labels') -Headers $requestHeaders -ContentType 'application/json; charset=utf-8' -Body ([Text.Encoding]::UTF8.GetBytes($payload))
        Write-Output ('Created label: ' + $created.name)
    } else { Write-Output 'Label already exists: phase:post-competition' }
    $confirmed = Invoke-RestMethod -Method Get -Uri ($apiRoot + '/labels/phase%3Apost-competition') -Headers $requestHeaders
    Write-Output ('Verified label: ' + $confirmed.name)
    Write-Output ('Existing labels: ' + (($labels | ForEach-Object name) -join ', '))
} catch { throw ('GitHub label request failed; status ' + [int]$_.Exception.Response.StatusCode) }
