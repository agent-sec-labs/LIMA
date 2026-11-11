param([switch]$Apply)
$ErrorActionPreference = 'Stop'
$plan = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'annotation-plan.json') -Raw -Encoding utf8 | ConvertFrom-Json
if (-not $Apply) {
    $plan | Select-Object number,kind,label,title | Format-Table -AutoSize
    exit 0
}
$env:GIT_TERMINAL_PROMPT = '0'
$env:GCM_INTERACTIVE = 'never'
$credentialText = "protocol=https`nhost=github.com`npath=agent-sec-labs/LIMA.git`n`n" | & git -c credential.interactive=never credential fill 2>$null
$credentialParts = @{}
foreach ($entry in $credentialText) {
    $pair = $entry -split '=',2
    if ($pair.Count -eq 2) { $credentialParts[$pair[0]] = $pair[1] }
}
if (-not $credentialParts['password']) { throw 'No existing GitHub authorization available' }
$requestHeaders = @{Authorization=('Bearer '+$credentialParts['password']);Accept='application/vnd.github+json';'X-GitHub-Api-Version'='2022-11-28'}
$api = 'https://api.github.com/repos/agent-sec-labs/LIMA'
function Api([string]$Method,[string]$Url,$Payload=$null) {
    try {
        if ($null -eq $Payload) { return Invoke-RestMethod -Method $Method -Uri $Url -Headers $requestHeaders -TimeoutSec 25 }
        $json = $Payload | ConvertTo-Json -Depth 100 -Compress
        return Invoke-RestMethod -Method $Method -Uri $Url -Headers $requestHeaders -TimeoutSec 25 -ContentType 'application/json; charset=utf-8' -Body ([Text.Encoding]::UTF8.GetBytes($json))
    } catch { throw ('GitHub '+$Method+' failed; status '+[int]$_.Exception.Response.StatusCode) }
}
$results = [Collections.Generic.List[object]]::new()
$resultsPath = Join-Path $PSScriptRoot 'annotation-results.json'
foreach ($item in $plan) {
    $current = Api 'Get' ($api+'/issues/'+$item.number)
    if ($current.state -ne 'open' -or $null -ne $current.pull_request) { throw ('Unexpected issue state/type #'+$item.number) }
    if ($current.title -cne $item.title) { throw ('Title changed #'+$item.number) }
    if ($current.body -cne $item.expected_body -and $current.body -cne $item.body) { throw ('Body changed concurrently #'+$item.number) }
    $beforeAssignees = (@($current.assignees | ForEach-Object login) | Sort-Object) -join ','
    $beforeLabels = @($current.labels | ForEach-Object name)
    if ($item.label -and $beforeLabels -notcontains $item.label) {
        $null = Api 'Post' ($api+'/issues/'+$item.number+'/labels') @{labels=@($item.label)}
    }
    if ($current.body -cne $item.body) {
        $null = Api 'Patch' ($api+'/issues/'+$item.number) @{body=$item.body}
    }
    $actual = Api 'Get' ($api+'/issues/'+$item.number)
    $afterAssignees = (@($actual.assignees | ForEach-Object login) | Sort-Object) -join ','
    $afterLabels = @($actual.labels | ForEach-Object name)
    if ($actual.body -cne $item.body -or $actual.state -ne 'open' -or $actual.title -cne $item.title -or $beforeAssignees -cne $afterAssignees) { throw ('Read-back failed #'+$item.number) }
    foreach ($label in $beforeLabels) { if ($afterLabels -notcontains $label) { throw ('Existing label lost #'+$item.number) } }
    if ($item.label -and $afterLabels -notcontains $item.label) { throw ('Missing label #'+$item.number) }
    $results.Add([pscustomobject]@{number=$actual.number;kind=$item.kind;url=$actual.html_url;labels=$afterLabels;assignees=@($actual.assignees | ForEach-Object login);state=$actual.state;verified=$true;updated_at=$actual.updated_at})
    ConvertTo-Json -InputObject @($results.ToArray()) -Depth 10 | Set-Content -LiteralPath $resultsPath -Encoding utf8
    Write-Output ('verified #'+$actual.number+' '+$item.kind)
}
Write-Output ('Verified '+$results.Count+' issue annotations; no issue closed or assignee changed.')
