$ErrorActionPreference = 'Stop'
$plan = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'publication-plan.json') -Raw -Encoding utf8 | ConvertFrom-Json
if ($plan.repository -ne 'agent-sec-labs/LIMA') { throw 'Unexpected target repository' }
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
function Api([string]$Method, [string]$Url, $Payload = $null) {
    try {
        if ($null -eq $Payload) { return Invoke-RestMethod -Method $Method -Uri $Url -Headers $requestHeaders }
        $json = $Payload | ConvertTo-Json -Depth 100 -Compress
        return Invoke-RestMethod -Method $Method -Uri $Url -Headers $requestHeaders -ContentType 'application/json; charset=utf-8' -Body ([Text.Encoding]::UTF8.GetBytes($json))
    } catch { throw ('GitHub ' + $Method + ' failed; status ' + [int]$_.Exception.Response.StatusCode) }
}
$label = Api 'Get' ($apiRoot + '/labels/phase%3Apost-competition')
if ($label.name -ne 'phase:post-competition') { throw 'Required post-competition label is missing' }
$existing = [Collections.Generic.List[object]]::new()
for ($page = 1; $page -le 20; $page++) {
    $batch = @(Api 'Get' ($apiRoot + '/issues?state=all&per_page=100&page=' + $page))
    foreach ($item in $batch) { if (-not $item.pull_request) { $existing.Add($item) } }
    if ($batch.Count -lt 100) { break }
    if ($page -eq 20) { throw 'Issue inventory pagination limit reached' }
}
$results = [Collections.Generic.List[object]]::new()
$numbers = @{}
$expected = @{}
function Save-Results {
    $results.ToArray() | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath (Join-Path $PSScriptRoot 'publication-results.json') -Encoding utf8
}
function Publish($item, [string]$Body) {
    if (-not $item.title.StartsWith('[赛后开发]')) { throw 'Missing post-competition title prefix' }
    if (-not $Body.Contains('不纳入本届比赛')) { throw 'Missing scheduling boundary' }
    $matches = @($existing | Where-Object title -CEQ $item.title)
    if ($matches.Count -gt 1) { throw ('Duplicate titles for ' + $item.key) }
    if ($matches.Count -eq 1) {
        $issue = $matches[0]
        if ($item.key -ne 'EPIC' -and $issue.body -cne $Body) { throw ('Existing issue body differs: ' + $item.key) }
        $action = 'reused'
    } else {
        $issue = Api 'Post' ($apiRoot + '/issues') @{ title = $item.title; body = $Body; labels = @('phase:post-competition') }
        $existing.Add($issue)
        $action = 'created'
    }
    if (-not $issue.number -or -not $issue.html_url) { throw 'Incomplete GitHub issue response' }
    $numbers[$item.key] = [int]$issue.number
    $expected[$item.key] = [pscustomobject]@{ title = $item.title; body = $Body }
    $Body | Set-Content -LiteralPath (Join-Path $PSScriptRoot ($item.key + '.md')) -Encoding utf8 -NoNewline
    $results.Add([pscustomobject]@{ key = $item.key; number = $issue.number; url = $issue.html_url; title = $issue.title; action = $action; labels = @($issue.labels | ForEach-Object name) })
    Save-Results
    Write-Output ($action + ' ' + $item.key + ' #' + $issue.number + ' ' + $issue.html_url)
}
Publish $plan.epic $plan.epic.body
foreach ($item in $plan.items) {
    $body = $item.body.Replace('{{EPIC}}', ('#' + $numbers['EPIC']))
    foreach ($key in $numbers.Keys) { $body = $body.Replace(('{{' + $key + '}}'), ('#' + $numbers[$key])) }
    if ($body.Contains('{{')) { throw ('Unresolved dependency in ' + $item.key) }
    Publish $item $body
}
$lines = @('## 已发布子任务', '')
foreach ($item in $plan.items) { $lines += ('- [ ] #' + $numbers[$item.key] + ' — ' + $item.title) }
$finalEpicBody = $plan.epic.body + "`n`n" + ($lines -join "`n")
$currentEpic = Api 'Get' ($apiRoot + '/issues/' + $numbers['EPIC'])
if ($currentEpic.body -cne $plan.epic.body -and $currentEpic.body -cne $finalEpicBody) { throw 'Epic changed concurrently; refusing to overwrite' }
if ($currentEpic.body -cne $finalEpicBody) { $null = Api 'Patch' ($apiRoot + '/issues/' + $numbers['EPIC']) @{body = $finalEpicBody} }
$expected['EPIC'].body = $finalEpicBody
$finalEpicBody | Set-Content -LiteralPath (Join-Path $PSScriptRoot 'EPIC.md') -Encoding utf8 -NoNewline
foreach ($result in $results) {
    $actual = Api 'Get' ($apiRoot + '/issues/' + $result.number)
    if ($actual.title -cne $expected[$result.key].title -or $actual.body -cne $expected[$result.key].body) { throw ('Readback mismatch: ' + $result.key) }
    if (-not ($actual.labels | Where-Object name -EQ 'phase:post-competition')) { throw ('Missing phase label: ' + $result.key) }
    if ($actual.state -ne 'open') { throw ('Unexpected issue state: ' + $result.key) }
    $result | Add-Member -NotePropertyName verified -NotePropertyValue $true -Force
}
Save-Results
Write-Output 'All 7 issues verified: titles, bodies, scheduling labels and open state.'
