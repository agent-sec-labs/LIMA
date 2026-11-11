param([Parameter(Mandatory=$true)][string]$PlanPath,[Parameter(Mandatory=$true)][string]$ResultsPath)
$ErrorActionPreference='Stop'
$env:GIT_TERMINAL_PROMPT='0'
$env:GCM_INTERACTIVE='never'
$credentialText = "protocol=https`nhost=github.com`npath=agent-sec-labs/LIMA.git`n`n" | & git -c credential.interactive=never credential fill 2>$null
$credentialParts=@{}
foreach($entry in $credentialText){$pair=$entry -split '=',2; if($pair.Count -eq 2){$credentialParts[$pair[0]]=$pair[1]}}
if(-not $credentialParts['password']) {throw 'No non-interactive GitHub credential available'}
$requestHeaders=@{Authorization=('Bearer '+$credentialParts['password']);Accept='application/vnd.github+json';'X-GitHub-Api-Version'='2022-11-28'}
$plan=Get-Content -LiteralPath $PlanPath -Raw -Encoding utf8 | ConvertFrom-Json
if($plan.repository -ne 'agent-sec-labs/LIMA'){throw 'Unexpected repository'}
$api='https://api.github.com/repos/'+$plan.repository
function Api([string]$Method,[string]$Url,$Payload=$null){
  try {
    if($null -eq $Payload){return Invoke-RestMethod -Method $Method -Uri $Url -Headers $requestHeaders}
    $json=$Payload | ConvertTo-Json -Depth 100 -Compress
    return Invoke-RestMethod -Method $Method -Uri $Url -Headers $requestHeaders -ContentType 'application/json; charset=utf-8' -Body ([Text.Encoding]::UTF8.GetBytes($json))
  }catch {throw ('GitHub '+$Method+' failed; status '+[int]$_.Exception.Response.StatusCode)}
}
$results=[Collections.Generic.List[object]]::new()
function Save-Results { $results.ToArray() | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $ResultsPath -Encoding utf8 }
foreach($item in $plan.create){
  $recent=@(Api 'Get' ($api+'/issues?state=all&per_page=100&sort=created&direction=desc'))
  $match=@($recent | Where-Object {$_.title -eq $item.title -and -not $_.pull_request})
  if($match.Count -gt 1){throw ('Duplicate existing titles for '+$item.key)}
  if($match.Count -eq 1){
    if($match[0].body -cne $item.body){throw ('Existing title has different body: '+$item.key)}
    $created=$match[0];$action='reused'
  }else{
    $created=Api 'Post' ($api+'/issues') @{title=$item.title;body=$item.body;labels=@('enhancement')}
    $action='created'
  }
  $results.Add([pscustomobject]@{key=$item.key;number=$created.number;url=$created.html_url;action=$action})
  Save-Results
  Write-Output ($action+' '+$item.key+' #'+$created.number+' '+$created.html_url)
}
foreach($item in $plan.update){
  $current=Api 'Get' ($api+'/issues/'+$item.number)
  if($current.state -ne 'open'){throw ('Issue state changed; stop before modifying #'+$item.number)}
  $titleOkay=($null -eq $item.title -or $current.title -ceq $item.title)
  if($current.body -ceq $item.body -and $titleOkay){$updated=$current;$action='already-updated'}
  else{
    if($current.body -cne $item.expected_body){throw ('Issue body changed concurrently; stop before modifying #'+$item.number)}
    $payload=@{body=$item.body}
    if($item.title){$payload.title=$item.title}
    $updated=Api 'Patch' ($api+'/issues/'+$item.number) $payload
    $action='updated'
  }
  $results.Add([pscustomobject]@{key=('existing-'+$item.number);number=$updated.number;url=$updated.html_url;action=$action})
  Save-Results
  Write-Output ($action+' #'+$updated.number+' '+$updated.html_url)
}
foreach($item in $plan.create){
  $entry=$results | Where-Object key -EQ $item.key | Select-Object -First 1
  $actual=Api 'Get' ($api+'/issues/'+$entry.number)
  if($actual.body -cne $item.body -or $actual.title -cne $item.title){throw ('Read-back failed: '+$item.key)}
}
foreach($item in $plan.update){
  $actual=Api 'Get' ($api+'/issues/'+$item.number)
  if($actual.body -cne $item.body){throw ('Read-back failed: #'+$item.number)}
}
Write-Output 'All issue titles/bodies read back successfully.'

