param(
    [switch]$RefreshMap
)

$ErrorActionPreference = 'Stop'
$repoRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
Push-Location $repoRoot
try {
    $head = (& git rev-parse --short=12 HEAD).Trim()
    $branch = (& git branch --show-current).Trim()
    $upstream = & git rev-parse --abbrev-ref --symbolic-full-name '@{upstream}' 2>$null
    $dirty = @(& git status --porcelain=v1)
    Write-Output "Repository: $repoRoot"
    Write-Output "Branch/HEAD: $branch $head"
    if ($LASTEXITCODE -eq 0 -and $upstream) {
        $counts = (& git rev-list --left-right --count "HEAD...$upstream").Trim() -split '\s+'
        Write-Output "Tracking ref: $upstream (ahead $($counts[0]), behind $($counts[1]); no fetch)"
    } else {
        Write-Output 'Tracking ref: none'
    }
    Write-Output "Working tree: $($dirty.Count) changed/untracked paths"
    if ($dirty.Count) { $dirty | ForEach-Object { Write-Output "  $_" } }
    Write-Output 'Worktrees:'
    & git worktree list

    if ($RefreshMap) {
        $mapDir = Join-Path $repoRoot 'tmp\code-map'
        New-Item -ItemType Directory -Path $mapDir -Force | Out-Null
        $sourceDirty = @(& git status --porcelain=v1 -- src)
        $suffix = if ($sourceDirty.Count) { "-$((Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ'))-working" } else { '' }
        $stem = "code-map-$head$suffix"
        $map = Join-Path $mapDir "$stem.json"
        $python = Join-Path $repoRoot '.venv\Scripts\python.exe'
        if (-not (Test-Path -LiteralPath $python)) { $python = 'python' }
        & $python (Join-Path $repoRoot 'scripts\code_map.py') build --repo $repoRoot --output $map
        if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $map)) { throw 'Code map generation failed.' }
        Write-Output "Static code map: $map"
        Write-Output "Find one symbol: .\.venv\Scripts\python.exe scripts\code_map.py find --map '$map' --query Investigator"
        if ($sourceDirty.Count) { Write-Output 'Map includes uncommitted source and does not represent clean HEAD.' }
    }
} finally {
    Pop-Location
}
