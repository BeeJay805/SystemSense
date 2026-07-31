$ErrorActionPreference = "Stop"
$stateRoot = if ($env:SYSTEMSENSE_AB_STATE_DIR) {
    [System.IO.Path]::GetFullPath($env:SYSTEMSENSE_AB_STATE_DIR)
} else {
    Join-Path $env:TEMP "systemsense-ab-port-conflict"
}
$pidPath = Join-Path $stateRoot "fault.pid"

function Stop-ScenarioProcessTree {
    param([int]$RootProcessId)
    $children = Get-CimInstance Win32_Process `
        -Filter "ParentProcessId = $RootProcessId" `
        -ErrorAction SilentlyContinue
    foreach ($child in $children) {
        Stop-ScenarioProcessTree -RootProcessId ([int]$child.ProcessId)
    }
    Stop-Process -Id $RootProcessId -Force -ErrorAction SilentlyContinue
}

if (-not (Test-Path -LiteralPath $pidPath)) {
    throw "The injected fault PID is unavailable."
}

$faultPid = [int](Get-Content -LiteralPath $pidPath -Raw)
$process = Get-Process -Id $faultPid -ErrorAction SilentlyContinue
if ($process) {
    Stop-ScenarioProcessTree -RootProcessId $faultPid
    Wait-Process -Id $faultPid -ErrorAction SilentlyContinue
}
Remove-Item -LiteralPath $pidPath -Force

@{
    repair = "stop_conflicting_process"
    pid = $faultPid
    state = "repaired"
} | ConvertTo-Json -Compress
