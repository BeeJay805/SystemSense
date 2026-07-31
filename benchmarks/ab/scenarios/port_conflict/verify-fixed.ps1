$ErrorActionPreference = "Stop"
$scenarioRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$stateRoot = if ($env:SYSTEMSENSE_AB_STATE_DIR) {
    [System.IO.Path]::GetFullPath($env:SYSTEMSENSE_AB_STATE_DIR)
} else {
    Join-Path $env:TEMP "systemsense-ab-port-conflict"
}
$python = if ($env:SYSTEMSENSE_AB_PYTHON) {
    $env:SYSTEMSENSE_AB_PYTHON
} else {
    (Get-Command python.exe -ErrorAction Stop).Source
}
$stdoutPath = Join-Path $stateRoot "oracle.stdout.log"
$stderrPath = Join-Path $stateRoot "oracle.stderr.log"

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

New-Item -ItemType Directory -Path $stateRoot -Force | Out-Null
$process = Start-Process `
    -FilePath $python `
    -ArgumentList @("app.py") `
    -WorkingDirectory $scenarioRoot `
    -WindowStyle Hidden `
    -RedirectStandardOutput $stdoutPath `
    -RedirectStandardError $stderrPath `
    -PassThru
try {
    $healthy = $false
    for ($attempt = 0; $attempt -lt 40; $attempt++) {
        if ($process.HasExited) {
            break
        }
        try {
            $response = Invoke-WebRequest `
                -Uri "http://127.0.0.1:8000/health" `
                -UseBasicParsing `
                -TimeoutSec 1
            $content = if ($response.Content -is [byte[]]) {
                [System.Text.Encoding]::UTF8.GetString($response.Content)
            } else {
                [string]$response.Content
            }
            if ($response.StatusCode -eq 200 -and $content.Trim() -eq "ok") {
                $healthy = $true
                break
            }
        } catch {
        }
        Start-Sleep -Milliseconds 50
    }
    if (-not $healthy) {
        $errorText = if (Test-Path -LiteralPath $stderrPath) {
            Get-Content -LiteralPath $stderrPath -Raw
        } else {
            "no stderr captured"
        }
        throw "Fixed-state oracle failed: $errorText"
    }
    @{
        oracle = "fixed"
        passed = $true
        health = "ok"
    } | ConvertTo-Json -Compress
} finally {
    Stop-ScenarioProcessTree -RootProcessId $process.Id
    Wait-Process -Id $process.Id -ErrorAction SilentlyContinue
}
