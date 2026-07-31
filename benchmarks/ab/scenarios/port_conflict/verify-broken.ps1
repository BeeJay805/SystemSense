$ErrorActionPreference = "Stop"
$scenarioRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$python = if ($env:SYSTEMSENSE_AB_PYTHON) {
    $env:SYSTEMSENSE_AB_PYTHON
} else {
    (Get-Command python.exe -ErrorAction Stop).Source
}

$previousErrorPreference = $ErrorActionPreference
$ErrorActionPreference = "Continue"
& $python (Join-Path $scenarioRoot "app.py") --check-bind 2>$null
$bindExitCode = $LASTEXITCODE
$ErrorActionPreference = $previousErrorPreference
if ($bindExitCode -eq 0) {
    throw "Broken-state oracle failed: the application can still bind port 8000."
}

@{
    oracle = "broken"
    passed = $true
    observed = "address_in_use"
} | ConvertTo-Json -Compress
