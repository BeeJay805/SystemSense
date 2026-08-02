param([switch]$Ephemeral)

$ErrorActionPreference = "Stop"
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
$pidPath = Join-Path $stateRoot "fault.pid"
$stdoutPath = Join-Path $stateRoot "fault.stdout.log"
$stderrPath = Join-Path $stateRoot "fault.stderr.log"

if (-not $Ephemeral) {
    New-Item -ItemType Directory -Path $stateRoot -Force | Out-Null
}
if (-not $Ephemeral -and (Test-Path -LiteralPath $pidPath)) {
    $existingPid = [int](Get-Content -LiteralPath $pidPath -Raw)
    if (Get-Process -Id $existingPid -ErrorAction SilentlyContinue) {
        throw "The scenario fault is already active as PID $existingPid."
    }
    Remove-Item -LiteralPath $pidPath -Force
}

$listener = [System.Net.Sockets.TcpListener]::new(
    [System.Net.IPAddress]::Loopback,
    8000
)
try {
    $listener.Start()
} catch {
    throw "Port 8000 is already occupied before fault injection."
} finally {
    $listener.Stop()
}

if (-not $Ephemeral) {
    New-Item -ItemType File -Path $stdoutPath, $stderrPath -Force | Out-Null
}
$commandLine = "`"$python`" -m http.server 8000 --bind 127.0.0.1"
$created = Invoke-CimMethod `
    -ClassName Win32_Process `
    -MethodName Create `
    -Arguments @{ CommandLine = $commandLine }
if ($created.ReturnValue -ne 0 -or -not $created.ProcessId) {
    throw "Fault process creation failed with code $($created.ReturnValue)."
}
$process = Get-Process -Id ([int]$created.ProcessId) -ErrorAction Stop
if (-not $Ephemeral) {
    $process.Id | Set-Content -LiteralPath $pidPath -Encoding ascii -NoNewline
}

$ready = $false
for ($attempt = 0; $attempt -lt 40; $attempt++) {
    if ($process.HasExited) {
        throw "Fault process exited before it owned port 8000."
    }
    try {
        $client = [System.Net.Sockets.TcpClient]::new()
        $client.Connect("127.0.0.1", 8000)
        $client.Dispose()
        $ready = $true
        break
    } catch {
        Start-Sleep -Milliseconds 50
    }
}
if (-not $ready) {
    Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
    throw "Fault process did not own port 8000 within two seconds."
}

@{
    fault = "port_conflict"
    pid = $process.Id
    port = 8000
    state = "injected"
} | ConvertTo-Json -Compress
