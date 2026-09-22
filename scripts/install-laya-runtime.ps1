[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$PythonPath,

    [ValidateSet("cpu", "cuda")]
    [string]$Device = "cuda",

    [string]$InstallRoot = (Join-Path $env:LOCALAPPDATA "SystemSense\runtimes\laya-0.3.5")
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

$Repository = "convaiinnovations/laya-typed-decisions"
$Revision = "f9ab0b228f0fc0f14d873dbc99038f135c2da1b2"
$ExpectedWeightBytes = 842609220
$ExpectedWeightSha256 = "4fa56de72383a9d3efa9cfa78955733c81b9fc8067a587ca4beb82c78107a24e"

if (-not (Test-Path -LiteralPath $PythonPath -PathType Leaf)) {
    throw "PythonPath must identify an existing Python 3.12+ executable."
}
$resolvedPython = (Resolve-Path -LiteralPath $PythonPath).Path
$pythonVersion = & $resolvedPython -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')"
if ($LASTEXITCODE -ne 0 -or [version]$pythonVersion -lt [version]"3.12") {
    throw "Laya installation requires Python 3.12 or newer."
}

$resolvedRoot = [System.IO.Path]::GetFullPath($InstallRoot)
if (Test-Path -LiteralPath $resolvedRoot) {
    throw "InstallRoot already exists; refusing to overwrite: $resolvedRoot"
}
[void](New-Item -ItemType Directory -Path $resolvedRoot)

& $resolvedPython -m venv (Join-Path $resolvedRoot "venv")
if ($LASTEXITCODE -ne 0) { throw "Failed to create the isolated Laya environment." }
$venvPython = Join-Path $resolvedRoot "venv\Scripts\python.exe"

& $venvPython -m pip install --disable-pip-version-check --no-cache-dir --upgrade "pip==25.0.1"
if ($LASTEXITCODE -ne 0) { throw "Failed to install the pinned pip version." }

if ($Device -eq "cuda") {
    & $venvPython -m pip install --disable-pip-version-check --no-cache-dir `
        "torch==2.10.0" --index-url "https://download.pytorch.org/whl/cu128"
} else {
    & $venvPython -m pip install --disable-pip-version-check --no-cache-dir `
        "torch==2.10.0" --index-url "https://download.pytorch.org/whl/cpu"
}
if ($LASTEXITCODE -ne 0) { throw "Failed to install the pinned PyTorch runtime." }

& $venvPython -m pip install --disable-pip-version-check --no-cache-dir `
    "laya @ https://files.pythonhosted.org/packages/ec/1c/a9903d5c3c51579f45f9656f733c8a2d985b16a3cb7594edf45369d1f995/laya-0.3.5-py3-none-any.whl#sha256=4c57f64cbaf893bb5c7b4affddc2bf21a819f55df51941689f11868583be2903" `
    "transformers==5.17.0" `
    "huggingface_hub==1.32.0" `
    "safetensors==0.8.0" `
    "numpy==2.5.3"
if ($LASTEXITCODE -ne 0) { throw "Failed to install the pinned Laya dependencies." }

$modelPath = Join-Path $resolvedRoot "model"
$env:SYSTEMSENSE_LAYA_MODEL_PATH = $modelPath
$env:SYSTEMSENSE_LAYA_REPOSITORY = $Repository
$env:SYSTEMSENSE_LAYA_REVISION = $Revision
$downloadScript = @'
import os
from huggingface_hub import snapshot_download

snapshot_download(
    repo_id=os.environ["SYSTEMSENSE_LAYA_REPOSITORY"],
    revision=os.environ["SYSTEMSENSE_LAYA_REVISION"],
    local_dir=os.environ["SYSTEMSENSE_LAYA_MODEL_PATH"],
    allow_patterns=[
        "model.safetensors",
        "rl_agent_config.json",
        "tokenizer/*",
        "encoder/*",
    ],
)
'@
& $venvPython -c $downloadScript
if ($LASTEXITCODE -ne 0) { throw "Failed to download the pinned Laya artifact." }

$weightPath = Join-Path $modelPath "model.safetensors"
$weight = Get-Item -LiteralPath $weightPath
$actualSha256 = (Get-FileHash -LiteralPath $weightPath -Algorithm SHA256).Hash.ToLowerInvariant()
if ($weight.Length -ne $ExpectedWeightBytes -or $actualSha256 -ne $ExpectedWeightSha256) {
    throw "The downloaded Laya weights do not match the admitted size and SHA-256."
}

$runtimeProbe = & $venvPython -c `
    "import json, torch, transformers; print(json.dumps({'torch': torch.__version__, 'transformers': transformers.__version__, 'cuda': torch.cuda.is_available()}))"
if ($LASTEXITCODE -ne 0) { throw "Failed to inspect the installed Laya runtime." }
$runtime = $runtimeProbe | ConvertFrom-Json
if ($Device -eq "cuda" -and -not $runtime.cuda) {
    throw "The CUDA runtime was requested but PyTorch cannot use CUDA on this host."
}

$manifest = [ordered]@{
    schema_version = 1
    model_repository = $Repository
    model_revision = $Revision
    weight_sha256 = $actualSha256
    weight_bytes = $weight.Length
    package_version = "0.3.5"
    package_wheel_sha256 = "4c57f64cbaf893bb5c7b4affddc2bf21a819f55df51941689f11868583be2903"
    license = "Apache-2.0"
    torch_version = $runtime.torch
    transformers_version = $runtime.transformers
    device_policy = if ($Device -eq "cuda") { "cpu_and_cuda" } else { "cpu_only" }
    acquired_at = [DateTimeOffset]::UtcNow.ToString("o")
}
$manifestJson = $manifest | ConvertTo-Json
$manifestPath = Join-Path $modelPath "INSTALL-MANIFEST.json"
[System.IO.File]::WriteAllText(
    $manifestPath,
    $manifestJson,
    [System.Text.UTF8Encoding]::new($false)
)

Write-Output "Installed admitted Laya runtime at $resolvedRoot"
Write-Output "Weights SHA-256: $actualSha256"
