[CmdletBinding()]
param([string]$ArchivePath)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
# npm can inherit module search paths from a different PowerShell edition.
# Load this shell's built-in utility module before hashing or serializing assets.
Import-Module (Join-Path $PSHOME 'Modules\Microsoft.PowerShell.Utility\Microsoft.PowerShell.Utility.psd1')
$desktopRoot = Split-Path $PSScriptRoot -Parent
$repoRoot = Split-Path $desktopRoot -Parent
$assetRoot = Join-Path $desktopRoot 'setup-assets'
$pythonRoot = Join-Path $assetRoot 'python'
$archiveName = 'cpython-3.12.14+20260814-x86_64-pc-windows-msvc-install_only_stripped.tar.gz'
$expectedHash = '89f18f6932917163b74339ebcec2645c8e47ae7f1c5f2ac37f2b4f4cf3beb647'
$archiveUri = 'https://github.com/astral-sh/python-build-standalone/releases/download/20260814/cpython-3.12.14%2B20260814-x86_64-pc-windows-msvc-install_only_stripped.tar.gz'
$targetArchive = Join-Path $pythonRoot $archiveName
New-Item -ItemType Directory -Force -Path $pythonRoot | Out-Null
if ($ArchivePath) {
    if ((Get-FileHash -LiteralPath $ArchivePath -Algorithm SHA256).Hash.ToLowerInvariant() -ne $expectedHash) {
        throw 'The supplied Python archive does not match the admitted build.'
    }
    Copy-Item -LiteralPath $ArchivePath -Destination $targetArchive
} elseif (-not (Test-Path -LiteralPath $targetArchive)) {
    Invoke-WebRequest -Uri $archiveUri -OutFile $targetArchive
}
if ((Get-FileHash -LiteralPath $targetArchive -Algorithm SHA256).Hash.ToLowerInvariant() -ne $expectedHash) {
    throw 'Packaged Python archive hash mismatch; refusing to build local model setup.'
}
Copy-Item -LiteralPath (Join-Path $repoRoot 'scripts\install-laya-runtime.ps1') -Destination (Join-Path $assetRoot 'install-laya-runtime.ps1')
$receipt = [ordered]@{
    schema_version = 1
    python_version = '3.12.14'
    build = '20260814'
    archive = $archiveName
    archive_sha256 = $expectedHash
    source = $archiveUri
    checksum_source = 'https://github.com/astral-sh/uv/blob/0.12.5/crates/uv-python/download-metadata.json'
    license = 'Python and bundled component licenses are preserved inside the original archive.'
}
[System.IO.File]::WriteAllText((Join-Path $assetRoot 'PROVENANCE.json'), ($receipt | ConvertTo-Json), [System.Text.UTF8Encoding]::new($false))
Write-Output "Prepared the pinned Python archive and trusted local setup script."
