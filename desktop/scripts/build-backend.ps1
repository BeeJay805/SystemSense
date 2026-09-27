$ErrorActionPreference = 'Stop'
$desktopRoot = Split-Path $PSScriptRoot -Parent
$repoRoot = Split-Path $desktopRoot -Parent
$python = Join-Path $desktopRoot 'backend\.venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $python)) {
    & uv venv (Join-Path $desktopRoot 'backend\.venv') --python 3.12
    if ($LASTEXITCODE -ne 0) { throw 'Python environment creation failed' }
}
& uv export --project $repoRoot --frozen --no-dev --no-emit-project --format requirements-txt --output-file (Join-Path $desktopRoot 'backend\runtime-requirements.txt') | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Locked runtime dependency export failed' }
& uv pip install --python $python --requirement (Join-Path $desktopRoot 'backend\runtime-requirements.txt') 'pyinstaller==6.22.0'
if ($LASTEXITCODE -ne 0) { throw 'Locked runtime dependencies failed' }
& uv pip install --python $python --no-deps --reinstall-package systemsense $repoRoot
if ($LASTEXITCODE -ne 0) { throw 'Backend build dependencies failed' }
Push-Location (Join-Path $desktopRoot 'backend')
try {
    & $python -m PyInstaller --noconfirm --clean --onedir --name investigator --collect-all systemsense --hidden-import win32timezone launcher.py
    if ($LASTEXITCODE -ne 0) { throw 'Backend packaging failed' }
} finally { Pop-Location }
