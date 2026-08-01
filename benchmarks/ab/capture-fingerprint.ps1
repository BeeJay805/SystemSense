param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("baseline", "systemsense")]
    [string]$Arm,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$CloneId,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$ParentSnapshotId,

    [Parameter(Mandatory = $true)]
    [ValidateScript({ Test-Path -LiteralPath $_ -PathType Container })]
    [string]$ScenarioRoot
)

$ErrorActionPreference = "Stop"

function Get-CanonicalHash {
    param([string[]]$Lines)
    $normalized = (($Lines | Sort-Object) -join "`n")
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($normalized)
    $hasher = [System.Security.Cryptography.SHA256]::Create()
    try {
        return [BitConverter]::ToString($hasher.ComputeHash($bytes)).
            Replace("-", "").
            ToLowerInvariant()
    } finally {
        $hasher.Dispose()
    }
}

function Get-RegistryLines {
    param([string[]]$Paths)
    $lines = [System.Collections.Generic.List[string]]::new()
    foreach ($path in $Paths) {
        if (-not (Test-Path -LiteralPath $path)) {
            continue
        }
        Get-ChildItem -LiteralPath $path -Recurse -ErrorAction SilentlyContinue |
            Sort-Object Name |
            ForEach-Object {
                $key = $_
                $properties = Get-ItemProperty -LiteralPath $key.PSPath -ErrorAction SilentlyContinue
                foreach ($property in $properties.PSObject.Properties |
                    Where-Object { $_.Name -notlike "PS*" } |
                    Sort-Object Name) {
                    $lines.Add("$($key.Name)|$($property.Name)|$($property.Value)")
                }
            }
    }
    return $lines.ToArray()
}

$scenarioRootPath = [System.IO.Path]::GetFullPath($ScenarioRoot)
$python = if ($env:SYSTEMSENSE_AB_PYTHON) {
    $env:SYSTEMSENSE_AB_PYTHON
} else {
    (Get-Command python.exe -ErrorAction Stop).Source
}

$osKey = Get-ItemProperty `
    -LiteralPath "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion"
$osLines = @(
    "ProductName=$($osKey.ProductName)",
    "DisplayVersion=$($osKey.DisplayVersion)",
    "CurrentBuild=$($osKey.CurrentBuild)",
    "UBR=$($osKey.UBR)",
    "Architecture=$env:PROCESSOR_ARCHITECTURE"
)
$powershellLines = @(
    "Edition=$($PSVersionTable.PSEdition)",
    "Version=$($PSVersionTable.PSVersion)",
    "CLR=$($PSVersionTable.CLRVersion)"
)
$packageInventoryScript = @'
from importlib.metadata import distributions

packages = (
    '{}=={}'.format(distribution.metadata.get('Name'), distribution.version)
    for distribution in distributions()
    if distribution.metadata.get('Name')
)
print('\n'.join(sorted(packages, key=str.casefold)))
'@
$pythonPackages = @(
    "Python=$(& $python --version 2>&1)"
    & $python -c $packageInventoryScript 2>$null
)

$softwareRoots = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
)
$softwareLines = foreach ($root in $softwareRoots) {
    if (Test-Path -LiteralPath $root) {
        Get-ChildItem -LiteralPath $root -ErrorAction SilentlyContinue |
            ForEach-Object {
                $item = Get-ItemProperty -LiteralPath $_.PSPath -ErrorAction SilentlyContinue
                if ($item.DisplayName) {
                    "$($item.DisplayName)|$($item.DisplayVersion)|$($item.Publisher)"
                }
            }
    }
}

$driverLines = Get-CimInstance Win32_PnPSignedDriver -ErrorAction SilentlyContinue |
    ForEach-Object {
        "$($_.DeviceID)|$($_.DriverVersion)|$($_.DriverProviderName)|$($_.InfName)"
    }
$policyLines = Get-RegistryLines @(
    "HKLM:\SOFTWARE\Policies",
    "HKCU:\SOFTWARE\Policies"
)
$serviceLines = Get-CimInstance Win32_Service -ErrorAction SilentlyContinue |
    ForEach-Object {
        "$($_.Name)|$($_.StartMode)|$($_.PathName)"
    }
$scenarioLines = Get-ChildItem -LiteralPath $scenarioRootPath -File -Recurse |
    Sort-Object FullName |
    ForEach-Object {
        $relative = $_.FullName.Substring($scenarioRootPath.Length).TrimStart("\")
        $hash = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        "$relative|$hash"
    }

$faultLines = Get-NetTCPConnection `
    -LocalPort 8000 `
    -State Listen `
    -ErrorAction SilentlyContinue |
    ForEach-Object {
        $owner = Get-CimInstance Win32_Process `
            -Filter "ProcessId = $($_.OwningProcess)" `
            -ErrorAction SilentlyContinue
        "$($_.LocalAddress)|$($_.LocalPort)|$($owner.Name)|$($owner.ExecutablePath)|$($owner.CommandLine)"
    }
$systemSenseLines = @(
    "Version=$(& $python -c `"import systemsense; print(systemsense.__version__)`" 2>&1)",
    "Location=$(& $python -c `"import pathlib, systemsense; print(pathlib.Path(systemsense.__file__).resolve())`" 2>&1)"
)

[ordered]@{
    schema_version = 1
    arm = $Arm
    clone_id = $CloneId
    parent_snapshot_id = $ParentSnapshotId
    state = [ordered]@{
        os = Get-CanonicalHash $osLines
        powershell = Get-CanonicalHash $powershellLines
        python_packages = Get-CanonicalHash $pythonPackages
        installed_software = Get-CanonicalHash $softwareLines
        drivers = Get-CanonicalHash $driverLines
        policies = Get-CanonicalHash $policyLines
        services = Get-CanonicalHash $serviceLines
        scenario_files = Get-CanonicalHash $scenarioLines
        fault_state = Get-CanonicalHash $faultLines
        systemsense = Get-CanonicalHash $systemSenseLines
    }
} | ConvertTo-Json -Depth 4
