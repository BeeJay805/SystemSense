param([long]$WindowHandle, [string]$OutputPath)
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Drawing
Add-Type @'
using System;
using System.Runtime.InteropServices;
public static class DyadIconReadback {
    [DllImport("user32.dll")] public static extern IntPtr SendMessage(IntPtr window, uint message, IntPtr parameter, IntPtr unused);
    [DllImport("user32.dll", EntryPoint="GetClassLongPtrW")] public static extern IntPtr GetClassLongPtr(IntPtr window, int index);
}
'@
$windowPointer = [IntPtr]::new($WindowHandle)
$iconPointer = [DyadIconReadback]::SendMessage($windowPointer, 0x007F, [IntPtr]::new(1), [IntPtr]::Zero)
if ($iconPointer -eq [IntPtr]::Zero) { $iconPointer = [DyadIconReadback]::GetClassLongPtr($windowPointer, -14) }
if ($iconPointer -eq [IntPtr]::Zero) { throw 'Native window did not report an icon.' }
$icon = [System.Drawing.Icon]::FromHandle($iconPointer)
$bitmap = $icon.ToBitmap()
try {
    $mintPixels = 0
    for ($x = 0; $x -lt $bitmap.Width; $x++) {
        for ($y = 0; $y -lt $bitmap.Height; $y++) {
            $pixel = $bitmap.GetPixel($x, $y)
            if ($pixel.A -gt 128 -and $pixel.G -gt 130 -and $pixel.G -gt ($pixel.R * 1.4) -and $pixel.G -gt ($pixel.B * 1.08)) { $mintPixels++ }
        }
    }
    if ($mintPixels -lt ($bitmap.Width * $bitmap.Height * 0.04)) { throw 'Native window icon does not contain the Dyad mint mark.' }
    $bitmap.Save($OutputPath, [System.Drawing.Imaging.ImageFormat]::Png)
    @{ width = $bitmap.Width; height = $bitmap.Height; mintPixels = $mintPixels } | ConvertTo-Json -Compress
} finally { $bitmap.Dispose(); $icon.Dispose() }
