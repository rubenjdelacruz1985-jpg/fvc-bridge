# build.ps1 — package the plugin into build/fvc-bridge.zip (stable root folder)
# and generate build/manifest.json pointing at this version's release asset.
#
#   powershell -File build.ps1
#
# The zip always contains a top-level "fvc-bridge/" folder so WordPress keeps the
# plugin path stable across self-updates.

$ErrorActionPreference = 'Stop'
$repo   = 'rubenjdelacruz1985-jpg/fvc-bridge'
$root   = $PSScriptRoot
$plugin = Join-Path $root 'fvc-bridge.php'

# Read version from the plugin header.
$header = Get-Content $plugin -Raw
if ($header -notmatch '(?m)^\s*\*\s*Version:\s*(.+?)\s*$') { throw 'Could not read Version from fvc-bridge.php header' }
$version = $Matches[1].Trim()
Write-Host "Version: $version"

$build = Join-Path $root 'build'
$stage = Join-Path $build 'fvc-bridge'
if (Test-Path $build) { Remove-Item $build -Recurse -Force }
New-Item -ItemType Directory -Path $stage -Force | Out-Null

# Copy plugin files into the stable folder (add more Copy-Item lines if you add files).
Copy-Item $plugin (Join-Path $stage 'fvc-bridge.php')

$zip = Join-Path $build 'fvc-bridge.zip'
# Build the zip manually with FORWARD-SLASH entry names. PowerShell's
# Compress-Archive writes backslashes, which break extraction on Linux hosts
# (WordPress would create a file named "fvc-bridge\fvc-bridge.php" instead of a folder).
Add-Type -AssemblyName System.IO.Compression | Out-Null
Add-Type -AssemblyName System.IO.Compression.FileSystem | Out-Null
if (Test-Path $zip) { Remove-Item $zip -Force }
$fs = [System.IO.File]::Open($zip, [System.IO.FileMode]::Create)
$archive = New-Object System.IO.Compression.ZipArchive($fs, [System.IO.Compression.ZipArchiveMode]::Create)
try {
    foreach ($f in Get-ChildItem $stage -Recurse -File) {
        $rel = 'fvc-bridge/' + ($f.FullName.Substring($stage.Length + 1) -replace '\\', '/')
        $entry = $archive.CreateEntry($rel, [System.IO.Compression.CompressionLevel]::Optimal)
        $es = $entry.Open()
        $bytes = [System.IO.File]::ReadAllBytes($f.FullName)
        $es.Write($bytes, 0, $bytes.Length)
        $es.Dispose()
    }
} finally {
    $archive.Dispose()
    $fs.Close()
}
Write-Host "Wrote $zip"

# manifest.json — package pinned to this version's release download URL.
$manifest = [ordered]@{
    version = $version
    package = "https://github.com/$repo/releases/download/v$version/fvc-bridge.zip"
}
$manifestPath = Join-Path $build 'manifest.json'
# Write UTF-8 WITHOUT a BOM — PHP's json_decode() fails on a leading BOM.
[System.IO.File]::WriteAllText($manifestPath, ($manifest | ConvertTo-Json), (New-Object System.Text.UTF8Encoding($false)))
Write-Host "Wrote $manifestPath"

Write-Host ""
Write-Host "Next: publish the release (tag must be v$version):"
Write-Host "  gh release create v$version build/fvc-bridge.zip build/manifest.json --repo $repo --title v$version --notes `"FVC Bridge v$version`""
