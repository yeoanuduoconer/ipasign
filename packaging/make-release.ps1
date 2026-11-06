# Build a portable Windows release: dist\ipasign-<version>-win-x64.zip
#
#   pwsh -File packaging\make-release.ps1
#
# The archive contains the single-file executable and the documentation.

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
Set-Location $root

$version = (Select-String -Path "ipasign\__init__.py" -Pattern '__version__ = "(.+)"').Matches[0].Groups[1].Value
Write-Host "[..] version $version"

# 1) build the executable
python -m PyInstaller --noconfirm --clean --distpath dist --workpath build packaging\ipasign.spec
if (-not (Test-Path "dist\ipasign.exe")) { throw "build failed: dist\ipasign.exe is missing" }

# 2) assemble the release directory
$stage = "build\release"
if (Test-Path $stage) { Remove-Item $stage -Recurse -Force }
New-Item -ItemType Directory -Force $stage | Out-Null
Copy-Item "dist\ipasign.exe" $stage
Copy-Item "README.md" "$stage\README.md"
Copy-Item "THIRD_PARTY_NOTICES.md" "$stage\THIRD_PARTY_NOTICES.md"

@"
ipasign $version (win-x64)
=========================

Run ipasign.exe directly; no Python installation is required.

The executable bundles the Python runtime, every dependency and the native
sign-in libraries.  Signing, sign-in, certificate issuing and auto-renew work
without any other software.

The only system-level requirement is Apple's USB driver (iTunes or the
"Apple Devices" app) on Windows, and only for installing over a cable.

See README.md for usage and THIRD_PARTY_NOTICES.md for licensing.
"@ | Set-Content "$stage\README.txt" -Encoding UTF8

# 3) zip it
$zip = "dist\ipasign-$version-win-x64.zip"
if (Test-Path $zip) { Remove-Item $zip -Force }
Compress-Archive -Path "$stage\*" -DestinationPath $zip -CompressionLevel Optimal

Write-Host "[done] $zip"
Write-Host ("       {0:N1} MB" -f ((Get-Item $zip).Length / 1MB))
