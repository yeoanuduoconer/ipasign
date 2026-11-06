# 构建发行包：dist\ipasign-<version>-win-x64.zip
#
#   pwsh -File packaging\make-release.ps1
#
# 产物包含单文件可执行程序、安装脚本、卸载脚本和说明文档。

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
Set-Location $root

$version = (Select-String -Path "ipasign\__init__.py" -Pattern '__version__ = "(.+)"').Matches[0].Groups[1].Value
Write-Host "[..] 版本 $version"

# 1) 打包可执行文件
python -m PyInstaller --noconfirm --clean --distpath dist --workpath build packaging\ipasign.spec
if (-not (Test-Path "dist\ipasign.exe")) { throw "打包失败" }

# 2) 组装发行目录
$stage = "build\release"
if (Test-Path $stage) { Remove-Item $stage -Recurse -Force }
New-Item -ItemType Directory -Force $stage | Out-Null
Copy-Item "dist\ipasign.exe" $stage
Copy-Item "packaging\install.cmd" $stage
Copy-Item "packaging\uninstall.cmd" $stage
Copy-Item "README.md" "$stage\README.md"
Copy-Item "THIRD_PARTY_NOTICES.md" "$stage\THIRD_PARTY_NOTICES.md"

@"
ipasign $version (win-x64)
=========================

安装（任选其一）：

  1. 双击 install.cmd，然后新开一个终端输入：ipasign
  2. 直接运行 ipasign.exe

安装脚本会把程序放到 %LOCALAPPDATA%\ipasign\bin，
加入用户 PATH，并创建开始菜单快捷方式（不需要管理员权限）。

卸载：运行 uninstall.cmd

说明见 README.md；第三方许可证见 THIRD_PARTY_NOTICES.md。
"@ | Set-Content "$stage\安装说明.txt" -Encoding UTF8

# 3) 打 zip
$zip = "dist\ipasign-$version-win-x64.zip"
if (Test-Path $zip) { Remove-Item $zip -Force }
Compress-Archive -Path "$stage\*" -DestinationPath $zip -CompressionLevel Optimal

Write-Host "[完成] $zip"
Write-Host ("        {0:N1} MB" -f ((Get-Item $zip).Length / 1MB))
