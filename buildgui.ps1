# NetScan GUI 构建脚本(Windows)
# 用法: powershell -ExecutionPolicy Bypass -File buildgui.ps1
# GUI 基于 WebView2(Windows 10/11 已预装), 需要 CGO。
# 命名: x64 = 64位(amd64), x86 = 32位(386), arm64 = ARM 64位。

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$dist = Join-Path $root "dist"
New-Item -ItemType Directory -Force -Path $dist | Out-Null

# 版本号: 从 git tag 自动注入, 无 tag 时用 commit hash
$version = "dev"
try {
    $v = git -C $root describe --tags --always --dirty 2>$null
    if ($v) { $version = $v.Trim() }
} catch { $version = "dev" }
Write-Host "版本: $version"

function ArchName([string]$arch) {
    switch ($arch) {
        "amd64" { return "x64" }
        "386"   { return "x86" }
        "arm64" { return "arm64" }
        default { return $arch }
    }
}

$env:CGO_ENABLED = "1"
$guiOS = "windows"
$guiArch = go env GOARCH
$guiArchName = ArchName $guiArch
$guiName = "netscan-gui-$guiOS-$guiArchName.exe"
$guiOut = Join-Path $dist $guiName
Write-Host "编译 GUI: $guiOS/$guiArchName -> $guiName"
go build -trimpath -ldflags "-s -w -H windowsgui -X main.version=$version" -o $guiOut ./cmd/gui

Write-Host ""
Write-Host "GUI 构建完成: $guiOut"
