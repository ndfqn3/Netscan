# NetScan CLI 构建脚本(Windows)
# 用法: powershell -ExecutionPolicy Bypass -File buildcli.ps1
# 仅编译 CLI(纯 Go, 可交叉编译到所有主流平台), 不编译 GUI。
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

$cliTargets = @(
    @{ os = "windows"; arch = "amd64" },
    @{ os = "windows"; arch = "386" },
    @{ os = "windows"; arch = "arm64" },
    @{ os = "linux";   arch = "amd64" },
    @{ os = "linux";   arch = "386" },
    @{ os = "linux";   arch = "arm64" },
    @{ os = "darwin";  arch = "amd64" },
    @{ os = "darwin";  arch = "arm64" },
    @{ os = "freebsd"; arch = "amd64" },
    @{ os = "freebsd"; arch = "386" },
    @{ os = "freebsd"; arch = "arm64" },
    @{ os = "netbsd";  arch = "amd64" },
    @{ os = "netbsd";  arch = "386" },
    @{ os = "netbsd";  arch = "arm64" },
    @{ os = "openbsd"; arch = "amd64" },
    @{ os = "openbsd"; arch = "386" },
    @{ os = "openbsd"; arch = "arm64" }
)

$env:CGO_ENABLED = "0"
foreach ($t in $cliTargets) {
    $env:GOOS = $t.os
    $env:GOARCH = $t.arch
    $archName = ArchName $t.arch
    $ext = if ($t.os -eq "windows") { ".exe" } else { "" }
    $out = Join-Path $dist "netscan-$($t.os)-$archName$ext"
    Write-Host "编译 CLI: $($t.os)/$archName -> $(Split-Path $out -Leaf)"
    go build -trimpath -ldflags "-s -w -X main.version=$version" -o $out ./cmd/cli
}

Write-Host ""
Write-Host "CLI 构建完成, 产物目录: $dist"
Get-ChildItem $dist -Filter "netscan-*" | Where-Object { $_.Name -notlike "*gui*" } | Sort-Object Name | ForEach-Object {
    Write-Host ("  {0,-42} {1,10:N0} bytes" -f $_.Name, $_.Length)
}
