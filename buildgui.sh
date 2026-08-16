#!/bin/bash
# NetScan GUI 构建脚本(Unix: Linux/macOS)
# 用法: ./buildgui.sh
# GUI 基于 WebView, 依赖系统图形库:
#   Linux: 需要 webkit2gtk (如 Ubuntu: libwebkit2gtk-4.0-dev)
#   macOS: 依赖系统 WKWebView(无需额外安装)
# 需在对应平台本机构建(WebView 不支持交叉编译)。

set -e
root="$(cd "$(dirname "$0")" && pwd)"
dist="$root/dist"
mkdir -p "$dist"

version="dev"
if v=$(git -C "$root" describe --tags --always --dirty 2>/dev/null); then
  [ -n "$v" ] && version="$v"
fi
echo "版本: $version"

os="$(go env GOOS)"
arch="$(go env GOARCH)"
case "$arch" in
  amd64) a="x64" ;;
  386)   a="x86" ;;
  *)     a="$arch" ;;
esac

out="$dist/netscan-gui-$os-$a"
echo "编译 GUI: $os/$a -> $(basename "$out")"
CGO_ENABLED=1 go build -trimpath -ldflags "-s -w -X main.version=$version" -o "$out" ./cmd/gui

echo ""
echo "GUI 构建完成: $out"
