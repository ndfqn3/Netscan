#!/bin/bash
# NetScan GUI 构建脚本(Unix: Linux/macOS)
# 用法: ./buildgui.sh
# 会自动 go mod vendor 确保 vendor 目录包含修改过的 webview_go(webkit2gtk-4.1 兼容)

set -e
root="$(cd "$(dirname "$0")" && pwd)"
dist="$root/dist"

if ! command -v go &>/dev/null; then
  echo "❌ 未找到 Go, 请先安装: https://go.dev/dl/"
  exit 1
fi
echo "Go: $(go version 2>/dev/null | sed 's/go version //')"

# macOS
if [ "$(go env GOOS)" = "darwin" ]; then
  mkdir -p "$dist"
  version="dev"
  v=$(git -C "$root" describe --tags --always --dirty 2>/dev/null) && [ -n "$v" ] && version="$v"
  arch="$(go env GOARCH)"; [ "$arch" = "amd64" ] && arch="x64"
  out="$dist/netscan-gui-darwin-$arch"
  echo "编译 GUI -> $(basename "$out")"
  CGO_ENABLED=1 go build -trimpath -ldflags "-s -w -X main.version=$version" -o "$out" ./cmd/gui
  echo "✅ 完成: $out"
  exit 0
fi

# Linux: 检查依赖
echo "检查 Linux GUI 构建依赖..."
missing=""
if ! command -v gcc &>/dev/null; then missing="$missing gcc"; fi
if ! command -v g++ &>/dev/null; then missing="$missing g++"; fi
if ! pkg-config --exists gtk+-3.0 2>/dev/null; then missing="$missing gtk+-3.0"; fi
if ! pkg-config --exists webkit2gtk-4.1 2>/dev/null; then missing="$missing webkit2gtk-4.1"; fi

if [ -n "$missing" ]; then
  echo ""
  echo "❌ 缺少 GUI 构建依赖:$missing"
  echo ""
  echo "安装命令:"
  echo "  Ubuntu 22+:       sudo apt install gcc g++ libgtk-3-dev libwebkit2gtk-4.1-dev"
  echo "  RHEL/CentOS 8+:  sudo dnf install gcc gcc-c++ gtk3-devel webkit2gtk3-devel"
  echo "  Arch Linux:       sudo pacman -S gcc gtk3 webkit2gtk"
  echo ""
  echo "CentOS 7 不支持(webkit2gtk 版本太旧), 请用 CLI: ./buildcli.sh"
  exit 1
fi

# 确保 vendor 目录存在(包含修改过的 webview_go)
if [ ! -d "$root/vendor/github.com/webview" ]; then
  echo "初始化 vendor 目录..."
  cd "$root" && go mod vendor
fi

# 构建
mkdir -p "$dist"
version="dev"
v=$(git -C "$root" describe --tags --always --dirty 2>/dev/null) && [ -n "$v" ] && version="$v"
arch="$(go env GOARCH)"; [ "$arch" = "amd64" ] && a="x64" || a="$arch"
out="$dist/netscan-gui-linux-$a"
echo "编译 GUI: $a -> $(basename "$out")"
CGO_ENABLED=1 go build -trimpath -ldflags "-s -w -X main.version=$version" -o "$out" ./cmd/gui
echo "✅ 完成: $out"
