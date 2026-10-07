package portscan

import (
	"os"
	"runtime"
	"strings"
)

// isProot 检测是否运行在 Termux/proot 等受限移动环境中
// 判断依据: PREFIX 环境变量、/data/data/com.termux 目录、GOOS=android
func isProot() bool {
	if runtime.GOOS == "android" {
		return true
	}
	if os.Getenv("PREFIX") != "" && strings.Contains(os.Getenv("PREFIX"), "com.termux") {
		return true
	}
	if _, err := os.Stat("/data/data/com.termux"); err == nil {
		return true
	}
	if os.Getenv("TERMUX_VERSION") != "" {
		return true
	}
	return false
}

// applyProotSafety 在 proot 环境下降低并发、禁用 raw socket, 避免崩溃
func applyProotSafety(opts *Options) bool {
	if !isProot() || opts.ForceRaw {
		return false
	}
	// 过滤掉需要 raw socket 的扫描技术
	var types []ScanType
	for _, t := range opts.ScanTypes {
		switch t {
		case ScanTCPSYN, ScanFIN, ScanNULL, ScanXMAS, ScanACK:
			continue
		default:
			types = append(types, t)
		}
	}
	if len(types) > 0 {
		opts.ScanTypes = types
	} else {
		// 所有扫描类型都是 raw socket 类型, 降级为 TCP Connect 扫描
		opts.ScanTypes = []ScanType{ScanTCPConnect}
	}
	// 降低并发
	if opts.Concurrency > 100 {
		opts.Concurrency = 100
	}
	if opts.Rate <= 0 || opts.Rate > 500 {
		opts.Rate = 500
	}
	return true
}
