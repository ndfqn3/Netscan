//go:build windows

package scanner

import (
	"errors"
	"syscall"

	"golang.org/x/sys/windows"
)

// isRefused 判断错误是否为"连接被拒绝"(RST, 端口关闭)
func isRefused(err error) bool {
	if err == nil {
		return false
	}
	var errno syscall.Errno
	if errors.As(err, &errno) {
		return errno == windows.WSAECONNREFUSED || errno == syscall.ECONNREFUSED
	}
	return false
}
