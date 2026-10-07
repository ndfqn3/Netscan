package portscan

import "errors"

// errRawUnsupported 当前平台不支持 raw socket 扫描
var errRawUnsupported = errors.New("当前平台不支持 SYN/FIN/NULL/Xmas/ACK 扫描, 需 Linux + root 权限")
