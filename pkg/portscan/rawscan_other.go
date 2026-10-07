//go:build !linux

package portscan

import "time"

// rawScanner 在非 Linux 平台不可用(需要 raw socket / npcap)
type rawScanner struct{}

func newRawScanner() (*rawScanner, error) {
	return nil, errRawUnsupported
}

func (s *rawScanner) close() {}

func (s *rawScanner) probe(ip string, port int, flags uint8, timeout time.Duration) PortState {
	return StateFiltered
}
