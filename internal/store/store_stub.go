//go:build (netbsd && arm64) || (netbsd && 386) || (openbsd && 386)

package store

import (
	"portscanner/pkg/portscan"
)

import "time"

// 该文件为部分 BSD 平台提供 SQLite 存储的桩实现
// (modernc.org/sqlite 在这些平台缺少生成的 C 类型, 无法编译)

type StoreAsset struct {
	IP       string `json:"ip"`
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
	Service  string `json:"service"`
	Version  string `json:"version"`
	Vuln     string `json:"vuln"`
}

type ScanRecord struct {
	Target string       `json:"target"`
	Time   time.Time    `json:"time"`
	Assets []StoreAsset `json:"assets"`
}

type Store struct{}

func OpenStore(dir string) *Store { return &Store{} }

func (s *Store) Close() {}

func (s *Store) Save(target string, results []portscan.Result) error { return nil }

func (s *Store) History(target string) ([]ScanRecord, error) { return nil, nil }

func (s *Store) Diff(target string, results []portscan.Result) (added, removed []StoreAsset, err error) {
	return nil, nil, nil
}

func (s *Store) RecordExploit(service, vulnID string, success bool) {}
