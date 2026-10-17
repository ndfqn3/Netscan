//go:build (netbsd && arm64) || (netbsd && 386) || (openbsd && 386)

package store

import (
	"errors"
	"portscanner/pkg/portscan"
)

import "time"

// 该文件为部分 BSD 平台提供 SQLite 存储的桩实现
// (modernc.org/sqlite 在这些平台缺少生成的 C 类型, 无法编译)

// ErrUnsupported 表示当前平台不支持 SQLite 持久化
var ErrUnsupported = errors.New("当前平台不支持 SQLite 持久化(资产历史/变更对比不可用)")

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

type Store struct {
	initErr error
}

func OpenStore(dir string) *Store { return &Store{initErr: ErrUnsupported} }

func (s *Store) Close() {}

func (s *Store) Save(target string, results []portscan.Result) error {
	if s != nil && s.initErr != nil {
		return s.initErr
	}
	return ErrUnsupported
}

func (s *Store) History(target string) ([]ScanRecord, error) {
	if s != nil && s.initErr != nil {
		return nil, s.initErr
	}
	return nil, ErrUnsupported
}

func (s *Store) Diff(target string, results []portscan.Result) (added, removed []StoreAsset, err error) {
	if s != nil && s.initErr != nil {
		return nil, nil, s.initErr
	}
	return nil, nil, ErrUnsupported
}

func (s *Store) RecordExploit(service, vulnID string, success bool) {}
