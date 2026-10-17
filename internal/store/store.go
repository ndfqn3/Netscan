//go:build !(netbsd && arm64) && !(netbsd && 386) && !(openbsd && 386)

package store

import (
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"
	"portscanner/internal/netx"
	"portscanner/pkg/portscan"
	"sort"
	"time"

	_ "modernc.org/sqlite"
)

// StoreAsset 资产条目
type StoreAsset struct {
	IP       string `json:"ip"`
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
	Service  string `json:"service"`
	Version  string `json:"version"`
	Vuln     string `json:"vuln"`
}

// ScanRecord 一次扫描记录
type ScanRecord struct {
	Target string       `json:"target"`
	Time   time.Time    `json:"time"`
	Assets []StoreAsset `json:"assets"`
}

// Store 本地资产存储(SQLite, 纯 Go 无 CGO)
type Store struct {
	db      *sql.DB
	initErr error
}

// OpenStore 打开(或创建)资产数据库
func OpenStore(dir string) *Store {
	if dir == "" {
		dir = DefaultStateDir()
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return &Store{initErr: err}
	}
	db, err := sql.Open("sqlite", filepath.Join(dir, "netscan.db"))
	if err != nil {
		return &Store{initErr: err}
	}
	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		db.Close()
		s.db = nil
		s.initErr = err
	}
	return s
}

func (s *Store) migrate() error {
	if s == nil || s.db == nil {
		return nil
	}
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS scans (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		target TEXT NOT NULL,
		time TEXT NOT NULL,
		results TEXT NOT NULL
	)`,
		`CREATE TABLE IF NOT EXISTS assets (
		key TEXT PRIMARY KEY,
		ip TEXT, port INTEGER, protocol TEXT, service TEXT, version TEXT, vuln TEXT,
		first_seen TEXT, last_seen TEXT
	)`,
		`CREATE TABLE IF NOT EXISTS exploits (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		service TEXT, vuln_id TEXT, success INTEGER, time TEXT
	)`,
		`CREATE TABLE IF NOT EXISTS changes (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		target TEXT, change_type TEXT, item TEXT, time TEXT
	)`,
	}
	for _, q := range stmts {
		if _, err := s.db.Exec(q); err != nil {
			return err
		}
	}
	return nil
}

// Close 关闭数据库
func (s *Store) Close() {
	if s != nil && s.db != nil {
		s.db.Close()
	}
}

// Save 保存一次扫描结果(--store)
func (s *Store) Save(target string, results []portscan.Result) error {
	if s == nil {
		return nil
	}
	if s.initErr != nil {
		return s.initErr
	}
	if s.db == nil {
		return nil
	}
	data, err := json.Marshal(results)
	if err != nil {
		return err
	}
	now := time.Now().Format(time.RFC3339)
	if _, err := s.db.Exec(`INSERT INTO scans (target, time, results) VALUES (?, ?, ?)`, target, now, string(data)); err != nil {
		return err
	}
	for _, a := range resultsToAssets(results) {
		if err := s.upsertAsset(a); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) upsertAsset(a StoreAsset) error {
	now := time.Now().Format(time.RFC3339)
	_, err := s.db.Exec(`INSERT INTO assets (key, ip, port, protocol, service, version, vuln, first_seen, last_seen)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(key) DO UPDATE SET service=excluded.service, version=excluded.version, vuln=excluded.vuln, last_seen=excluded.last_seen`,
		a.IP+":"+netx.Itoa(a.Port)+"/"+a.Protocol, a.IP, a.Port, a.Protocol, a.Service, a.Version, a.Vuln, now, now)
	return err
}

// History 查看目标的历史扫描记录(--history)
func (s *Store) History(target string) ([]ScanRecord, error) {
	if s == nil || s.db == nil {
		return nil, nil
	}
	rows, err := s.db.Query(`SELECT time, results FROM scans WHERE target = ? ORDER BY id DESC LIMIT 10`, target)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ScanRecord
	for rows.Next() {
		var t, rj string
		if err := rows.Scan(&t, &rj); err != nil {
			return nil, err
		}
		var results []portscan.Result
		if err := json.Unmarshal([]byte(rj), &results); err != nil {
			return nil, err
		}
		tm, _ := time.Parse(time.RFC3339, t)
		out = append(out, ScanRecord{Target: target, Time: tm, Assets: resultsToAssets(results)})
	}
	return out, nil
}

// Diff 与上次记录比对(--diff)
func (s *Store) Diff(target string, results []portscan.Result) (added, removed []StoreAsset, err error) {
	recs, err := s.History(target)
	if err != nil {
		return nil, nil, err
	}
	if len(recs) == 0 {
		cur := resultsToAssets(results)
		return cur, nil, nil
	}
	prev := recs[0].Assets
	prevSet := map[string]StoreAsset{}
	for _, a := range prev {
		prevSet[a.key()] = a
	}
	curSet := map[string]StoreAsset{}
	for _, a := range resultsToAssets(results) {
		curSet[a.key()] = a
	}
	for k, a := range curSet {
		if _, ok := prevSet[k]; !ok {
			added = append(added, a)
		}
	}
	for k, a := range prevSet {
		if _, ok := curSet[k]; !ok {
			removed = append(removed, a)
		}
	}
	sortAssets(added)
	sortAssets(removed)
	// 记录变更
	now := time.Now().Format(time.RFC3339)
	var chErr error
	for _, a := range added {
		if _, e := s.db.Exec(`INSERT INTO changes (target, change_type, item, time) VALUES (?, 'add', ?, ?)`, target, a.key(), now); e != nil && chErr == nil {
			chErr = e
		}
	}
	for _, a := range removed {
		if _, e := s.db.Exec(`INSERT INTO changes (target, change_type, item, time) VALUES (?, 'remove', ?, ?)`, target, a.key(), now); e != nil && chErr == nil {
			chErr = e
		}
	}
	return added, removed, chErr
}

// RecordExploit 记录漏洞利用
func (s *Store) RecordExploit(service, vulnID string, success bool) {
	if s == nil || s.db == nil {
		return
	}
	ok := 0
	if success {
		ok = 1
	}
	s.db.Exec(`INSERT INTO exploits (service, vuln_id, success, time) VALUES (?, ?, ?, ?)`,
		service, vulnID, ok, time.Now().Format(time.RFC3339))
}

func (a StoreAsset) key() string {
	return a.IP + ":" + netx.Itoa(a.Port) + "/" + a.Protocol
}

func resultsToAssets(results []portscan.Result) []StoreAsset {
	var assets []StoreAsset
	for _, r := range results {
		if r.State == portscan.StateOpen || r.State == portscan.StateOpenFiltered {
			assets = append(assets, StoreAsset{
				IP: r.IP, Port: r.Port, Protocol: r.Protocol,
				Service: r.Service, Version: r.Version, Vuln: r.Vuln,
			})
		}
	}
	sortAssets(assets)
	return assets
}

func sortAssets(assets []StoreAsset) {
	sort.Slice(assets, func(i, j int) bool {
		if assets[i].IP != assets[j].IP {
			return assets[i].IP < assets[j].IP
		}
		return assets[i].Port < assets[j].Port
	})
}
