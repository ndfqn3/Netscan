package store

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// MonitorState 监控状态(保存在本地, 用于变更比对)
type MonitorState struct {
	Target string    `json:"target"`
	Time   time.Time `json:"time"`
	Items  []string  `json:"items"` // 例如 "1.2.3.4:80/tcp" 或 "sub.example.com"
}

// DefaultStateDir 状态文件保存目录
func DefaultStateDir() string {
	home, _ := os.UserHomeDir()
	if home == "" {
		return ".netscan_state"
	}
	return filepath.Join(home, ".netscan_state")
}

func stateFilePath(dir, target string) string {
	name := strings.NewReplacer("/", "_", ":", "_", "\\", "_", " ", "_").Replace(target)
	return filepath.Join(dir, name+".json")
}

// DiffState 加载上次状态并与当前 items 比对, 返回新增/消失项, 并保存当前状态
func DiffState(dir, target string, items []string) (added, removed []string, err error) {
	path := stateFilePath(dir, target)

	var prev MonitorState
	if data, rerr := os.ReadFile(path); rerr == nil {
		if uerr := json.Unmarshal(data, &prev); uerr != nil {
			return nil, nil, uerr
		}
	} else if !os.IsNotExist(rerr) {
		return nil, nil, rerr
	}

	prevSet := map[string]bool{}
	for _, it := range prev.Items {
		prevSet[it] = true
	}
	curSet := map[string]bool{}
	for _, it := range items {
		curSet[it] = true
	}
	for it := range curSet {
		if !prevSet[it] {
			added = append(added, it)
		}
	}
	for it := range prevSet {
		if !curSet[it] {
			removed = append(removed, it)
		}
	}
	sort.Strings(added)
	sort.Strings(removed)

	state := MonitorState{Target: target, Time: time.Now(), Items: items}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return added, removed, err
	}
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return added, removed, err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return added, removed, err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		if werr := os.WriteFile(path, data, 0o644); werr != nil {
			return added, removed, werr
		}
	}
	return added, removed, nil
}
