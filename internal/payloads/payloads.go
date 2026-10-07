// Package payloads 内置 PayloadsAllTheThings (MIT, Copyright (c) 2019 Swissky) 字典资源。
// 逐文件许可审计: 仅收录无冲突许可的 .txt 列表(3 个 CC/BSD 标记经核实为误报,
// 1 个 GPL 文件已排除); 详见 pat/SOURCE.json 与 THIRD_PARTY_NOTICES.md。
package payloads

import (
	"embed"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

//go:embed pat
var patFS embed.FS

const prefix = "pat/"

// Names 返回所有内置字典名(相对路径, 无 .txt 后缀), 已排序
func Names() []string {
	var out []string
	_ = fs.WalkDir(patFS, "pat", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		lp := strings.ToLower(p)
		if !strings.HasSuffix(lp, ".txt") {
			return nil
		}
		name := strings.TrimPrefix(p, prefix)
		name = name[:len(name)-len(".txt")]
		out = append(out, filepath.ToSlash(name))
		return nil
	})
	sort.Strings(out)
	return out
}

// resolve 名称解析: 完整相对路径(不区分大小写) 或唯一 basename
func resolve(name string) (string, error) {
	n := strings.TrimSpace(name)
	n = strings.TrimSuffix(n, ".txt")
	n = strings.ReplaceAll(n, "\\", "/")
	all := Names()
	for _, a := range all {
		if strings.EqualFold(a, n) {
			return a, nil
		}
	}
	var matches []string
	for _, a := range all {
		if strings.EqualFold(filepath.Base(a), n) {
			matches = append(matches, a)
		}
	}
	switch len(matches) {
	case 1:
		return matches[0], nil
	case 0:
		return "", fmt.Errorf("未找到内置字典 %q (可用: netscan 字典管理查看)", name)
	default:
		return "", fmt.Errorf("字典名 %q 不唯一, 请用完整路径: %s", name, strings.Join(matches, ", "))
	}
}

// Lines 返回内置字典内容(逐行)
func Lines(name string) ([]string, error) {
	a, err := resolve(name)
	if err != nil {
		return nil, err
	}
	b, err := patFS.ReadFile(prefix + a + ".txt")
	if err != nil {
		return nil, err
	}
	s := strings.ReplaceAll(string(b), "\r\n", "\n")
	var out []string
	for _, ln := range strings.Split(s, "\n") {
		if strings.TrimSpace(ln) != "" {
			out = append(out, ln)
		}
	}
	return out, nil
}

// List 返回供字典管理展示的条目(名称 + 行数)
func List() []string {
	names := Names()
	out := make([]string, 0, len(names))
	for _, n := range names {
		lines, _ := Lines(n)
		out = append(out, fmt.Sprintf("pat/%s (%d)", n, len(lines)))
	}
	return out
}

// Materialize 将内置字典写出为临时文件, 返回路径
// (供 ffuf 等按文件路径读取的组件使用, 调用方可用 "builtin:<name>" 引用)
func Materialize(name string) (string, error) {
	a, err := resolve(name)
	if err != nil {
		return "", err
	}
	lines, err := Lines(a)
	if err != nil {
		return "", err
	}
	safe := strings.NewReplacer("/", "_", "\\", "_", " ", "_").Replace(a)
	p := filepath.Join(os.TempDir(), "netscan_pat_"+safe+".txt")
	if err := os.WriteFile(p, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		return "", err
	}
	return p, nil
}
