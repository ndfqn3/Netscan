package netx

import (
	"os"
	"path/filepath"
	"strings"
)

// ResolveDataDir 解析平台化数据目录: 依次查找可执行文件目录、当前目录下的 <name>/,
// 存在即使用(便于免安装/随程序携带, 与 README 的 shells/ modules/ 等目录一致);
// 都不存在时回退到用户主目录的 <hidden>/
func ResolveDataDir(name, hidden string) string {
	if exe, err := os.Executable(); err == nil {
		d := filepath.Join(filepath.Dir(exe), name)
		if fi, err := os.Stat(d); err == nil && fi.IsDir() {
			return d
		}
	}
	if fi, err := os.Stat(name); err == nil && fi.IsDir() {
		return name
	}
	home, _ := os.UserHomeDir()
	if home == "" {
		return name
	}
	return filepath.Join(home, hidden)
}

// SanitizeID 清洗插件/模块/POC/链的 ID, 防止路径穿越写到目标目录之外
func SanitizeID(id string) string {
	id = strings.TrimSpace(id)
	id = strings.ReplaceAll(id, "/", "_")
	id = strings.ReplaceAll(id, "\\", "_")
	id = strings.ReplaceAll(id, "..", "__")
	if id == "" {
		id = "unnamed"
	}
	return id
}
