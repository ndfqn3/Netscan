package main

import (
	"fmt"
	"os"

	"portscanner/internal/scanner"
)

// dispatchSubcommand 处理 plugin/pocs/dict/module 子命令
func dispatchSubcommand() bool {
	if len(os.Args) < 2 {
		return false
	}
	switch os.Args[1] {
	case "plugin":
		pluginCmd(os.Args[2:])
		return true
	case "pocs":
		pocsCmd(os.Args[2:])
		return true
	case "dict":
		dictCmd(os.Args[2:])
		return true
	case "module":
		moduleCmd(os.Args[2:])
		return true
	case "shell":
		shellCmd(os.Args[2:])
		return true
	}
	return false
}

func shellCmd(args []string) {
	m := scanner.OpenShellChainManager("")
	switch {
	case len(args) == 0 || args[0] == "list":
		fmt.Println("内置拿 shell 链: redis(6379) / docker(2375) / jenkins(8080) / couchdb(5984)")
		fmt.Println("用户拿 shell 链(shells/):")
		for _, c := range m.List() {
			fmt.Printf("%-24s %-6d %s\n", c.ID, c.Port, c.Name)
		}
		if len(m.List()) == 0 {
			fmt.Println("  (无自定义拿 shell 链, 将 YAML/JSON 链文件放入 shells/ 目录)")
		}
	case args[0] == "add":
		if len(args) < 2 {
			fmt.Println("用法: netscan shell add <链文件.yaml|json>")
			return
		}
		if err := m.Add(args[1]); err != nil {
			fmt.Fprintf(os.Stderr, "添加失败: %v\n", err)
			return
		}
		fmt.Println("已添加拿 shell 链:", args[1])
	case args[0] == "remove":
		if len(args) < 2 {
			fmt.Println("用法: netscan shell remove <id>")
			return
		}
		if err := m.Remove(args[1]); err != nil {
			fmt.Fprintf(os.Stderr, "卸载失败: %v\n", err)
			return
		}
		fmt.Println("已卸载拿 shell 链:", args[1])
	default:
		fmt.Println("用法: netscan shell <list|add|remove> [参数]")
	}
}

func moduleCmd(args []string) {
	m := scanner.OpenModuleManager("")
	switch {
	case len(args) == 0 || args[0] == "list":
		fmt.Println("内置模块:", len(scanner.ExploitList()), "个")
		fmt.Println("用户模块(modules/):")
		for _, fm := range m.List() {
			fmt.Printf("%-30s %-8s %s\n", fm.ID, fm.Type, fm.Name)
		}
		if len(m.List()) == 0 {
			fmt.Println("  (无自定义模块, 将 YAML/JSON 模块文件放入 modules/ 目录)")
		}
	case args[0] == "add":
		if len(args) < 2 {
			fmt.Println("用法: netscan module add <模块文件.yaml|json>")
			return
		}
		if err := m.Add(args[1]); err != nil {
			fmt.Fprintf(os.Stderr, "添加失败: %v\n", err)
			return
		}
		fmt.Println("已添加模块:", args[1])
	case args[0] == "remove":
		if len(args) < 2 {
			fmt.Println("用法: netscan module remove <id>")
			return
		}
		if err := m.Remove(args[1]); err != nil {
			fmt.Fprintf(os.Stderr, "卸载失败: %v\n", err)
			return
		}
		fmt.Println("已卸载模块:", args[1])
	default:
		fmt.Println("用法: netscan module <list|add|remove> [参数]")
	}
}

func pluginCmd(args []string) {
	if len(args) == 0 {
		fmt.Println("用法: netscan plugin <list|install|remove|update> [参数]")
		return
	}
	m := scanner.OpenPluginManager(scanner.DefaultPluginDir())
	switch args[0] {
	case "list":
		for _, p := range m.List() {
			fmt.Printf("%-20s %-14s %s v%s\n", p.ID, p.Type, p.Name, p.Version)
		}
		if len(m.List()) == 0 {
			fmt.Println("(无插件, 将插件文件放入 plugins/ 目录)")
		}
	case "install":
		if len(args) < 2 {
			fmt.Println("用法: netscan plugin install <插件文件.yaml/json>")
			return
		}
		if err := m.Install(args[1]); err != nil {
			fmt.Fprintf(os.Stderr, "安装失败: %v\n", err)
			return
		}
		fmt.Println("已安装插件:", args[1])
	case "remove":
		if len(args) < 2 {
			fmt.Println("用法: netscan plugin remove <id>")
			return
		}
		if err := m.Remove(args[1]); err != nil {
			fmt.Fprintf(os.Stderr, "卸载失败: %v\n", err)
			return
		}
		fmt.Println("已卸载插件:", args[1])
	case "update":
		if len(args) < 2 {
			fmt.Println("用法: netscan plugin update <插件id>")
			return
		}
		if err := scanner.InstallMarketPlugin(args[1]); err != nil {
			fmt.Fprintf(os.Stderr, "更新失败: %v\n", err)
			return
		}
		fmt.Println("已更新插件:", args[1])
	default:
		fmt.Println("未知子命令:", args[0])
	}
}

func pocsCmd(args []string) {
	if len(args) == 0 {
		fmt.Println("用法: netscan pocs <list|add|remove> [参数]")
		return
	}
	m := scanner.OpenPOCManager(scanner.DefaultPOCDir())
	switch args[0] {
	case "list":
		n := 0
		for _, id := range scanner.ExploitList() {
			fmt.Printf("builtin  %s\n", id)
			n++
		}
		for _, t := range m.List() {
			fmt.Printf("custom   %-20s %s\n", t.ID, t.Name)
			n++
		}
		fmt.Printf("共 %d 个 POC\n", n)
	case "add":
		if len(args) < 2 {
			fmt.Println("用法: netscan pocs add <poc.yaml|poc.json>")
			return
		}
		if err := m.Add(args[1]); err != nil {
			fmt.Fprintf(os.Stderr, "添加失败: %v\n", err)
			return
		}
		fmt.Println("已添加 POC:", args[1])
	case "remove":
		if len(args) < 2 {
			fmt.Println("用法: netscan pocs remove <id>")
			return
		}
		if err := m.Remove(args[1]); err != nil {
			fmt.Fprintf(os.Stderr, "删除失败: %v\n", err)
			return
		}
		fmt.Println("已删除 POC:", args[1])
	default:
		fmt.Println("未知子命令:", args[0])
	}
}

func dictCmd(args []string) {
	if len(args) == 0 {
		fmt.Println("用法: netscan dict <list|add> [参数]")
		return
	}
	m := scanner.OpenDictManager(scanner.DefaultDictDir())
	switch args[0] {
	case "list":
		for _, d := range m.List() {
			fmt.Println(d)
		}
	case "add":
		if len(args) < 2 {
			fmt.Println("用法: netscan dict add <字典文件.txt>")
			return
		}
		if err := m.Add(args[1]); err != nil {
			fmt.Fprintf(os.Stderr, "添加失败: %v\n", err)
			return
		}
		fmt.Println("已添加字典:", args[1])
	default:
		fmt.Println("未知子命令:", args[0])
	}
}
