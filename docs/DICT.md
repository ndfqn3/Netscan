# 字典格式说明

NetScan 内置用户名与密码字典，支持自定义扩展。

## 内置字典

| 字典 | 数量 | 说明 |
|------|------|------|
| 用户名（按服务分类） | ~500 | common / ssh / mysql / postgresql / redis / ftp / smtp / telnet |
| 密码 Top1000 | 1000+ | 常见弱口令 |

查看内置字典：

```bash
./netscan dict list
```

## 自定义字典

### 添加字典

```bash
./netscan dict add ./my-passwords.txt
```

### 字典文件格式

纯文本，每行一条（自动忽略空行与首尾空格）：

```
password
123456
admin888
P@ssw0rd
```

## 在爆破中使用自定义字典

```bash
./netscan -target 192.168.1.1 -p 22 --brute ssh --user-dict ./users.txt --pass-dict ./pass.txt
```

> `--user-dict` / `--pass-dict` 指定字典文件；留空则使用内置字典（用户名按服务分类 + Top1000 密码）。

## 目录

自定义字典默认保存在 `~/.netscan_dicts/`（也可用 `dict add` 命令添加到该目录）。
