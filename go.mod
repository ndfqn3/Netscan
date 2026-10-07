module portscanner

go 1.27.0

require (
	github.com/ffuf/ffuf/v2 v2.0.0-00010101000000-000000000000
	github.com/go-sql-driver/mysql v1.10.0
	github.com/praetorian-inc/nerva v1.70.3
	github.com/projectdiscovery/wappalyzergo v0.3.4
	github.com/webview/webview_go v0.0.0-20240831120633-6173450d4dd6
	golang.org/x/crypto v0.57.0
	golang.org/x/net v0.59.0
	golang.org/x/sync v0.23.0
	golang.org/x/sys v0.48.0
	golang.org/x/term v0.46.0
	gopkg.in/yaml.v3 v3.0.1
	modernc.org/sqlite v1.56.0
)

require (
	filippo.io/edwards25519 v1.2.0 // indirect
	github.com/PuerkitoBio/goquery v1.13.0 // indirect
	github.com/adrg/xdg v0.5.3 // indirect
	github.com/andybalholm/brotli v1.2.4 // indirect
	github.com/andybalholm/cascadia v1.3.5 // indirect
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/ffuf/pencode v0.0.0-20240120104927-07e33ef17d5a // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/ishidawataru/sctp v0.0.0-20251114114122-19ddcbc6aae2 // indirect
	github.com/mattn/go-isatty v0.0.24 // indirect
	github.com/ncruces/go-strftime v1.0.0 // indirect
	github.com/pelletier/go-toml v1.9.5 // indirect
	github.com/quic-go/quic-go v0.60.0 // indirect
	github.com/remyoudompheng/bigfft v0.0.0-20230129092748-24d4a6f8daec // indirect
	github.com/twmb/murmur3 v1.1.8 // indirect
	golang.org/x/text v0.42.0 // indirect
	golang.org/x/time v0.14.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20251029180050-ab9386a59fda // indirect
	google.golang.org/grpc v1.78.0 // indirect
	google.golang.org/protobuf v1.36.10 // indirect
	modernc.org/libc v1.74.4 // indirect
	modernc.org/mathutil v1.7.1 // indirect
	modernc.org/memory v1.11.0 // indirect
)

replace github.com/ffuf/ffuf/v2 => ./third_party/ffuf
