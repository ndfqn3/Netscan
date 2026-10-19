# Release Notes (English)

## v5.0.4

> Documentation localization and GUI improvements.

- Added English documentation: `README.en.md`, `RELEASE_NOTES.en.md`, `THIRD_PARTY_NOTICES.en.md`
- GUI: built-in POC batch runner on the WEB page — enter target/port, choose the number of templates (50/100/200/300/500/all), click once; results are printed after the batch completes
- GUI: language selector (Chinese / English)
- Backend: `ScanPOCsFilteredLimit` for count-limited POC batches; `pocBuiltinList` binding and `POCBuiltinList` facade export

## v5.0.3

- Built-in POC library moved to the top of the WEB page with target/port inputs, search, and one-click execution
- Resource page no longer duplicates the built-in library

## v5.0.2

- WEB page built-in POC library (search + run) so the 5,380 templates are usable from the GUI

## v5.0.1

- Security audit remediation: target/CIDR overflow and wrap-around, IPv6 endpoint panic, webhook nil request, GUI concurrent scan isolation, proxy fail-closed, honest shell-chain reporting
- Correctness: JSON extractor rewritten with `encoding/json`, UDP ICMP code/IP validation, DNS timeouts, store/monitor error propagation, rand helper limits, OAST lifecycle, nil callback guards, port range validation, BSD stub errors, explicit TLS verification toggle
- GUI: live scan log, POC hit details/tags, dedicated output for the vulnerability scan card

## v5.0

- Fingerprint compliance: removed all nmap-derived content; web technologies via wappalyzergo (MIT), service fingerprinting via nerva (Apache-2.0, MIT-compatible)
- POC engine v3: payloads, variables/helpers, indexed DSL, internal extractors, negative/oast_request matchers, automatic Content-Length
- ffuf integration (`--fuzz-*`, GUI tab)
- PayloadsAllTheThings built-in dictionaries (`builtin:`)
- Exploit chains: 13 verified CVE chains
- New GUI tabs: Web Recon, Fuzzing; 5,380 POC templates

For the full changelog, see the Chinese [RELEASE_NOTES.md](RELEASE_NOTES.md).
