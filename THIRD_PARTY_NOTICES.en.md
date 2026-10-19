# Third-Party Notices (English)

This project is MIT-licensed. It includes or derives from the following third-party components. Full license texts are retained in the repository and in the vendored source trees.

## 1. projectdiscovery/nuclei-templates (MIT)

- Source: <https://github.com/projectdiscovery/nuclei-templates>
- License: MIT, Copyright (c) 2025 ProjectDiscovery, Inc.
- Usage: official templates selected by the conversion pipeline; plus 64 maintained extras in `internal/poc/nuclei_pocs_extra_gen.go`

## 2. AllForOne collection and MIT-licensed template repositories (MIT)

- MIT-licensed repositories from the AllForOne list were collected and de-duplicated; see `THIRD_PARTY_NOTICES.md` for the full list and copyright lines.

## 3. ffuf (MIT)

- Source: <https://github.com/ffuf/ffuf> (snapshot v2.1.0, embedded in `third_party/ffuf/`)
- License: MIT, Copyright (c) 2021 Joona Hoikkala
- Usage: web fuzzing engine (`--fuzz-*`, GUI fuzzing tab)

## 4. PayloadsAllTheThings (MIT)

- Source: <https://github.com/swisskyrepo/PayloadsAllTheThings> (commit `3ac27901c711bdf3f5b65a7b1d1820a1f65bd09a`)
- License: MIT, Copyright (c) 2019 Swissky
- Usage: 66 built-in dictionaries in `internal/payloads/pat/` (`builtin:<name>`)

## 5. wappalyzergo (MIT)

- Source: <https://github.com/projectdiscovery/wappalyzergo> (v0.3.4)
- License: MIT, Copyright (c) 2023 ProjectDiscovery, Inc.
- Fingerprint data: <https://github.com/enthec/webappanalyzer>, <https://github.com/HTTPArchive/wappalyzer> (MIT)

## 6. nerva (Apache-2.0, MIT-compatible)

- Source: <https://github.com/praetorian-inc/nerva> (v1.70.3)
- License: Apache License 2.0 (full text in `vendor/github.com/praetorian-inc/nerva/LICENSE`)
- Note: nerva is the maintained fork of praetorian-inc/fingerprintx (Apache-2.0, archived); this project uses nerva as the service fingerprinting engine

## No nmap-derived content

This project contains no nmap source code, `nmap-service-probes`, or `nmap-services` data. Importing nmap XML output files is format-only interoperability. Port/service mappings are based on the IANA service-name registry and common conventions; SMB build mappings are based on MS-NLMP and public Microsoft build information.

For full Chinese notices, per-file license audit, and complete copyright lines, see [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
