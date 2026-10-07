// Copyright 2022 Praetorian Security, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

/*
Package fingerprinters provides HTTP fingerprinting for Microsoft Exchange Server (OWA/EWS).

# Detection Strategy

Microsoft Exchange Server is a mail server and collaboration platform. Exposed instances
represent a security concern due to:
  - Outlook Web Access (OWA) with email and calendar access
  - Exchange Web Services (EWS) API exposure
  - Authentication bypass vulnerabilities (ProxyLogon, ProxyShell)
  - Server-Side Request Forgery (SSRF) attack surface
  - Often exposed without MFA

Detection uses active probing:
  - Active: Query /owa/ endpoint (OWA login page)
  - Response headers contain X-OWA-Version or X-FEServer
  - Body content contains OWA-specific patterns

# Response Headers

Exchange OWA responses include identifying headers:
  - X-OWA-Version: 15.2.1544.11 (OWA build version)
  - X-FEServer: MAIL-SRV01 (Frontend server hostname - recon value)
  - Server: Microsoft-IIS/10.0 (with /owa/ redirect)
  - X-AspNet-Version: 4.0.30319 (ASP.NET version)

# Version Mapping

OWA version to Exchange version mapping:
  - 15.2.x → Exchange Server 2019
  - 15.1.x → Exchange Server 2016
  - 15.0.x → Exchange Server 2013

# Port Configuration

Exchange typically runs on:
  - 443:  HTTPS (default for OWA)
  - 80:   HTTP (often redirects to HTTPS)

# Example Usage

	fp := &ExchangeFingerprinter{}
	if fp.Match(resp) {
		result, err := fp.Fingerprint(resp, body)
		if err == nil && result != nil {
			fmt.Printf("Detected: %s version %s\n", result.Technology, result.Version)
		}
	}
*/
package fingerprinters

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"
)

// ExchangeFingerprinter detects Microsoft Exchange Server via OWA/EWS
type ExchangeFingerprinter struct{}

// exchangeVersionRegex validates Exchange version format
// Accepts: 15.2.1544.11 (standard), 15.2.1544.10 (patch)
var exchangeVersionRegex = regexp.MustCompile(`^\d+\.\d+\.\d+(\.\d+)?$`)

func init() {
	Register(&ExchangeFingerprinter{})
}

func (f *ExchangeFingerprinter) Name() string {
	return "exchange"
}

func (f *ExchangeFingerprinter) ProbeEndpoint() string {
	return "/owa/"
}

func (f *ExchangeFingerprinter) Match(resp *http.Response) bool {
	// Check for Exchange-specific headers (most reliable indicators)
	if resp.Header.Get("X-OWA-Version") != "" {
		return true
	}
	if resp.Header.Get("X-FEServer") != "" {
		return true
	}

	// Check for IIS Server header combined with /owa/ redirect
	serverHeader := resp.Header.Get("Server")
	locationHeader := resp.Header.Get("Location")
	if strings.Contains(serverHeader, "Microsoft-IIS") && strings.Contains(locationHeader, "/owa/") {
		return true
	}

	// Check for ASP.NET header with IIS (weaker indicator)
	if resp.Header.Get("X-AspNet-Version") != "" && strings.Contains(serverHeader, "Microsoft-IIS") {
		return true
	}

	return false
}

func (f *ExchangeFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	// Build metadata first (available regardless of version presence)
	metadata := map[string]any{}

	// Extract FE Server (internal hostname - valuable for recon)
	if feServer := resp.Header.Get("X-FEServer"); feServer != "" {
		metadata["fe_server"] = feServer
	}

	// Extract IIS version
	if serverHeader := resp.Header.Get("Server"); serverHeader != "" {
		metadata["iis_version"] = serverHeader
	}

	// Extract ASP.NET version
	if aspNetVersion := resp.Header.Get("X-AspNet-Version"); aspNetVersion != "" {
		metadata["aspnet_version"] = aspNetVersion
	}

	// Extract version from X-OWA-Version header (most precise, but optional)
	owaVersion := resp.Header.Get("X-OWA-Version")

	// If version present, validate and add edition mapping
	if owaVersion != "" {
		// Validate version format to prevent CPE injection
		if !exchangeVersionRegex.MatchString(owaVersion) {
			// Invalid version format - return result without version
			owaVersion = ""
		} else {
			// Valid version - map OWA version to Exchange edition
			exchangeEdition := mapExchangeEdition(owaVersion)
			if exchangeEdition != "" {
				metadata["exchange_edition"] = exchangeEdition
			}
		}
	}

	// Always return a result when Fingerprint is called (Match already confirmed Exchange)
	return &FingerprintResult{
		Technology: "exchange_server",
		Version:    owaVersion,
		CPEs:       []string{buildExchangeCPE(owaVersion)},
		Metadata:   metadata,
	}, nil
}

func buildExchangeCPE(version string) string {
	if version == "" {
		version = "*"
	}
	return fmt.Sprintf("cpe:2.3:a:microsoft:exchange_server:%s:*:*:*:*:*:*:*", version)
}

func mapExchangeEdition(owaVersion string) string {
	// OWA version format: major.minor.build.revision
	// Extract major.minor (e.g., "15.2" from "15.2.1544.11")
	parts := strings.Split(owaVersion, ".")
	if len(parts) < 2 {
		return ""
	}

	majorMinor := parts[0] + "." + parts[1]

	switch majorMinor {
	case "15.2":
		return "Exchange Server 2019"
	case "15.1":
		return "Exchange Server 2016"
	case "15.0":
		return "Exchange Server 2013"
	default:
		return ""
	}
}
