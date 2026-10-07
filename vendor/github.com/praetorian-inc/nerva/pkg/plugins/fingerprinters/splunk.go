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
Package fingerprinters provides HTTP fingerprinting for Splunk Enterprise/Cloud.

# Detection Strategy

Splunk is an enterprise data platform for searching, monitoring, and analyzing
machine-generated data. Exposed Splunkd HTTP services can indicate:
  - Management port exposure (8089 default)
  - Web interface exposure (8000 default)
  - API endpoints without authentication
  - Version information disclosure

Detection uses passive header analysis:
  - X-Splunk-Version header (definitive indicator)
  - Server: Splunkd header (with optional version)

# Header Response Format

Splunk HTTP responses include identifying headers:

	HTTP/1.1 200 OK
	X-Splunk-Version: 9.1.2
	Server: Splunkd/9.1.2
	Content-Type: text/html

# Port Configuration

Splunk typically runs on:
  - 8089: Default Splunkd management port
  - 8000: Default Splunk Web interface
  - 443:  HTTPS in production deployments

# Example Usage

	fp := &SplunkFingerprinter{}
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

// SplunkFingerprinter detects Splunk Enterprise/Cloud via HTTP headers
type SplunkFingerprinter struct{}

// splunkVersionRegex validates Splunk version format (prevents CPE injection)
// Accepts: 9.1.2, 8.2.6, 9.0.0
var splunkVersionRegex = regexp.MustCompile(`^\d+\.\d+\.\d+$`)

func init() {
	Register(&SplunkFingerprinter{})
}

func (f *SplunkFingerprinter) Name() string {
	return "splunk"
}

func (f *SplunkFingerprinter) Match(resp *http.Response) bool {
	// Signal 1: X-Splunk-Version header (definitive)
	if resp.Header.Get("X-Splunk-Version") != "" {
		return true
	}

	// Signal 2: Server header starts with "Splunkd"
	serverHeader := resp.Header.Get("Server")
	if strings.HasPrefix(serverHeader, "Splunkd") {
		return true
	}

	return false
}

func (f *SplunkFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	var version string
	metadata := make(map[string]any)

	// Try to extract version from X-Splunk-Version header first
	xSplunkVersion := resp.Header.Get("X-Splunk-Version")
	if xSplunkVersion != "" {
		version = xSplunkVersion
	}

	// If no X-Splunk-Version, try extracting from Server header
	serverHeader := resp.Header.Get("Server")
	if version == "" && strings.HasPrefix(serverHeader, "Splunkd/") {
		// Extract version from "Splunkd/9.1.2" format
		parts := strings.SplitN(serverHeader, "/", 2)
		if len(parts) == 2 {
			version = parts[1]
		}
	}

	// Store server header in metadata if present
	if serverHeader != "" {
		metadata["server"] = serverHeader
	}

	// Must have at least one confirmed Splunk signal
	if xSplunkVersion == "" && !strings.HasPrefix(serverHeader, "Splunkd") {
		return nil, nil // Not Splunk
	}

	// Validate version format if present (prevent CPE injection)
	if version != "" && !splunkVersionRegex.MatchString(version) {
		return nil, nil // Invalid version format
	}

	return &FingerprintResult{
		Technology: "splunk",
		Version:    version,
		CPEs:       []string{buildSplunkCPE(version)},
		Metadata:   metadata,
	}, nil
}

// buildSplunkCPE generates a CPE (Common Platform Enumeration) string for Splunk.
// CPE format: cpe:2.3:a:splunk:splunk:{version}:*:*:*:*:*:*:*
//
// When version is unknown, uses "*" for version field to enable asset inventory use cases.
func buildSplunkCPE(version string) string {
	if version == "" {
		version = "*" // Unknown version, but known product
	}
	return fmt.Sprintf("cpe:2.3:a:splunk:splunk:%s:*:*:*:*:*:*:*", version)
}
