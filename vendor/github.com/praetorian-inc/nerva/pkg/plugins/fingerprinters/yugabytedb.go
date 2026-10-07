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

package fingerprinters

import (
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"
)

// YugabyteDBFingerprinter detects YugabyteDB via /api/v1/version endpoint.
// Note: Master typically runs on port 7000, TServer on port 9000.
// Node type cannot be determined from the API response alone.
type YugabyteDBFingerprinter struct{}

// yugabyteDBResponse represents the JSON response from /api/v1/version endpoint
type yugabyteDBResponse struct {
	VersionInfo yugabyteDBVersionInfo `json:"version_info"`
}

// yugabyteDBVersionInfo represents version information from YugabyteDB
type yugabyteDBVersionInfo struct {
	VersionString string `json:"version_string"`
	Edition       string `json:"edition"`
	VersionMajor  string `json:"version_major"`
	VersionMinor  string `json:"version_minor"`
	VersionPatch  string `json:"version_patch"`
	BuildNumber   string `json:"build_number"`
}

// yugabyteDBVersionRegex validates version format to prevent CPE injection
// Allows: digits, dots, and hyphens (e.g., "2.14.0.0-b94")
var yugabyteDBVersionRegex = regexp.MustCompile(`^[\d\.\-a-zA-Z]+$`)

func init() {
	Register(&YugabyteDBFingerprinter{})
}

func (f *YugabyteDBFingerprinter) Name() string {
	return "yugabytedb"
}

func (f *YugabyteDBFingerprinter) ProbeEndpoint() string {
	return "/api/v1/version"
}

func (f *YugabyteDBFingerprinter) Match(resp *http.Response) bool {
	// YugabyteDB returns JSON at /api/v1/version endpoint
	contentType := resp.Header.Get("Content-Type")
	return strings.Contains(contentType, "application/json")
}

func (f *YugabyteDBFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	// Parse JSON response
	var ybResponse yugabyteDBResponse
	if err := json.Unmarshal(body, &ybResponse); err != nil {
		return nil, nil // Not valid JSON or not YugabyteDB format
	}

	// Extract version from version_info.version_string
	version := ybResponse.VersionInfo.VersionString

	// YugabyteDB detection: version_string must be non-empty
	if version == "" {
		return nil, nil
	}

	// Validate version format to prevent CPE injection
	if !yugabyteDBVersionRegex.MatchString(version) {
		return nil, nil
	}

	// Build metadata
	metadata := map[string]any{
		"detection_method": "version_api",
		// Document that port determines node type
		"port_info": "master=7000, tserver=9000",
	}

	// Add optional fields if present
	if ybResponse.VersionInfo.Edition != "" {
		metadata["edition"] = ybResponse.VersionInfo.Edition
	}
	if ybResponse.VersionInfo.VersionMajor != "" {
		metadata["version_major"] = ybResponse.VersionInfo.VersionMajor
	}
	if ybResponse.VersionInfo.VersionMinor != "" {
		metadata["version_minor"] = ybResponse.VersionInfo.VersionMinor
	}
	if ybResponse.VersionInfo.VersionPatch != "" {
		metadata["version_patch"] = ybResponse.VersionInfo.VersionPatch
	}
	if ybResponse.VersionInfo.BuildNumber != "" {
		metadata["build_number"] = ybResponse.VersionInfo.BuildNumber
	}

	return &FingerprintResult{
		Technology: "yugabytedb",
		Version:    version,
		CPEs:       []string{buildYugabyteDBCPE(version)},
		Metadata:   metadata,
	}, nil
}

// buildYugabyteDBCPE generates a CPE (Common Platform Enumeration) string for YugabyteDB.
// CPE format: cpe:2.3:a:yugabyte:yugabytedb:{version}:*:*:*:*:*:*:*
//
// When version is unknown, uses "*" for version field to enable asset inventory use cases.
func buildYugabyteDBCPE(version string) string {
	// YugabyteDB product is always known when this is called, so always generate CPE
	if version == "" {
		version = "*" // Unknown version, but known product
	}
	return fmt.Sprintf("cpe:2.3:a:yugabyte:yugabytedb:%s:*:*:*:*:*:*:*", version)
}
