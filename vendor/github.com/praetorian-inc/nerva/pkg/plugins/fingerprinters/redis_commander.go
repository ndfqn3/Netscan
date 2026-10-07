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
	"net/http"
	"regexp"
	"strings"
)

// RedisCommanderFingerprinter detects Redis Commander web management interfaces.
//
// Detection Strategy:
// Redis Commander serves a distinctive HTML page at / with unique markers.
// All /apiv1/* and /apiv2/* routes require authentication, so detection is
// passive and based on the root HTML page body only:
//
//  1. PRIMARY:   <title>Redis Commander in the body (case-insensitive)
//  2. SECONDARY: redisCommander.js script reference (highly distinctive)
//
// Must match PRIMARY or SECONDARY to confirm detection.
//
// Version Detection:
// Redis Commander does NOT expose its version in the HTML page.
// The version field is always empty and CPE uses wildcard (*).
//
// Metadata:
//   - title: dynamic portion extracted after "Redis Commander: " in the title tag
//   - read_only: heuristic based on absence of editing modal elements
type RedisCommanderFingerprinter struct{}

func init() {
	Register(&RedisCommanderFingerprinter{})
}

// redisCommanderTitlePattern extracts the dynamic title portion from the Redis Commander title tag.
// Matches: <title>Redis Commander: {dynamic-title}</title>
var redisCommanderTitlePattern = regexp.MustCompile(`(?i)<title>\s*Redis Commander:\s*(.+?)\s*</title>`)

func (f *RedisCommanderFingerprinter) Name() string {
	return "redis_commander"
}

// Match returns true for responses with a text/html Content-Type.
// Redis Commander serves HTML at its root page, so this pre-filters
// on content type before reading the body.
func (f *RedisCommanderFingerprinter) Match(resp *http.Response) bool {
	ct := resp.Header.Get("Content-Type")
	return strings.Contains(ct, "text/html")
}

// Fingerprint performs Redis Commander detection from the HTTP response body.
// Returns nil if the page does not contain Redis Commander markers.
func (f *RedisCommanderFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	ct := resp.Header.Get("Content-Type")
	if !strings.Contains(ct, "text/html") {
		return nil, nil
	}

	if len(body) == 0 {
		return nil, nil
	}

	bodyStr := string(body)

	// PRIMARY detection: title tag containing "Redis Commander" (case-insensitive)
	primaryMatch := strings.Contains(strings.ToLower(bodyStr), "<title>redis commander")

	// SECONDARY detection: distinctive redisCommander.js script reference
	secondaryMatch := strings.Contains(bodyStr, "redisCommander.js")

	if !primaryMatch && !secondaryMatch {
		return nil, nil
	}

	metadata := make(map[string]any)

	// Extract dynamic title portion after "Redis Commander: "
	if matches := redisCommanderTitlePattern.FindStringSubmatch(bodyStr); len(matches) > 1 {
		metadata["title"] = strings.TrimSpace(matches[1])
	}

	// Read-only heuristic: absence of editing modal elements suggests read-only mode
	metadata["read_only"] = !strings.Contains(bodyStr, "addListValue")

	return &FingerprintResult{
		Technology: "redis_commander",
		Version:    "",
		CPEs:       []string{buildRedisCommanderCPE()},
		Metadata:   metadata,
	}, nil
}

// buildRedisCommanderCPE constructs the CPE string for Redis Commander.
// Version is always wildcard since it cannot be determined from the HTML page.
func buildRedisCommanderCPE() string {
	return "cpe:2.3:a:redis-commander:redis_commander:*:*:*:*:*:*:*:*"
}
