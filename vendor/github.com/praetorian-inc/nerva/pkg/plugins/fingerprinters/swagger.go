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
Package fingerprinters provides HTTP fingerprinting for Swagger/OpenAPI.

# Detection Strategy

Swagger/OpenAPI is an API specification format widely used for documenting REST APIs.
Exposed Swagger/OpenAPI documentation endpoints represent a security concern due to:
  - Information disclosure of API structure, endpoints, and parameters
  - Exposure of internal API design and business logic
  - Potential discovery of unauthenticated or admin-only endpoints
  - Known CVEs in Swagger UI and related tooling

Detection uses two complementary approaches:

Primary: Active probe of OpenAPI JSON spec endpoints (no authentication required).
Multiple common endpoints are checked:
  - /v3/api-docs - Spring Boot OpenAPI 3
  - /v2/api-docs - Spring Boot Swagger 2
  - /swagger.json - Generic Swagger 2
  - /openapi.json - Generic OpenAPI 3
  - /swagger/v1/swagger.json - .NET Swashbuckle

JSON markers:
  - "openapi": "3.x" - OpenAPI 3.x
  - "swagger": "2.0" - Swagger 2.0

Secondary: Active probe of Swagger UI HTML pages.
The HTML contains Swagger-specific markers including swagger-ui.css,
swagger-ui-bundle.js, and SwaggerUIBundle JavaScript initialization.

# Version Detection

OpenAPI/Swagger exposes version information through the spec:
  - spec_version: "2.0" or "3.x.x" from the spec
  - api_title: from info.title
  - api_version: from info.version

# Port Configuration

Swagger/OpenAPI typically runs on standard HTTP ports:
  - 80: HTTP
  - 443: HTTPS
  - 8080: Common alternate HTTP port

# Example Usage

	fp := &SwaggerV2ApiDocsFingerprinter{}
	if fp.Match(resp) {
		result, err := fp.Fingerprint(resp, body)
		if err == nil && result != nil {
			fmt.Printf("Detected: %s version %s\n", result.Technology, result.Version)
		}
	}
*/
package fingerprinters

import (
	"encoding/json"
	"net/http"
	"regexp"
	"strings"
)

// SwaggerV2ApiDocsFingerprinter detects Spring Boot Swagger 2 via /v2/api-docs endpoint.
// This is the primary detection method for Spring Boot applications using Swagger 2.
type SwaggerV2ApiDocsFingerprinter struct{}

// SwaggerV3ApiDocsFingerprinter detects Spring Boot OpenAPI 3 via /v3/api-docs endpoint.
// This is the primary detection method for Spring Boot applications using OpenAPI 3.
type SwaggerV3ApiDocsFingerprinter struct{}

// SwaggerJsonFingerprinter detects Generic Swagger 2 via /swagger.json endpoint.
// This endpoint is commonly used by non-Spring Boot applications.
type SwaggerJsonFingerprinter struct{}

// OpenApiJsonFingerprinter detects Generic OpenAPI 3 via /openapi.json endpoint.
// This endpoint is commonly used by various frameworks.
type OpenApiJsonFingerprinter struct{}

// SwaggerNetFingerprinter detects .NET Swashbuckle via /swagger/v1/swagger.json endpoint.
// This is the standard endpoint for ASP.NET Core applications using Swashbuckle.
type SwaggerNetFingerprinter struct{}

// SwaggerUIFingerprinter detects Swagger UI via /swagger-ui.html or /swagger-ui/ endpoints.
// This is the secondary detection method using HTML markers.
type SwaggerUIFingerprinter struct{}

// swaggerSpec represents the minimal structure of a Swagger 2.0 spec
type swaggerSpec struct {
	Swagger string `json:"swagger"`
	Info    struct {
		Title   string `json:"title"`
		Version string `json:"version"`
	} `json:"info"`
}

// openAPISpec represents the minimal structure of an OpenAPI 3.x spec
type openAPISpec struct {
	OpenAPI string `json:"openapi"`
	Info    struct {
		Title   string `json:"title"`
		Version string `json:"version"`
	} `json:"info"`
}

// versionRegex validates semver-like version strings
// Accepts: 2.0, 3.0.1, 3.0.0-rc1, but rejects injection attempts
var versionRegex = regexp.MustCompile(`^(\d+\.\d+(?:\.\d+)?(?:-[a-zA-Z0-9._-]+)?)`)

func init() {
	Register(&SwaggerV2ApiDocsFingerprinter{})
	Register(&SwaggerV3ApiDocsFingerprinter{})
	Register(&SwaggerJsonFingerprinter{})
	Register(&OpenApiJsonFingerprinter{})
	Register(&SwaggerNetFingerprinter{})
	Register(&SwaggerUIFingerprinter{})
}

// --- SwaggerV2ApiDocsFingerprinter (Spring Boot /v2/api-docs) ---

func (f *SwaggerV2ApiDocsFingerprinter) Name() string {
	return "swagger-v2-api-docs"
}

func (f *SwaggerV2ApiDocsFingerprinter) ProbeEndpoint() string {
	return "/v2/api-docs"
}

func (f *SwaggerV2ApiDocsFingerprinter) Match(resp *http.Response) bool {
	return strings.Contains(resp.Header.Get("Content-Type"), "application/json")
}

func (f *SwaggerV2ApiDocsFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	var spec swaggerSpec
	if err := json.Unmarshal(body, &spec); err != nil {
		return nil, nil
	}

	// Validate this is Swagger 2.0
	if !strings.HasPrefix(spec.Swagger, "2.") {
		return nil, nil
	}

	// Sanitize version to prevent injection
	specVersion := sanitizeVersion(spec.Swagger)
	if specVersion == "" {
		specVersion = "2.0"
	}

	metadata := map[string]any{
		"spec_version":      specVersion,
		"detection_method":  "openapi_spec",
		"endpoint":          "/v2/api-docs",
	}

	if spec.Info.Title != "" {
		metadata["api_title"] = spec.Info.Title
	}
	if spec.Info.Version != "" {
		metadata["api_version"] = spec.Info.Version
	}

	return &FingerprintResult{
		Technology: "swagger",
		Version:    specVersion,
		CPEs:       []string{buildSwaggerCPE(specVersion)},
		Metadata:   metadata,
	}, nil
}

// --- SwaggerV3ApiDocsFingerprinter (Spring Boot /v3/api-docs) ---

func (f *SwaggerV3ApiDocsFingerprinter) Name() string {
	return "swagger-v3-api-docs"
}

func (f *SwaggerV3ApiDocsFingerprinter) ProbeEndpoint() string {
	return "/v3/api-docs"
}

func (f *SwaggerV3ApiDocsFingerprinter) Match(resp *http.Response) bool {
	return strings.Contains(resp.Header.Get("Content-Type"), "application/json")
}

func (f *SwaggerV3ApiDocsFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	var spec openAPISpec
	if err := json.Unmarshal(body, &spec); err != nil {
		return nil, nil
	}

	// Validate this is OpenAPI 3.x
	if !strings.HasPrefix(spec.OpenAPI, "3.") {
		return nil, nil
	}

	// Sanitize version to prevent injection
	specVersion := sanitizeVersion(spec.OpenAPI)
	if specVersion == "" {
		specVersion = "3.0.0"
	}

	metadata := map[string]any{
		"spec_version":      specVersion,
		"detection_method":  "openapi_spec",
		"endpoint":          "/v3/api-docs",
	}

	if spec.Info.Title != "" {
		metadata["api_title"] = spec.Info.Title
	}
	if spec.Info.Version != "" {
		metadata["api_version"] = spec.Info.Version
	}

	return &FingerprintResult{
		Technology: "openapi",
		Version:    specVersion,
		CPEs:       []string{buildOpenAPICPE(specVersion)},
		Metadata:   metadata,
	}, nil
}

// --- SwaggerJsonFingerprinter (Generic /swagger.json) ---

func (f *SwaggerJsonFingerprinter) Name() string {
	return "swagger-json"
}

func (f *SwaggerJsonFingerprinter) ProbeEndpoint() string {
	return "/swagger.json"
}

func (f *SwaggerJsonFingerprinter) Match(resp *http.Response) bool {
	return strings.Contains(resp.Header.Get("Content-Type"), "application/json")
}

func (f *SwaggerJsonFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	var spec swaggerSpec
	if err := json.Unmarshal(body, &spec); err != nil {
		return nil, nil
	}

	// Validate this is Swagger 2.0
	if !strings.HasPrefix(spec.Swagger, "2.") {
		return nil, nil
	}

	specVersion := sanitizeVersion(spec.Swagger)
	if specVersion == "" {
		specVersion = "2.0"
	}

	metadata := map[string]any{
		"spec_version":      specVersion,
		"detection_method":  "openapi_spec",
		"endpoint":          "/swagger.json",
	}

	if spec.Info.Title != "" {
		metadata["api_title"] = spec.Info.Title
	}
	if spec.Info.Version != "" {
		metadata["api_version"] = spec.Info.Version
	}

	return &FingerprintResult{
		Technology: "swagger",
		Version:    specVersion,
		CPEs:       []string{buildSwaggerCPE(specVersion)},
		Metadata:   metadata,
	}, nil
}

// --- OpenApiJsonFingerprinter (Generic /openapi.json) ---

func (f *OpenApiJsonFingerprinter) Name() string {
	return "openapi-json"
}

func (f *OpenApiJsonFingerprinter) ProbeEndpoint() string {
	return "/openapi.json"
}

func (f *OpenApiJsonFingerprinter) Match(resp *http.Response) bool {
	return strings.Contains(resp.Header.Get("Content-Type"), "application/json")
}

func (f *OpenApiJsonFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	var spec openAPISpec
	if err := json.Unmarshal(body, &spec); err != nil {
		return nil, nil
	}

	// Validate this is OpenAPI 3.x
	if !strings.HasPrefix(spec.OpenAPI, "3.") {
		return nil, nil
	}

	specVersion := sanitizeVersion(spec.OpenAPI)
	if specVersion == "" {
		specVersion = "3.0.0"
	}

	metadata := map[string]any{
		"spec_version":      specVersion,
		"detection_method":  "openapi_spec",
		"endpoint":          "/openapi.json",
	}

	if spec.Info.Title != "" {
		metadata["api_title"] = spec.Info.Title
	}
	if spec.Info.Version != "" {
		metadata["api_version"] = spec.Info.Version
	}

	return &FingerprintResult{
		Technology: "openapi",
		Version:    specVersion,
		CPEs:       []string{buildOpenAPICPE(specVersion)},
		Metadata:   metadata,
	}, nil
}

// --- SwaggerNetFingerprinter (.NET Swashbuckle /swagger/v1/swagger.json) ---

func (f *SwaggerNetFingerprinter) Name() string {
	return "swagger-net"
}

func (f *SwaggerNetFingerprinter) ProbeEndpoint() string {
	return "/swagger/v1/swagger.json"
}

func (f *SwaggerNetFingerprinter) Match(resp *http.Response) bool {
	return strings.Contains(resp.Header.Get("Content-Type"), "application/json")
}

func (f *SwaggerNetFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	// Try OpenAPI 3.x first (Swashbuckle 5.x+)
	var oaSpec openAPISpec
	if err := json.Unmarshal(body, &oaSpec); err == nil && strings.HasPrefix(oaSpec.OpenAPI, "3.") {
		specVersion := sanitizeVersion(oaSpec.OpenAPI)
		if specVersion == "" {
			specVersion = "3.0.0"
		}

		metadata := map[string]any{
			"spec_version":      specVersion,
			"detection_method":  "openapi_spec",
			"endpoint":          "/swagger/v1/swagger.json",
			"framework":         ".NET Swashbuckle",
		}

		if oaSpec.Info.Title != "" {
			metadata["api_title"] = oaSpec.Info.Title
		}
		if oaSpec.Info.Version != "" {
			metadata["api_version"] = oaSpec.Info.Version
		}

		return &FingerprintResult{
			Technology: "openapi",
			Version:    specVersion,
			CPEs:       []string{buildOpenAPICPE(specVersion)},
			Metadata:   metadata,
		}, nil
	}

	// Try Swagger 2.0 (Swashbuckle 4.x and earlier)
	var swSpec swaggerSpec
	if err := json.Unmarshal(body, &swSpec); err == nil && strings.HasPrefix(swSpec.Swagger, "2.") {
		specVersion := sanitizeVersion(swSpec.Swagger)
		if specVersion == "" {
			specVersion = "2.0"
		}

		metadata := map[string]any{
			"spec_version":      specVersion,
			"detection_method":  "openapi_spec",
			"endpoint":          "/swagger/v1/swagger.json",
			"framework":         ".NET Swashbuckle",
		}

		if swSpec.Info.Title != "" {
			metadata["api_title"] = swSpec.Info.Title
		}
		if swSpec.Info.Version != "" {
			metadata["api_version"] = swSpec.Info.Version
		}

		return &FingerprintResult{
			Technology: "swagger",
			Version:    specVersion,
			CPEs:       []string{buildSwaggerCPE(specVersion)},
			Metadata:   metadata,
		}, nil
	}

	return nil, nil
}

// --- SwaggerUIFingerprinter (HTML page) ---

func (f *SwaggerUIFingerprinter) Name() string {
	return "swagger-ui"
}

func (f *SwaggerUIFingerprinter) ProbeEndpoint() string {
	return "/swagger-ui.html"
}

func (f *SwaggerUIFingerprinter) Match(resp *http.Response) bool {
	contentType := resp.Header.Get("Content-Type")
	return strings.Contains(contentType, "text/html")
}

func (f *SwaggerUIFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	bodyStr := string(body)

	// Score-based detection using multiple Swagger UI-specific markers.
	// Require at least 2 markers to reduce false positives.
	score := 0
	var markers []string

	// Strong markers (very unique to Swagger UI) - worth 2 points each
	if strings.Contains(bodyStr, "SwaggerUIBundle") {
		score += 2
		markers = append(markers, "SwaggerUIBundle")
	}
	if strings.Contains(bodyStr, "swagger-ui-bundle.js") {
		score += 2
		markers = append(markers, "swagger-ui-bundle.js")
	}

	// Medium markers (common in Swagger UI but less specific) - worth 1 point each
	if strings.Contains(bodyStr, "swagger-ui.css") {
		score++
		markers = append(markers, "swagger-ui.css")
	}
	if strings.Contains(bodyStr, "swagger-ui-standalone-preset") {
		score++
		markers = append(markers, "swagger-ui-standalone-preset")
	}
	if strings.Contains(bodyStr, "swagger-ui.js") {
		score++
		markers = append(markers, "swagger-ui.js")
	}
	if strings.Contains(bodyStr, `id="swagger-ui"`) {
		score++
		markers = append(markers, "swagger-ui-element")
	}

	// Require score >= 2 for detection
	if score < 2 {
		return nil, nil
	}

	metadata := map[string]any{
		"detection_method":  "swagger_ui",
		"endpoint":          "/swagger-ui.html",
		"markers":           markers,
	}

	return &FingerprintResult{
		Technology: "swagger-ui",
		Version:    "",
		CPEs:       []string{buildSwaggerCPE("")},
		Metadata:   metadata,
	}, nil
}

// --- Helper functions ---

// buildSwaggerCPE generates a CPE string for Swagger.
// CPE format: cpe:2.3:a:smartbear:swagger:{version}:*:*:*:*:*:*:*
//
// The version parameter is sanitized to prevent injection attacks.
func buildSwaggerCPE(version string) string {
	// Sanitize version to prevent CPE injection
	version = sanitizeVersion(version)
	if version == "" {
		version = "*"
	}
	return "cpe:2.3:a:smartbear:swagger:" + version + ":*:*:*:*:*:*:*"
}

// buildOpenAPICPE generates a CPE string for OpenAPI.
// CPE format: cpe:2.3:a:openapis:openapi:{version}:*:*:*:*:*:*:*
//
// The version parameter is sanitized to prevent injection attacks.
func buildOpenAPICPE(version string) string {
	// Sanitize version to prevent CPE injection
	version = sanitizeVersion(version)
	if version == "" {
		version = "*"
	}
	return "cpe:2.3:a:openapis:openapi:" + version + ":*:*:*:*:*:*:*"
}

// sanitizeVersion validates and sanitizes version strings to prevent injection attacks.
// Accepts semver-like versions (e.g., "2.0", "3.0.1", "3.0.0-rc1")
// Rejects anything with special characters that could be used for injection.
func sanitizeVersion(version string) string {
	if version == "" {
		return ""
	}

	matches := versionRegex.FindStringSubmatch(version)
	if len(matches) < 2 {
		return ""
	}

	return matches[1]
}
