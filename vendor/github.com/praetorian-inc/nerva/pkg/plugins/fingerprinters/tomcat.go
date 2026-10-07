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
Package fingerprinters provides HTTP fingerprinting for Apache Tomcat.

# Detection Strategy

Apache Tomcat is an open-source Java Servlet container. Exposed instances
represent a security concern due to:
  - Manager application with deployment capabilities
  - Potential remote code execution via WAR deployment
  - Default credentials on manager/admin applications
  - Known CVEs in older versions

Detection uses passive analysis:
  - Server header: "Apache Tomcat/X.Y.Z" or "Apache-Coyote/X.Y"
  - X-Powered-By header: "Servlet/X.Y JSP/X.Y"
  - Error page body: Contains "Apache Tomcat/X.Y.Z"
  - Default endpoints: /manager, /host-manager, /docs

# Server Header Patterns

Tomcat exposes version information through multiple headers:

	Server: Apache Tomcat/9.0.98
	Server: Apache-Coyote/1.1 (Coyote is Tomcat's HTTP connector)
	X-Powered-By: Servlet/4.0 JSP/2.3

Error pages also leak version information:

	<h3>Apache Tomcat/9.0.98</h3>

# Version to Servlet Mapping

Different Tomcat versions support different Servlet specifications:
  - Tomcat 11.x: Servlet 6.0, JSP 3.1
  - Tomcat 10.x: Servlet 5.0, JSP 3.0
  - Tomcat 9.x:  Servlet 4.0, JSP 2.3
  - Tomcat 8.x:  Servlet 3.1, JSP 2.3
  - Tomcat 7.x:  Servlet 3.0, JSP 2.2

# Port Configuration

Tomcat typically runs on:
  - 8080: Default HTTP port
  - 8443: Default HTTPS port
  - 443:  HTTPS in production

# Example Usage

	fp := &TomcatFingerprinter{}
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

// TomcatFingerprinter detects Apache Tomcat instances via headers and body
type TomcatFingerprinter struct{}

// tomcatVersionRegex extracts version from "Apache Tomcat/X.Y.Z" format
var tomcatVersionRegex = regexp.MustCompile(`Apache Tomcat/(\d+\.\d+\.\d+)`)

// coyoteVersionRegex extracts version from "Apache-Coyote/X.Y" format
var coyoteVersionRegex = regexp.MustCompile(`Apache-Coyote/(\d+\.\d+)`)

// servletVersionRegex extracts Servlet version from X-Powered-By header
var servletVersionRegex = regexp.MustCompile(`Servlet/(\d+\.\d+)`)

// jspVersionRegex extracts JSP version from X-Powered-By header
var jspVersionRegex = regexp.MustCompile(`JSP/(\d+\.\d+)`)

// tomcatVersionFormatRegex validates Tomcat version format
// Accepts: 9.0.98, 10.1.34, 11.0.2
var tomcatVersionFormatRegex = regexp.MustCompile(`^\d+\.\d+\.\d+$`)

func init() {
	Register(&TomcatFingerprinter{})
}

func (f *TomcatFingerprinter) Name() string {
	return "tomcat"
}

func (f *TomcatFingerprinter) ProbeEndpoint() string {
	// Use default "/" endpoint - Tomcat leaks info on default page and error responses
	return ""
}

func (f *TomcatFingerprinter) Match(resp *http.Response) bool {
	server := resp.Header.Get("Server")

	// Check for Apache-Coyote (Tomcat's HTTP connector)
	if strings.Contains(server, "Apache-Coyote") {
		return true
	}

	// Check for Apache Tomcat
	if strings.Contains(server, "Apache Tomcat") {
		return true
	}

	return false
}

func (f *TomcatFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	server := resp.Header.Get("Server")
	xPoweredBy := resp.Header.Get("X-Powered-By")
	bodyStr := string(body)

	var version string
	var coyoteVersion string
	var servletVersion string
	var jspVersion string

	// Extract Tomcat version from Server header
	if matches := tomcatVersionRegex.FindStringSubmatch(server); len(matches) > 1 {
		version = matches[1]
	}

	// Extract Tomcat version from error page body if not found in header
	if version == "" {
		if matches := tomcatVersionRegex.FindStringSubmatch(bodyStr); len(matches) > 1 {
			version = matches[1]
		}
	}

	// Extract Coyote version from Server header
	if matches := coyoteVersionRegex.FindStringSubmatch(server); len(matches) > 1 {
		coyoteVersion = matches[1]
	}

	// Extract Servlet version from X-Powered-By header
	if matches := servletVersionRegex.FindStringSubmatch(xPoweredBy); len(matches) > 1 {
		servletVersion = matches[1]
	}

	// Extract JSP version from X-Powered-By header
	if matches := jspVersionRegex.FindStringSubmatch(xPoweredBy); len(matches) > 1 {
		jspVersion = matches[1]
	}

	// Return nil if we have no identification information at all
	// Coyote, Servlet, or JSP versions are all sufficient signals for Tomcat
	if version == "" && coyoteVersion == "" && servletVersion == "" && jspVersion == "" {
		return nil, nil
	}

	// Validate version format to prevent CPE injection
	// This must happen AFTER we decide to return a result (not before)
	if version != "" && !tomcatVersionFormatRegex.MatchString(version) {
		return nil, nil
	}

	// Build metadata
	metadata := make(map[string]any)
	if coyoteVersion != "" {
		metadata["coyote_version"] = coyoteVersion
	}
	if servletVersion != "" {
		metadata["servlet_version"] = servletVersion
	}
	if jspVersion != "" {
		metadata["jsp_version"] = jspVersion
	}

	// Build CPE only if we have a Tomcat version
	var cpes []string
	if version != "" {
		cpes = []string{buildTomcatCPE(version)}
	}

	return &FingerprintResult{
		Technology: "tomcat",
		Version:    version,
		CPEs:       cpes,
		Metadata:   metadata,
	}, nil
}

func buildTomcatCPE(version string) string {
	if version == "" {
		version = "*"
	}
	return fmt.Sprintf("cpe:2.3:a:apache:tomcat:%s:*:*:*:*:*:*:*", version)
}
