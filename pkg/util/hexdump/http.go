// Copyright 2022 CFC4N <cfc4n.cs@gmail.com>. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package hexdump

import (
	"bytes"
	"fmt"
	"strings"
)

// HTTP methods for detection.
var httpMethods = [][]byte{
	[]byte("GET "),
	[]byte("POST "),
	[]byte("PUT "),
	[]byte("DELETE "),
	[]byte("PATCH "),
	[]byte("HEAD "),
	[]byte("OPTIONS "),
	[]byte("CONNECT "),
	[]byte("TRACE "),
}

// IsHTTPRequest checks if data looks like an HTTP/1.x request.
func IsHTTPRequest(data []byte) bool {
	for _, m := range httpMethods {
		if bytes.HasPrefix(data, m) {
			return true
		}
	}
	return false
}

// IsHTTPResponse checks if data looks like an HTTP/1.x response.
func IsHTTPResponse(data []byte) bool {
	return bytes.HasPrefix(data, []byte("HTTP/1."))
}

// FormatHTTPHex detects if data is HTTP/1.x and formats it with readable
// headers and hex-dumped body. Returns the formatted string and whether
// it was detected as HTTP.
func FormatHTTPHex(data []byte) (string, bool) {
	isReq := IsHTTPRequest(data)
	isResp := IsHTTPResponse(data)
	if !isReq && !isResp {
		return "", false
	}

	// Try to split headers and body at \r\n\r\n
	idx := bytes.Index(data, []byte("\r\n\r\n"))
	if idx == -1 {
		// No body separator found, treat everything as headers (maybe incomplete)
		return formatHTTPAllHeaders(data), true
	}

	headers := data[:idx+4] // include the \r\n\r\n
	body := data[idx+4:]

	var sb strings.Builder
	sb.WriteString(cleanHTTPHeaders(headers))

	if len(body) > 0 {
		fmt.Fprintf(&sb, "-- Body (%d bytes, hex): --\n", len(body))
		sb.WriteString(DumpByteSlice(body, ""))
	} else {
		sb.WriteString("-- (no body) --\n")
	}

	return sb.String(), true
}

// formatHTTPAllHeaders formats data that has no body separator.
func formatHTTPAllHeaders(data []byte) string {
	var sb strings.Builder
	sb.WriteString(cleanHTTPHeaders(data))
	sb.WriteString("-- (incomplete, no body separator) --\n")
	return sb.String()
}

// cleanHTTPHeaders formats HTTP headers for readable display.
func cleanHTTPHeaders(headers []byte) string {
	s := string(headers)
	s = strings.TrimSuffix(s, "\r\n\r\n")
	s = strings.ReplaceAll(s, "\r\n", "\n")
	return s + "\n"
}
