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
	"strings"
	"testing"
)

func TestIsHTTPRequest(t *testing.T) {
	tests := []struct {
		name   string
		data   []byte
		expect bool
	}{
		{"GET", []byte("GET / HTTP/1.1\r\n"), true},
		{"POST", []byte("POST /api HTTP/1.1\r\n"), true},
		{"PUT lowercase", []byte("put / HTTP/1.1\r\n"), false}, // case sensitive
		{"non-HTTP", []byte("\x16\x03\x01\x00\xa0"), false},
		{"HTTP response", []byte("HTTP/1.1 200 OK\r\n"), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsHTTPRequest(tt.data); got != tt.expect {
				t.Errorf("IsHTTPRequest() = %v, want %v", got, tt.expect)
			}
		})
	}
}

func TestIsHTTPResponse(t *testing.T) {
	tests := []struct {
		name   string
		data   []byte
		expect bool
	}{
		{"HTTP/1.1 200", []byte("HTTP/1.1 200 OK\r\n"), true},
		{"HTTP/1.0 404", []byte("HTTP/1.0 404 Not Found\r\n"), true},
		{"GET request", []byte("GET / HTTP/1.1\r\n"), false},
		{"non-HTTP", []byte("\x16\x03\x01\x00\xa0"), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsHTTPResponse(tt.data); got != tt.expect {
				t.Errorf("IsHTTPResponse() = %v, want %v", got, tt.expect)
			}
		})
	}
}

func TestFormatHTTPHex(t *testing.T) {
	// HTTP request with body
	reqData := []byte("POST /api HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/json\r\nContent-Length: 18\r\n\r\n{\"key\": \"value\"}")
	formatted, isHTTP := FormatHTTPHex(reqData)
	if !isHTTP {
		t.Fatal("expected HTTP detection")
	}
	if !strings.Contains(formatted, "POST /api HTTP/1.1") {
		t.Error("expected method line in output")
	}
	if !strings.Contains(formatted, "Host: example.com") {
		t.Error("expected Host header in output")
	}
	if !strings.Contains(formatted, "Body") {
		t.Error("expected Body section in output")
	}
	if !strings.Contains(formatted, "7B226B657922") { // {"key" in hex
		t.Errorf("expected body hex, got:\n%s", formatted)
	}

	t.Logf("HTTP request output:\n%s", formatted)
}

func TestFormatHTTPHex_Response(t *testing.T) {
	respData := []byte("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 13\r\n\r\nHello, World!")
	formatted, isHTTP := FormatHTTPHex(respData)
	if !isHTTP {
		t.Fatal("expected HTTP detection")
	}
	if !strings.Contains(formatted, "HTTP/1.1 200 OK") {
		t.Error("expected status line")
	}
	if !strings.Contains(formatted, "Content-Type: text/html") {
		t.Error("expected Content-Type header")
	}
	if !strings.Contains(formatted, "Body") {
		t.Error("expected Body section")
	}
	if !strings.Contains(formatted, "48656C6C6F2C2057") || !strings.Contains(formatted, "6F726C6421") { // "Hello, World!" in hex
		t.Errorf("expected body hex, got:\n%s", formatted)
	}
	t.Logf("HTTP response output:\n%s", formatted)
}

func TestFormatHTTPHex_NonHTTP(t *testing.T) {
	// TLS ClientHello fragment
	data := []byte("\x16\x03\x01\x00\xa0\x01\x00\x00\x9c\x03\x03")
	formatted, isHTTP := FormatHTTPHex(data)
	if isHTTP {
		t.Error("should not detect as HTTP")
	}
	if formatted != "" {
		t.Error("should return empty for non-HTTP")
	}
}

func TestFormatHTTPHex_NoBody(t *testing.T) {
	// GET request without body
	reqData := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
	formatted, isHTTP := FormatHTTPHex(reqData)
	if !isHTTP {
		t.Fatal("expected HTTP detection")
	}
	if !strings.Contains(formatted, "no body") {
		t.Error("expected no body indicator")
	}
}

func TestFormatHTTPHex_Incomplete(t *testing.T) {
	// Incomplete: no \r\n\r\n
	data := []byte("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n")
	formatted, isHTTP := FormatHTTPHex(data)
	if !isHTTP {
		t.Fatal("expected HTTP detection")
	}
	if !strings.Contains(formatted, "incomplete") {
		t.Error("expected incomplete indicator")
	}
}
