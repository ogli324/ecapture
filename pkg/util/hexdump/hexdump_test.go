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

func TestDumpByteSlice(t *testing.T) {
	tests := []struct {
		name   string
		data   []byte
		prefix string
		check  []string // substrings that must appear in the output
	}{
		{
			name:   "empty input",
			data:   []byte{},
			prefix: "",
			check:  []string{},
		},
		{
			name:   "single byte",
			data:   []byte{0x41}, // 'A'
			prefix: "",
			check:  []string{"0000  ", "41", "A", "\n"},
		},
		{
			name:   "short ASCII string",
			data:   []byte("Hello, World!"),
			prefix: "",
			check:  []string{"0000  ", "48656C6C6F2C2057", "6F726C6421", "Hello, World!"},
		},
		{
			name:   "binary data (non-printable)",
			data:   []byte{0x00, 0x01, 0x02, 0xFF, 0xFE},
			prefix: "",
			check:  []string{"0000  ", "000102FFFE", "....."},
		},
		{
			name:   "with prefix",
			data:   []byte("Test"),
			prefix: "PREFIX_",
			check:  []string{"PREFIX_0000"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := DumpByteSlice(tt.data, tt.prefix)
			for _, c := range tt.check {
				if !strings.Contains(result, c) {
					t.Errorf("expected output to contain %q, got:\n%s", c, result)
				}
			}
		})
	}
}

func TestDumpByteSlice_NonPrintable(t *testing.T) {
	// Binary data with non-printable bytes should render them as '.'
	data := []byte{0x00, 0x01, 0x02, 0x1F, 0x7F, 0xFF}
	result := DumpByteSlice(data, "")

	// Check that ASCII column has '.' for non-printable
	lines := strings.Split(strings.TrimSpace(result), "\n")
	lastLine := lines[len(lines)-1]
	// The ASCII column should contain dots for non-printable chars
	asciiPart := lastLine[strings.LastIndex(lastLine, "    ")+4:]
	if asciiPart != "......" {
		t.Errorf("expected ASCII column to show '......' for non-printable bytes, got %q", asciiPart)
	}
}

func TestDumpByteSlice_ExactLine(t *testing.T) {
	// 32 bytes should produce exactly one line
	data := make([]byte, 32)
	for i := range data {
		data[i] = 0x41 + byte(i) // 'A', 'B', 'C', ...
	}
	result := DumpByteSlice(data, "")
	lines := strings.Split(strings.TrimRight(result, "\n"), "\n")
	if len(lines) != 1 {
		t.Errorf("expected exactly 1 line for 32 bytes, got %d lines:\n%s", len(lines), result)
	}
}

func TestDumpByteSlice_MultiLine(t *testing.T) {
	// 33 bytes should produce two lines
	data := make([]byte, 33)
	for i := range data {
		data[i] = byte(i)
	}
	result := DumpByteSlice(data, "")
	lines := strings.Split(strings.TrimRight(result, "\n"), "\n")
	if len(lines) != 2 {
		t.Errorf("expected exactly 2 lines for 33 bytes, got %d lines:\n%s", len(lines), result)
	}
}
