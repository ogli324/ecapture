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
	"fmt"
	"strings"
)

const (
	// ChunkSize is the number of bytes per line in the hex dump.
	ChunkSize = 32
	// ChunkSizeHalf is half the chunk size, used for mid-line spacing.
	ChunkSizeHalf = ChunkSize / 2
)

// DumpByteSlice formats a byte slice as a hex dump with offset, hex bytes, and
// ASCII columns (32 bytes per line). Non-printable ASCII characters are
// rendered as '.' in the ASCII column.
//
// The output follows a format similar to the traditional hexdump:
//
//	0000  48656C6C6F20576F 48656C6C6F20576F  48656C6C6F20576F 48656C6C6F20576F    Hello.WoHello.WoHello.WoHello.Wo
func DumpByteSlice(b []byte, prefix string) string {
	var sb strings.Builder
	var a [ChunkSize]byte
	n := (len(b) + (ChunkSize - 1)) &^ (ChunkSize - 1) // round up to ChunkSize

	for i := 0; i < n; i++ {
		// Write offset on new line
		if i%ChunkSize == 0 {
			sb.WriteString(prefix)
			fmt.Fprintf(&sb, "%04X", i)
		}

		// Spacing between byte groups
		if i%ChunkSizeHalf == 0 {
			sb.WriteString("  ")
		} else if i%(ChunkSizeHalf/2) == 0 {
			sb.WriteString(" ")
		}

		// Hex byte or padding
		if i < len(b) {
			fmt.Fprintf(&sb, "%02X", b[i])
		} else {
			sb.WriteString(" ")
		}

		// ASCII column character
		if i >= len(b) {
			a[i%ChunkSize] = ' '
		} else if b[i] < 32 || b[i] > 126 {
			a[i%ChunkSize] = '.'
		} else {
			a[i%ChunkSize] = b[i]
		}

		// End of line: append ASCII column
		if i%ChunkSize == (ChunkSize - 1) {
			fmt.Fprintf(&sb, "    %s\n", string(a[:]))
		}
	}
	return sb.String()
}
