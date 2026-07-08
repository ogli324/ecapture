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

package event_processor

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/gojue/ecapture/pkg/util/hexdump"
	pb "github.com/gojue/ecapture/protobuf/gen/v1"
)

type AttachType int64

const (
	ProbeEntry AttachType = iota
	ProbeRet
)

const MaxDataSize = 1024 * 16

const (
	Ssl2Version   = 0x0002
	Ssl3Version   = 0x0300
	Tls1Version   = 0x0301
	Tls11Version  = 0x0302
	Tls12Version  = 0x0303
	Tls13Version  = 0x0304
	Dtls1Version  = 0xFEFF
	Dtls12Version = 0xFEFD
)

type TlsVersion struct {
	Version int32
}

func (t TlsVersion) String() string {
	switch t.Version {
	case Ssl2Version:
		return "SSL2_VERSION"
	case Ssl3Version:
		return "SSL3_VERSION"
	case Tls1Version:
		return "TLS1_VERSION"
	case Tls11Version:
		return "TLS1_1_VERSION"
	case Tls12Version:
		return "TLS1_2_VERSION"
	case Tls13Version:
		return "TLS1_3_VERSION"
	case Dtls1Version:
		return "DTLS1_VERSION"
	case Dtls12Version:
		return "DTLS1_2_VERSION"
	}
	return fmt.Sprintf("TLS_VERSION_UNKNOWN_%d", t.Version)
}

type BaseEvent struct {
	eventType Type
	DataType  int64
	Timestamp uint64
	Pid       uint32
	Tid       uint32
	Data      [MaxDataSize]byte
	DataLen   int32
	Comm      [16]byte
	Fd        uint32
	Version   int32
}

func (be *BaseEvent) Decode(payload []byte) (err error) {
	buf := bytes.NewBuffer(payload)
	if err = binary.Read(buf, binary.LittleEndian, &be.DataType); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &be.Timestamp); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &be.Pid); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &be.Tid); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &be.Data); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &be.DataLen); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &be.Comm); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &be.Fd); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &be.Version); err != nil {
		return
	}

	return nil
}

func (be *BaseEvent) GetUUID() string {
	return fmt.Sprintf("%d_%d_%s_%d_%d", be.Pid, be.Tid, CToGoString(be.Comm[:]), be.Fd, be.DataType)
}

func (be *BaseEvent) Payload() []byte {
	return be.Data[:be.DataLen]
}

func (be *BaseEvent) PayloadLen() int {
	return int(be.DataLen)
}

func (be *BaseEvent) StringHex() string {

	var prefix, connInfo string
	switch AttachType(be.DataType) {
	case ProbeEntry:
		connInfo = fmt.Sprintf("Received %d bytes", be.DataLen)
	case ProbeRet:
		connInfo = fmt.Sprintf("Send %d bytes", be.DataLen)
	default:
		prefix = fmt.Sprintf("UNKNOWN_%d", be.DataType)
	}

	b := hexdump.DumpByteSlice(be.Data[:be.DataLen], prefix)

	v := TlsVersion{Version: be.Version}
	s := fmt.Sprintf("PID:%d, Comm:%s, TID:%d, %s, Version:%s, Payload:\n%s", be.Pid, CToGoString(be.Comm[:]), be.Tid, connInfo, v.String(), b)
	return s
}

func (be *BaseEvent) String() string {

	var connInfo string
	switch AttachType(be.DataType) {
	case ProbeEntry:
		connInfo = fmt.Sprintf("Received %dbytes", be.DataLen)
	case ProbeRet:
		connInfo = fmt.Sprintf("Send %d bytes", be.DataLen)
	default:
		connInfo = fmt.Sprintf("UNKNOWN_%d", be.DataType)
	}
	v := TlsVersion{Version: be.Version}
	s := fmt.Sprintf("PID:%d, Comm:%s, TID:%d, Version:%s, %s, Payload:\n%s", be.Pid, bytes.TrimSpace(be.Comm[:]), be.Tid, v.String(), connInfo, string(be.Data[:be.DataLen]))
	return s
}

func (be *BaseEvent) Clone() IEventStruct {
	e := new(BaseEvent)
	e.eventType = TypeOutput
	return e
}

func (be *BaseEvent) Base() Base {
	return Base{
		Timestamp: int64(be.Timestamp),
		UUID:      be.GetUUID(),
		PID:       int64(be.Pid),
		PName:     CToGoString(be.Comm[:]),
	}
}

func (be *BaseEvent) ToProtobufEvent() *pb.Event {
	// Convert BaseEvent to protobuf Event. Some fields (IPs/ports) are not available at this layer
	// and will remain zero values. Display() will fill Type/Length/Payload accordingly.
	return &pb.Event{
		Timestamp: int64(be.Timestamp),
		Uuid:      be.GetUUID(),
		Pid:       int64(be.Pid),
		Pname:     CToGoString(be.Comm[:]),
	}
}

func (be *BaseEvent) EventType() Type {
	return be.eventType
}

func CToGoString(c []byte) string {
	n := -1
	for i, b := range c {
		if b == 0 {
			break
		}
		n = i
	}
	return string(c[:n+1])
}
