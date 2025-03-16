package dns

import (
	"encoding/binary"
	"fmt"
)

// 															 1  1  1  1  1  1
// 0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |                                               |
// /                                               /
// /                      NAME                     /
// |                                               |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |                      TYPE                     |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |                     CLASS                     |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |                      TTL                      |
// |                                               |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |                   RDLENGTH                    |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--|
// /                     RDATA                     /
// /                                               /
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

type ResourceRecord struct {
	Name     []byte
	Type     uint16
	Class    uint16
	TTL      uint32
	RDLength uint16
	RData    []byte // RData size is based on TYPE and CLASS
}

func (r *ResourceRecord) Parse(data []byte) error {
	if len(data) < 10 {
		return fmt.Errorf("data is too short")
	}

	r.Name = data[0:2]
	r.Type = binary.BigEndian.Uint16(data[2:4])
	r.Class = binary.BigEndian.Uint16(data[4:6])
	r.TTL = binary.BigEndian.Uint32(data[6:10])
	r.RDLength = binary.BigEndian.Uint16(data[10:12])
	r.RData = data[12 : 12+r.RDLength]

	return nil
}

func (r *ResourceRecord) Serialize() (data []byte) {
	data = make([]byte, 12+len(r.RData))

	data = append(data, r.Name...)

	binary.BigEndian.PutUint16(data[2:4], r.Type)
	binary.BigEndian.PutUint16(data[4:6], r.Class)
	binary.BigEndian.PutUint32(data[6:10], r.TTL)
	binary.BigEndian.PutUint16(data[10:12], r.RDLength)
	copy(data[12:], r.RData)

	return data
}
