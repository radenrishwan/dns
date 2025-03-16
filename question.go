package dns

import (
	"encoding/binary"
	"fmt"
)

type Question struct {
	QName  uint16
	QType  uint16
	QClass uint16
}

func (q *Question) Parse(data []byte) error {
	if len(data) < 4 {
		return fmt.Errorf("data is too short")
	}

	q.QName = binary.BigEndian.Uint16(data[0:2])
	q.QType = binary.BigEndian.Uint16(data[2:4])
	q.QClass = binary.BigEndian.Uint16(data[4:6])

	return nil
}

func (q *Question) Serialize() (data []byte) {
	data = make([]byte, 6)

	binary.BigEndian.PutUint16(data[0:2], q.QName)
	binary.BigEndian.PutUint16(data[2:4], q.QType)
	binary.BigEndian.PutUint16(data[4:6], q.QClass)

	return data
}
