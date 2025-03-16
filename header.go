package dns

import (
	"encoding/binary"
	"fmt"
)

type OpCodeType uint8

const (
	StandardQuery       OpCodeType = 0
	InverseQuery        OpCodeType = 1
	ServerStatusRequest OpCodeType = 2
)

type DNSHeader struct {
	TransactionId uint16
	Flags         flags
	QDCount       uint16
	ANCount       uint16
	NSCount       uint16
	ARCount       uint16
}

func (d *DNSHeader) Parse(data []byte) error {
	if len(data) < 12 {
		return fmt.Errorf("data is too short")
	}

	if len(data) > 512 { // in udp, the maximum size is 512 bytes
		return fmt.Errorf("data is too long")
	}

	d.TransactionId = binary.BigEndian.Uint16(data[0:2])

	d.Flags.Parse(binary.BigEndian.Uint16(data[2:4]))

	d.QDCount = binary.BigEndian.Uint16(data[4:6])
	d.ANCount = binary.BigEndian.Uint16(data[6:8])
	d.NSCount = binary.BigEndian.Uint16(data[8:10])
	d.ARCount = binary.BigEndian.Uint16(data[10:12])

	return nil
}

func (d *DNSHeader) Serialize() (data []byte) {
	data = make([]byte, 12)

	binary.BigEndian.PutUint16(data[0:2], d.TransactionId)

	binary.BigEndian.PutUint16(data[2:4], d.Flags.Serialize())

	binary.BigEndian.PutUint16(data[4:6], d.QDCount)
	binary.BigEndian.PutUint16(data[6:8], d.ANCount)
	binary.BigEndian.PutUint16(data[8:10], d.NSCount)
	binary.BigEndian.PutUint16(data[10:12], d.ARCount)

	return data
}

func (d *DNSHeader) IsQuery() bool {
	return d.Flags.QR == 0
}

func (d *DNSHeader) IsResponse() bool {
	return d.Flags.QR == 1
}

func (d *DNSHeader) OpCodeType() OpCodeType {
	return OpCodeType(d.Flags.OpCode)
}

func (d *DNSHeader) IsAuthoritative() bool {
	return d.Flags.AA == 1
}

func (d *DNSHeader) IsTruncated() bool {
	return d.Flags.TC == 1
}

func (d *DNSHeader) IsRecursionDesired() bool {
	return d.Flags.RD == 1
}

func (d *DNSHeader) IsRecursionAvailable() bool {
	return d.Flags.RA == 1
}

func (d *DNSHeader) ResponseCode() uint8 {
	return d.Flags.RCode
}

func (d *DNSHeader) SetResponse(isResponse bool) {
	if isResponse {
		d.Flags.QR = 1
	} else {
		d.Flags.QR = 0
	}
}

func (d *DNSHeader) SetRecursionAvailable(isRecursion bool) {
	if isRecursion {
		d.Flags.RD = 1
	} else {
		d.Flags.RD = 0
	}
}

func (d *DNSHeader) SetAuthoritative(isAuthoritative bool) {
	if isAuthoritative {
		d.Flags.AA = 1
	} else {
		d.Flags.AA = 0
	}
}

func (d *DNSHeader) SetTruncated(isTruncated bool) {
	if isTruncated {
		d.Flags.TC = 1
	} else {
		d.Flags.TC = 0
	}
}

func (d *DNSHeader) SetRecursionDesired(isRecursion bool) {
	if isRecursion {
		d.Flags.RD = 1
	} else {
		d.Flags.RD = 0
	}
}

func (d *DNSHeader) SetNumberOfQuestions(count uint16) {
	d.QDCount = count
}

func (d *DNSHeader) String() string {
	return fmt.Sprintf("Transaction ID: %d\nFlags: %+v\nQuestions: %d\nAnswer RRs: %d\nAuthority RRs: %d\nAdditional RRs: %d",
		d.TransactionId, d.Flags, d.QDCount, d.ANCount, d.NSCount, d.ARCount)
}
