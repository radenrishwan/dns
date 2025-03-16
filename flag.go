package dns

type flags struct {
	QR     uint8 // 1 bit
	OpCode uint8 // 4 bits
	AA     uint8 // 1 bit
	TC     uint8 // 1 bit
	RD     uint8 // 1 bit
	RA     uint8 // 1 bit
	Z      uint8 // 1 bits
	AD     uint8 // 1 bit
	CD     uint8 // 1 bit
	RCode  uint8 // 4 bits
}

// Bit position for each flag
const (
	QRPosition     = 15
	OPCodePosition = 11 // 4 bits
	AAPosition     = 10
	TCPosition     = 9
	RDPosition     = 8
	RAPosition     = 7
	ZPosition      = 6
	ADPosition     = 5
	CDPosition     = 4
	RCodePosition  = 0 // 4 bits
)

// Mask
const (
	QRMask     = 1 << QRPosition
	OPCodeMask = 0xF << OPCodePosition
	AAMask     = 1 << AAPosition
	TCMask     = 1 << TCPosition
	RDMask     = 1 << RDPosition
	RAMask     = 1 << RAPosition
	ZMask      = 1 << ZPosition
	ADMask     = 1 << ADPosition
	CDMask     = 1 << CDPosition
	RCodeMask  = 0xF << RCodePosition
)

func (f *flags) Parse(data uint16) {
	f.QR = uint8((data & QRMask) >> QRPosition)
	f.OpCode = uint8((data & OPCodeMask) >> OPCodePosition)
	f.AA = uint8((data & AAMask) >> AAPosition)
	f.TC = uint8((data & TCMask) >> TCPosition)
	f.RD = uint8((data & RDMask) >> RDPosition)
	f.RA = uint8((data & RAMask) >> RAPosition)
	f.Z = uint8((data & ZMask) >> ZPosition)
	f.AD = uint8((data & ADMask) >> ADPosition)
	f.CD = uint8((data & CDMask) >> CDPosition)
	f.RCode = uint8(data & RCodeMask)
}

func (f *flags) Serialize() uint16 {
	return uint16(f.QR)<<QRPosition |
		uint16(f.OpCode)<<OPCodePosition |
		uint16(f.AA)<<AAPosition |
		uint16(f.TC)<<TCPosition |
		uint16(f.RD)<<RDPosition |
		uint16(f.RA)<<RAPosition |
		uint16(f.Z)<<ZPosition |
		uint16(f.AD)<<ADPosition |
		uint16(f.CD)<<CDPosition |
		uint16(f.RCode)<<RCodePosition
}
