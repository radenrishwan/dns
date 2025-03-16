package dns

import (
	"strings"
)

type Message struct {
	Header    DNSHeader
	Questions []byte
	Answers   []byte
}

func NewMessage() *Message {
	return &Message{
		Header:    DNSHeader{},
		Questions: make([]byte, 12),
		Answers:   make([]byte, 12),
	}
}

func (m *Message) SetQuestion(msg string) {
	msgs := strings.Split(msg, ".")
	var result []byte

	for _, msg := range msgs {
		result = append(result, byte(len(msg)))
		result = append(result, []byte(msg)...)
	}

	// Add \x00 to end of message
	result = append(result, 0)

	// hexStr := ""
	// for _, b := range result {
	// 	if hexStr != "" {
	// 		hexStr += " "
	// 	}
	// 	hexStr += fmt.Sprintf("%02x", b)
	// }

	// fmt.Println(hexStr)

	m.Questions = append(m.Questions, result...)
}

func (m *Message) Serialise() []byte {
	result := make([]byte, 0)

	result = append(result, m.Header.Serialize()...)
	result = append(result, m.Questions...)
	result = append(result, m.Answers...)

	return result
}
