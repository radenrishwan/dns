package dns

import "fmt"

type Message struct {
	Header    DNSHeader
	Questions Question
	Answers   ResourceRecord
	Authority ResourceRecord
	Addition  ResourceRecord
}

func NewMessage() *Message {
	return &Message{
		Header:    DNSHeader{},
		Questions: Question{},
		Answers:   ResourceRecord{},
		Authority: ResourceRecord{},
		Addition:  ResourceRecord{},
	}
}

const (
	headerOffset   = 12
	questionOffset = 6
	resourceOffset = 12
)

func (m *Message) Parse(data []byte) error {
	offset := headerOffset // start after the header

	if len(data) < 12 {
		return fmt.Errorf("data is too short")
	}

	if err := m.Header.Parse(data[:12]); err != nil {
		return fmt.Errorf("failed to parse header: %v", err)
	}

	if m.Header.QDCount > 0 {
		if err := m.Questions.Parse(data[offset:]); err != nil {
			return fmt.Errorf("failed to parse question: %v", err)
		}

		offset += questionOffset
	}

	if m.Header.ANCount > 0 {
		if err := m.Answers.Parse(data[offset:]); err != nil {
			return fmt.Errorf("failed to parse answer: %v", err)
		}

		offset += resourceOffset + int(m.Answers.RDLength)
	}

	if m.Header.NSCount > 0 {
		if err := m.Authority.Parse(data[offset:]); err != nil {
			return fmt.Errorf("failed to parse authority: %v", err)
		}

		offset += resourceOffset + int(m.Authority.RDLength)
	}

	if m.Header.ARCount > 0 {
		if err := m.Addition.Parse(data[offset:]); err != nil {
			return fmt.Errorf("failed to parse additional: %v", err)
		}
	}

	return nil
}

func (m *Message) Serialise() []byte {
	totalSize := headerOffset // count the message size

	if m.Header.QDCount > 0 {
		totalSize += questionOffset
	}

	if m.Header.ANCount > 0 {
		totalSize += resourceOffset + int(m.Answers.RDLength)
	}

	if m.Header.NSCount > 0 {
		totalSize += resourceOffset + int(m.Authority.RDLength)
	}

	if m.Header.ARCount > 0 {
		totalSize += resourceOffset + int(m.Addition.RDLength)
	}

	data := make([]byte, totalSize)

	headerData := m.Header.Serialize()
	copy(data[0:12], headerData)

	// serialize the message
	offset := headerOffset

	if m.Header.QDCount > 0 {
		questionData := m.Questions.Serialize()
		copy(data[offset:offset+len(questionData)], questionData)
		offset += len(questionData)
	}

	if m.Header.ANCount > 0 {
		answersData := m.Answers.Serialize()
		copy(data[offset:offset+len(answersData)], answersData)
		offset += len(answersData)
	}

	if m.Header.NSCount > 0 {
		authorityData := m.Authority.Serialize()
		copy(data[offset:offset+len(authorityData)], authorityData)
		offset += len(authorityData)
	}

	if m.Header.ARCount > 0 {
		additionalData := m.Addition.Serialize()
		copy(data[offset:offset+len(additionalData)], additionalData)
	}

	return data
}
