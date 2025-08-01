package serialization

import (
	"bytes"
	"encoding/binary"
	"go.dedis.ch/kyber/v3"
)

type Serializer struct {
	buf *bytes.Buffer
	err error
}

func NewSerializer() *Serializer {
	return &Serializer{buf: new(bytes.Buffer)}
}

func (s *Serializer) Write(data []byte) {
	if s.err != nil {
		return
	}
	_, s.err = s.buf.Write(data)
}

func (s *Serializer) WriteUint64(u uint64) {
	if s.err != nil {
		return
	}
	s.err = binary.Write(s.buf, binary.BigEndian, u)
}

func (s *Serializer) WriteKyber(obj ...kyber.Marshaling) {
	if s.err != nil {
		return
	}
	for _, o := range obj {
		_, s.err = o.MarshalTo(s.buf)
		if s.err != nil {
			return
		}
	}
}

// WriteByteSlice writes a length-prefixed byte slice.
func (s *Serializer) WriteByteSlice(b []byte) {
	if s.err != nil {
		return
	}
	// Write length as a uint32
	s.err = binary.Write(s.buf, binary.BigEndian, uint32(len(b)))
	if s.err != nil {
		return
	}
	s.Write(b)
}

func (s *Serializer) Bytes() ([]byte, error) {
	if s.err != nil {
		return nil, s.err
	}
	return s.buf.Bytes(), nil
}
