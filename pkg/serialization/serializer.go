package serialization

import (
	"bytes"
	"encoding/binary"
	"go.dedis.ch/kyber/v3"
)

// Serializer provides methods for serializing data into a buffer.
type Serializer struct {
	buf *bytes.Buffer
	err error
}

// NewSerializer initializes and returns a new Serializer instance with an empty buffer.
func NewSerializer() *Serializer {
	return &Serializer{buf: new(bytes.Buffer)}
}

// Write writes the provided byte slice to the buffer.
func (s *Serializer) Write(data []byte) {
	if s.err != nil {
		return
	}
	_, s.err = s.buf.Write(data)
}

// WriteUint64 writes the provided uint64 value to the buffer using BigEndian encoding.
func (s *Serializer) WriteUint64(u uint64) {
	if s.err != nil {
		return
	}
	s.err = binary.Write(s.buf, binary.BigEndian, u)
}

// WriteKyber serializes one or more kyber.Marshaling objects into the buffer.
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

// Bytes returns the serialized byte slice from the buffer and any error encountered during serialization.
func (s *Serializer) Bytes() ([]byte, error) {
	if s.err != nil {
		return nil, s.err
	}
	return s.buf.Bytes(), nil
}
