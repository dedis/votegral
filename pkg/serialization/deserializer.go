package serialization

import (
	"bytes"
	"encoding/binary"
	"go.dedis.ch/kyber/v3"
	"io"
)

// Deserializer is a utility for reading and decoding data from a byte stream.
type Deserializer struct {
	r   *bytes.Reader
	err error
}

// NewDeserializer creates a new Deserializer instance for reading and decoding data from the provided byte slice.
func NewDeserializer(data []byte) *Deserializer {
	return &Deserializer{r: bytes.NewReader(data)}
}

// Read reads the exact number of bytes into p from the underlying reader
func (d *Deserializer) Read(p []byte) {
	if d.err != nil {
		return
	}
	_, d.err = io.ReadFull(d.r, p)
}

// ReadUint64 reads an unsigned 64-bit integer from the underlying byte stream in BigEndian order.
func (d *Deserializer) ReadUint64() uint64 {
	if d.err != nil {
		return 0
	}
	var u uint64
	d.err = binary.Read(d.r, binary.BigEndian, &u)
	return u
}

// ReadKyber reads and unmarshals the provided kyber.Marshaling objects from the underlying byte stream.
func (d *Deserializer) ReadKyber(obj ...kyber.Marshaling) {
	if d.err != nil {
		return
	}
	for _, o := range obj {
		_, d.err = o.UnmarshalFrom(d.r)
		if d.err != nil {
			return
		}
	}
}

// ReadBytes reads from the current position to the end of the reader.
func (d *Deserializer) ReadBytes() []byte {
	if d.err != nil {
		return nil
	}
	rem := d.r.Len()
	if rem == 0 {
		return []byte{}
	}
	buf := make([]byte, rem)
	d.Read(buf)
	return buf
}

// ReadByteSlice reads a length-prefixed byte slice.
func (d *Deserializer) ReadByteSlice() []byte {
	if d.err != nil {
		return nil
	}
	// Read length as a uint32
	var length uint32
	d.err = binary.Read(d.r, binary.BigEndian, &length)
	if d.err != nil {
		return nil
	}
	buf := make([]byte, length)
	d.Read(buf)
	return buf
}

func (d *Deserializer) Err() error {
	if d.err == io.EOF {
		return nil // EOF is expected
	}
	return d.err
}
