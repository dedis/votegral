package serialization

import (
	"bytes"
	"encoding/binary"
	"go.dedis.ch/kyber/v3"
	"io"
)

type Deserializer struct {
	r   *bytes.Reader
	err error
}

func NewDeserializer(data []byte) *Deserializer {
	return &Deserializer{r: bytes.NewReader(data)}
}

func (d *Deserializer) Read(p []byte) {
	if d.err != nil {
		return
	}
	_, d.err = io.ReadFull(d.r, p)
}

func (d *Deserializer) ReadUint64() uint64 {
	if d.err != nil {
		return 0
	}
	var u uint64
	d.err = binary.Read(d.r, binary.BigEndian, &u)
	return u
}

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
