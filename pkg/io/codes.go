package io

import (
	"fmt"
	"votegral/pkg/ledger"
	"votegral/pkg/serialization"

	"go.dedis.ch/kyber/v3"
	"votegral/pkg/crypto"
)

// CodeType is an enumeration for the different kinds of codes in the protocol.
type CodeType int

const (
	CheckInBarcodeType CodeType = iota
	CommitQRType
	EnvelopeQRType
	CheckOutQRType
	ResponseQRType
)

func (ct CodeType) String() string {
	switch ct {
	case CheckInBarcodeType:
		return "CheckInBarcode"
	case CommitQRType:
		return "Commit"
	case EnvelopeQRType:
		return "Envelope"
	case CheckOutQRType:
		return "Checkout"
	case ResponseQRType:
		return "Response"
	default:
		return "Unknown"
	}
}

// Code is the base interface for all scannable codes.
type Code interface {
	// Type returns the specific type of the code.
	Type() CodeType
	// Serialize converts the code's data into a byte slice for transmission or storage.
	Serialize() ([]byte, error)
	// Deserialize populates the code's fields from a byte slice.
	Deserialize(data []byte) error
}

// SignableCode is an interface for codes that can be digitally signed.
type SignableCode interface {
	Code
	// MessageToSign returns the byte representation of the data that should be signed.
	MessageToSign() ([]byte, error)
	// SetSignature attaches a signature to the code.
	SetSignature(sigma []byte)
	// GetSignature retrieves the signature from the code.
	GetSignature() []byte
}

// CodeStorage defines an object that can persist in memory or on disk.
type CodeStorage interface {
	Save(codeType CodeType, location string)
	Load(codeType CodeType) string
}

// --- CheckInBarcode ---

// CheckInBarcode is a simple barcode containing a voter's ID and an HMAC tag.
type CheckInBarcode struct {
	VoterID uint64
	Tag     []byte // The HMAC tag
}

// NewCheckInBarcode is a constructor for CheckInBarcode.
func NewCheckInBarcode(id uint64, tag []byte) *CheckInBarcode {
	return &CheckInBarcode{VoterID: id, Tag: tag}
}
func (c *CheckInBarcode) Type() CodeType { return CheckInBarcodeType }

func (c *CheckInBarcode) Serialize() ([]byte, error) {
	return []byte(fmt.Sprintf("%d:%x", c.VoterID, c.Tag)), nil
}

func (c *CheckInBarcode) Deserialize(data []byte) error {
	var id uint64
	var tag []byte
	_, err := fmt.Sscanf(string(data), "%d:%x", &id, &tag)
	if err != nil {
		return fmt.Errorf("failed to parse check-in barcode data: %w", err)
	}
	c.VoterID = id
	c.Tag = tag
	return nil
}

// --- CommitQR ---

// CommitQR contains the voter's encrypted credential and ZKP commitment.
type CommitQR struct {
	VoterID    uint64
	Ciphertext crypto.ElGamalCiphertext
	Commitment crypto.ZKPCommitment
	KioskSigma []byte
}

func (c *CommitQR) Type() CodeType        { return CommitQRType }
func (c *CommitQR) GetSignature() []byte  { return c.KioskSigma }
func (c *CommitQR) SetSignature(s []byte) { c.KioskSigma = s }

func (c *CommitQR) MessageToSign() ([]byte, error) {
	s := serialization.NewSerializer()
	s.WriteUint64(c.VoterID)
	s.WriteKyber(c.Ciphertext.C1, c.Ciphertext.C2)
	s.WriteKyber(c.Commitment.Y1, c.Commitment.Y2)
	return s.Bytes()
}

func (c *CommitQR) Serialize() ([]byte, error) {
	msg, err := c.MessageToSign()
	if err != nil {
		return nil, err
	}
	return append(msg, c.KioskSigma...), nil
}

func (c *CommitQR) Deserialize(data []byte) error {
	c.Ciphertext.C1 = crypto.Suite.Point()
	c.Ciphertext.C2 = crypto.Suite.Point()
	c.Commitment.Y1 = crypto.Suite.Point()
	c.Commitment.Y2 = crypto.Suite.Point()

	s := serialization.NewDeserializer(data)
	c.VoterID = s.ReadUint64()
	s.ReadKyber(c.Ciphertext.C1, c.Ciphertext.C2)
	s.ReadKyber(c.Commitment.Y1, c.Commitment.Y2)
	c.KioskSigma = s.ReadBytes() // Read the rest of the slice as the signature
	return s.Err()
}

// --- EnvelopeQR ---

// EnvelopeQR contains a random challenge `e` and is signed by the envelope printer.
type EnvelopeQR struct {
	PrinterPK    kyber.Point
	Challenge    kyber.Scalar
	PrinterSigma []byte

	// Filepath is used for simulation purposes only in `Core` and `Disk`
	Filepath string
}

func (e *EnvelopeQR) Type() CodeType        { return EnvelopeQRType }
func (e *EnvelopeQR) GetSignature() []byte  { return e.PrinterSigma }
func (e *EnvelopeQR) SetSignature(s []byte) { e.PrinterSigma = s }
func (e *EnvelopeQR) String() string {
	return fmt.Sprintf("PrinterPK: %v, Challenge: %v, Sigma: %v, FilePath: %v", e.PrinterPK, e.Challenge, e.PrinterSigma, e.Filepath)
}

func (e *EnvelopeQR) MessageToSign() ([]byte, error) {
	s := serialization.NewSerializer()
	s.WriteKyber(e.Challenge)
	return s.Bytes()
}

func (e *EnvelopeQR) Serialize() ([]byte, error) {
	s := serialization.NewSerializer()
	s.WriteKyber(e.PrinterPK, e.Challenge)
	msg, err := s.Bytes()
	if err != nil {
		return nil, err
	}
	return append(msg, e.PrinterSigma...), nil
}

func (e *EnvelopeQR) Deserialize(data []byte) error {
	e.PrinterPK = crypto.Suite.Point()
	e.Challenge = crypto.Suite.Scalar()

	s := serialization.NewDeserializer(data)
	s.ReadKyber(e.PrinterPK, e.Challenge)
	e.PrinterSigma = s.ReadBytes()
	return s.Err()
}

// --- CheckOutQR ---

// CheckOutQR is the checkout ticket used to display to the election official at checkout, signed by the kiosk.
type CheckOutQR struct {
	VoterID    uint64
	EncVoterPk crypto.ElGamalCiphertext
	KioskPK    kyber.Point
	KioskSigma []byte
}

func (c *CheckOutQR) Type() CodeType        { return CheckOutQRType }
func (c *CheckOutQR) GetSignature() []byte  { return c.KioskSigma } // Kiosk signature is primary
func (c *CheckOutQR) SetSignature(s []byte) { c.KioskSigma = s }

func (c *CheckOutQR) MessageToSign() ([]byte, error) {
	return ledger.RegistrationForKioskSig(c.VoterID, c.EncVoterPk.C1, c.EncVoterPk.C2)
}

func (c *CheckOutQR) Serialize() ([]byte, error) {
	s := serialization.NewSerializer()
	s.WriteUint64(c.VoterID)
	s.WriteKyber(c.EncVoterPk.C1, c.EncVoterPk.C2)
	s.WriteKyber(c.KioskPK)
	s.WriteByteSlice(c.KioskSigma)
	return s.Bytes()
}

func (c *CheckOutQR) Deserialize(data []byte) error {
	// Initialize fields
	c.EncVoterPk.C1 = crypto.Suite.Point()
	c.EncVoterPk.C2 = crypto.Suite.Point()
	c.KioskPK = crypto.Suite.Point()

	s := serialization.NewDeserializer(data)
	c.VoterID = s.ReadUint64()
	s.ReadKyber(c.EncVoterPk.C1, c.EncVoterPk.C2)
	s.ReadKyber(c.KioskPK)
	c.KioskSigma = s.ReadByteSlice()
	return s.Err()
}

// --- ResponseQR ---

// ResponseQR contains the secret parts of the voter's credential and the ZKP response.
type ResponseQR struct {
	CredentialSK kyber.Scalar
	ZKPResponse  kyber.Scalar
	KioskPK      kyber.Point
	KioskSigma   []byte
}

func (r *ResponseQR) Type() CodeType        { return ResponseQRType }
func (r *ResponseQR) GetSignature() []byte  { return r.KioskSigma }
func (r *ResponseQR) SetSignature(s []byte) { r.KioskSigma = s }

func (r *ResponseQR) MessageToSign() ([]byte, error) {
	s := serialization.NewSerializer()
	s.WriteKyber(r.CredentialSK, r.ZKPResponse)
	return s.Bytes()
}

func (r *ResponseQR) Serialize() ([]byte, error) {
	s := serialization.NewSerializer()
	s.WriteKyber(r.CredentialSK, r.ZKPResponse, r.KioskPK)
	msg, err := s.Bytes()
	if err != nil {
		return nil, err
	}
	return append(msg, r.KioskSigma...), nil
}

func (r *ResponseQR) Deserialize(data []byte) error {
	// Initialize fields
	r.CredentialSK = crypto.Suite.Scalar()
	r.ZKPResponse = crypto.Suite.Scalar()
	r.KioskPK = crypto.Suite.Point()

	s := serialization.NewDeserializer(data)
	s.ReadKyber(r.CredentialSK, r.ZKPResponse, r.KioskPK)
	r.KioskSigma = s.ReadBytes()
	return s.Err()
}
