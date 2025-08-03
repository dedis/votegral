package crypto

import (
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/sign/schnorr"
)

// SchnorrSignature represents a cryptographic signature using the Schnorr signature scheme.
type SchnorrSignature struct {
	Pk  kyber.Point
	Sig []byte
}

// NewSchnorrSignature creates a new Schnorr signature for the specified message using the given secret and public keys.
func NewSchnorrSignature(sk kyber.Scalar, pk kyber.Point, msg []byte) (*SchnorrSignature, error) {
	sig, err := schnorr.Sign(Suite, sk, msg)
	if err != nil {
		return nil, err
	}
	return &SchnorrSignature{Pk: pk, Sig: sig}, nil
}

// Verify validates a Schnorr signature over a message.
func (s *SchnorrSignature) Verify(msg []byte) error {
	return schnorr.Verify(Suite, s.Pk, msg, s.Sig)
}
