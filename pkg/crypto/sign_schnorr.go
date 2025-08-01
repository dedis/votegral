package crypto

import (
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/sign/schnorr"
)

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

// NewSchnorrSignaturePoint generates a Schnorr signature for a given Kyber point using a private and public key pair.
func NewSchnorrSignaturePoint(sk kyber.Scalar, pk kyber.Point, point kyber.Point) (*SchnorrSignature, error) {
	msg, err := point.MarshalBinary()
	if err != nil {
		return nil, err
	}
	sig, err := schnorr.Sign(Suite, sk, msg)
	if err != nil {
	}
	return &SchnorrSignature{Pk: pk, Sig: sig}, nil
}

// Verify validates a Schnorr signature over a message.
func (s *SchnorrSignature) Verify(msg []byte) error {
	return schnorr.Verify(Suite, s.Pk, msg, s.Sig)
}

// VerifyPoint validates a Schnorr signature for a given Kyber point.
func (s *SchnorrSignature) VerifyPoint(point kyber.Point) error {
	msg, err := point.MarshalBinary()
	if err != nil {
		return err
	}
	return schnorr.Verify(Suite, s.Pk, msg, s.Sig)
}
