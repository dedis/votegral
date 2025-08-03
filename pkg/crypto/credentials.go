package crypto

import (
	"crypto/rand"
	"fmt"
	"go.dedis.ch/kyber/v3"
)

// --- Asymmetric Credentials ---

// SignAsymmetricCredential represents an asymmetric key pair used for signing operations.
type SignAsymmetricCredential struct {
	private kyber.Scalar
	public  kyber.Point
}

func NewSignAsymmetricCredential() (*SignAsymmetricCredential, error) {
	private := Suite.Scalar().Pick(RandomStream)
	public := Suite.Point().Mul(private, nil)
	return &SignAsymmetricCredential{private: private, public: public}, nil
}
func (c *SignAsymmetricCredential) PrivateKey() kyber.Scalar { return c.private }
func (c *SignAsymmetricCredential) PublicKey() kyber.Point   { return c.public }
func (c *SignAsymmetricCredential) String() string {
	return fmt.Sprintf("SignAsymmetricCredential{Sk: %s, Pk: %s}", c.private, c.public)
}

// --- Symmetric Credentials ---

// SignSymmetricCredential holds a secret key for symmetric operations like HMAC.
type SignSymmetricCredential struct {
	key []byte
}

func NewSignSymmetricCredential(keySize int) (*SignSymmetricCredential, error) {
	key := make([]byte, keySize)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("failed to generate random key: %w", err)
	}
	return &SignSymmetricCredential{key: key}, nil
}
func (c *SignSymmetricCredential) Key() []byte { return c.key }
