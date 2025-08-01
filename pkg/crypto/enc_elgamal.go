package crypto

import (
	"fmt"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/proof"
	"io"
)

// ElGamalCiphertext holds the public components of an ElGamal encryption.
type ElGamalCiphertext struct {
	C1 kyber.Point // Ephemeral part 1: x * G
	C2 kyber.Point // Blinded message:  m + X
}

// ElGamalEncryptPoint encrypts a kyber.Point using the specified public key pk.
func ElGamalEncryptPoint(Pk, M kyber.Point) (ciphertext *ElGamalCiphertext, X kyber.Point, x kyber.Scalar) {
	// Create a secret ephemeral scalar x
	x = Suite.Scalar().Pick(RandomStream)

	// Derive the shared secret using the public key pk.
	X = Suite.Point().Mul(x, Pk)

	// Blind the message
	c1 := Suite.Point().Mul(x, G)
	c2 := Suite.Point().Add(M, X)

	return &ElGamalCiphertext{C1: c1, C2: c2}, X, x
}

// Decrypt decrypts an ElGamal ciphertext using the provided private key.
func (ct *ElGamalCiphertext) Decrypt(sk kyber.Scalar) (kyber.Point, kyber.Point, error) {
	if ct == nil || ct.C1 == nil || ct.C2 == nil || sk == nil {
		return nil, nil, fmt.Errorf("crypto: decrypting uninitialized ElGamal ciphertext or private key")
	}

	X := Suite.Point().Mul(sk, ct.C1) // regenerate shared secret
	M := Suite.Point().Sub(ct.C2, X)  // use to un-blind the message

	return M, X, nil
}

// DecryptWithProof decrypts an ElGamal ciphertext and generates a zero-knowledge proof of a correct decryption process.
func (ct *ElGamalCiphertext) DecryptWithProof(Pk kyber.Point, sk kyber.Scalar) (kyber.Point, *ElGamalProof, error) {
	// Decrypt the ciphertext
	M, X, err := ct.Decrypt(sk)
	if err != nil {
		return nil, nil, fmt.Errorf("decryption failed: %w", err)
	}

	// ZKP proof
	predicate := proof.And(proof.Rep("X", "sk", "C1"), proof.Rep("Pk", "sk", "G"))
	points := map[string]kyber.Point{"X": X, "C1": ct.C1, "Pk": Pk, "G": G}
	secrets := map[string]kyber.Scalar{"sk": sk}
	Proof, err := NewElGamalProof(predicate, points, secrets, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("ZKP Proof Generation Failed: %w", err)
	}

	return M, Proof, nil
}

// MultiKeyDecryptWithProof decrypts an ElGamal ciphertext using multiple DKG shares and generates zero-knowledge proofs.
// It combines partial decryptions from each share to compute the final decrypted value.
func (ct *ElGamalCiphertext) MultiKeyDecryptWithProof(shares []*DKGShare) (kyber.Point, []*ElGamalProof, error) {
	decProofs := make([]*ElGamalProof, len(shares))

	partialDec := &ElGamalCiphertext{
		C1: ct.C1,
		C2: ct.C2,
	}
	var err error
	for i := 0; i < len(shares); i++ {
		partialDec.C2, decProofs[i], err = partialDec.DecryptWithProof(shares[i].Pk, shares[i].Sk)
		if err != nil {
			return nil, nil, fmt.Errorf("decryption failed at privkey %d: %w", i, err)
		}
	}

	var finalDec = partialDec.C2

	return finalDec, decProofs, nil
}

// Equal compares two ElGamalCiphertext instances and returns an error if they do not match in any of their components.
func (ct *ElGamalCiphertext) Equal(ct2 *ElGamalCiphertext) bool {
	return ct.C1.Equal(ct2.C1) && ct.C2.Equal(ct2.C2)
}

// WriteTo serializes the ciphertext to a writer.
func (ct *ElGamalCiphertext) WriteTo(w io.Writer) (int64, error) {
	if ct.C1 == nil || ct.C2 == nil {
		return 0, fmt.Errorf("crypto: writing uninitialized ElGamal ciphertext")
	}

	n1, err := ct.C1.MarshalTo(w)
	if err != nil {
		return int64(n1), err
	}
	n2, err := ct.C2.MarshalTo(w)
	return int64(n1) + int64(n2), err
}

// String returns a formatted string representation of the ElGamalCiphertext, displaying its components C1 and C2.
func (ct *ElGamalCiphertext) String() string {
	return fmt.Sprintf("C1: %s, C2: %s", ct.C1, ct.C2)
}

// ExtractElGamalComponents extracts C1 and C2 components from a slice of ElGamalCiphertext into separate slices C1, C2.
func ExtractElGamalComponents(ciphertexts []*ElGamalCiphertext) ([]kyber.Point, []kyber.Point) {
	var C1s []kyber.Point
	var C2s []kyber.Point
	for _, ciphertext := range ciphertexts {
		C1s = append(C1s, ciphertext.C1)
		C2s = append(C2s, ciphertext.C2)
	}
	return C1s, C2s
}

// ElGamalComponentsToCiphertext constructs ElGamal ciphertexts from slices of C1 and C2 components and returns them.
func ElGamalComponentsToCiphertext(C1s []kyber.Point, C2s []kyber.Point) ([]*ElGamalCiphertext, error) {
	if len(C1s) != len(C2s) {
		return nil, fmt.Errorf("len(C1s) != len(C2s)")
	}

	ciphertexts := make([]*ElGamalCiphertext, len(C1s))
	for i := 0; i < len(C1s); i++ {
		ciphertexts[i] = &ElGamalCiphertext{
			C1: C1s[i],
			C2: C2s[i],
		}
	}
	return ciphertexts, nil
}
