package crypto

import (
	"fmt"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/proof"
)

// ZKPCommitment holds the public commitment values for the Sigma protocol.
type ZKPCommitment struct {
	Y1 kyber.Point
	Y2 kyber.Point
}

// Prover implements the prover side of the Sigma protocol for knowledge of `x`.
type Prover struct {
	x kyber.Scalar // The secret value being proven
	y kyber.Scalar // The ephemeral secret (nonce)
}

// NewProver creates a prover for a given secret `x`.
func NewProver(x kyber.Scalar) *Prover {
	return &Prover{x: x}
}

// Commit generates the public commitment `Y_c`.
func (p *Prover) Commit(eaPK kyber.Point) *ZKPCommitment {
	p.y = Suite.Scalar().Pick(RandomStream)
	return &ZKPCommitment{
		Y1: Suite.Point().Mul(p.y, G),
		Y2: Suite.Point().Mul(p.y, eaPK),
	}
}

// Respond computes the response `r` to a given challenge `e`.
func (p *Prover) Respond(challenge kyber.Scalar) kyber.Scalar {
	// r = y - e * x
	return Suite.Scalar().Sub(p.y, Suite.Scalar().Mul(challenge, p.x))
}

// SimulatedProver implements a prover that can generate a valid-looking proof
// without knowing the secret `x`.
type SimulatedProver struct {
	y kyber.Scalar // The ephemeral secret (nonce), same as response in this case.
}

// NewSimulatedProver creates a simulated prover.
func NewSimulatedProver() *SimulatedProver {
	return &SimulatedProver{}
}

// CommitAndRespond generates a commitment and response for a simulated proof.
// It requires the challenge `e` ahead of time.
func (p *SimulatedProver) CommitAndRespond(
	challenge kyber.Scalar,
	c_pc *ElGamalCiphertext,
	X, eaPK kyber.Point,
) (*ZKPCommitment, kyber.Scalar) {
	p.y = Suite.Scalar().Pick(RandomStream) // This is also the response `r`.
	r := p.y

	// Y1 = r*G + e*C1
	// Y3 = r*eaPK + e*X
	commitment := &ZKPCommitment{
		Y1: Suite.Point().Add(Suite.Point().Mul(r, G), Suite.Point().Mul(challenge, c_pc.C1)),
		Y2: Suite.Point().Add(Suite.Point().Mul(r, eaPK), Suite.Point().Mul(challenge, X)),
	}

	return commitment, r
}

// VerifyProof checks the Sigma protocol proof.
func VerifyProof(
	commitment *ZKPCommitment,
	challenge, response kyber.Scalar,
	c_pc *ElGamalCiphertext,
	X, eaPK kyber.Point,
) error {
	// Check Y1 == r*G + e*C1
	y1Check := Suite.Point().Add(Suite.Point().Mul(response, G), Suite.Point().Mul(challenge, c_pc.C1))
	if !commitment.Y1.Equal(y1Check) {
		return fmt.Errorf("ZKP Y1 verification failed")
	}

	// Check Y2 == r*eaPK + e*X
	y2Check := Suite.Point().Add(Suite.Point().Mul(response, eaPK), Suite.Point().Mul(challenge, X))
	if !commitment.Y2.Equal(y2Check) {
		return fmt.Errorf("ZKP Y2 verification failed")
	}

	return nil
}

// ElGamalProof represents a proof associated with the decryption of an ElGamal ciphertext.
type ElGamalProof struct {
	predicate proof.Predicate
	points    map[string]kyber.Point
	Proof     []byte
}

// NewElGamalProof generates a non-interactive zero-knowledge proof for a given predicate, secrets, and choice mapping.
func NewElGamalProof(predicate proof.Predicate, points map[string]kyber.Point, secrets map[string]kyber.Scalar, choice map[proof.Predicate]int) (*ElGamalProof, error) {
	prover := predicate.Prover(Suite, secrets, points, choice)
	Proof, err := proof.HashProve(Suite, "", prover) // Make non-interactive
	if err != nil {
		return nil, fmt.Errorf("ZKP Proof Generation Failed: %w", err)
	}

	return &ElGamalProof{
		predicate: predicate,
		points:    points, // Store the original points for verification.
		Proof:     Proof,
	}, nil
}

// Verify validates the zero-knowledge proof (ZKP) for the associated ElGamal ciphertext decryption.
func (p *ElGamalProof) Verify() error {
	verifier := p.predicate.Verifier(Suite, p.points)
	if err := proof.HashVerify(Suite, "", verifier, p.Proof); err != nil {
		return fmt.Errorf("ZKP Verification Failed: %w", err)
	}
	return nil
}
