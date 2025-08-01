package crypto

import (
	"fmt"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/proof"
	"golang.org/x/xerrors"
	"votegral/pkg/context"
	"votegral/pkg/log"
)

// --- Data Structures ---

// ZKPProof encapsulates a single Schnorr-style proof and its public values.
type ZKPProof struct {
	Proof  []byte
	Public map[string]kyber.Point
}

// Round1Bundle is the public data published by a single tallier after Round 1 (Additive Blinding).
type Round1Bundle struct {
	TallierID        int
	UpdatedC2s       []kyber.Point // C1s are unchanged in this round.
	FreshSecretProof *ZKPProof
}

// PartialTagBundle is the public data published by a single tallier after Round 2 (Re-masking).
type PartialTagBundle struct {
	TallierID        int
	C1s              []kyber.Point
	C2s              []kyber.Point
	RemaskingProofsA []*ZKPProof
	RemaskingProofsB []*ZKPProof
}

// Tallier represents a single server in the distributed protocol.
type Tallier struct {
	ID                int
	SecretShare       kyber.Scalar // Long-term secret key share, x_i
	FreshSecretRound1 kyber.Scalar // One-time secret for Round 1
	FreshSecretRound2 kyber.Scalar // One-time secret for Round 2
}

// DeterministicTagProof is the final, complete collection of proofs from the entire protocol.
// It acts as a public log of the work done by all talliers across both rounds.
type DeterministicTagProof struct {
	Round1Bundles []*Round1Bundle
	Round2Bundles []*PartialTagBundle
}

// --- Main Orchestrator ---

// GenerateDeterministicTags is the top-level orchestrator for the full two-round DDT protocol.
func GenerateDeterministicTags(ctx *context.OperationContext, suite proof.Suite, initialC1s, initialC2s []kyber.Point, talliers []*Tallier) ([]kyber.Point, *DeterministicTagProof, error) {
	if len(initialC1s) == 0 {
		log.Error("GenerateDeterministicTags called with empty ciphertext list.")
		return []kyber.Point{}, &DeterministicTagProof{}, nil
	}

	finalProof := &DeterministicTagProof{}

	// --- ROUND 1: Additive Blinding ---
	log.Debug("DDT Protocol: Beginning Round 1 (Additive Blinding)...")
	round1OutputC1s, round1OutputC2s, round1History, err := performRound1Chain(ctx, suite, initialC1s, initialC2s, talliers)
	if err != nil {
		return nil, nil, fmt.Errorf("failed during Round 1 processing: %w", err)
	}
	finalProof.Round1Bundles = round1History

	// --- ROUND 2: Multiplicative Re-masking & Partial Decryption ---
	log.Debug("DDT Protocol: Beginning Round 2 (Re-masking & Partial Decryption)...")
	_, finalTags, round2History, err := performRound2Chain(ctx, suite, round1OutputC1s, round1OutputC2s, talliers)
	if err != nil {
		return nil, nil, fmt.Errorf("failed during Round 2 processing: %w", err)
	}
	finalProof.Round2Bundles = round2History

	return finalTags, finalProof, nil
}

// --- Tallier Actor and its Methods ---

// NewTallier creates a new tallier instance and pre-generates its fresh secrets for a run.
func NewTallier(suite proof.Suite, id int, secret kyber.Scalar) *Tallier {
	return &Tallier{
		ID:                id,
		SecretShare:       secret,
		FreshSecretRound1: suite.Scalar().Pick(RandomStream),
		FreshSecretRound2: suite.Scalar().Pick(RandomStream),
	}
}

// PerformRound1 adds this tallier's blinding factor (s_i * B) to each C2 component.
func (t *Tallier) PerformRound1(suite proof.Suite, prevC2s []kyber.Point) (*Round1Bundle, error) {
	// Prove knowledge of the fresh secret used in this round.
	freshSecretProof, err := t.proveFreshSecret(suite, t.FreshSecretRound1, "FreshSecretProofR1")
	if err != nil {
		return nil, err
	}

	// Add the blinding factor to each C2.
	blindingFactor := suite.Point().Mul(t.FreshSecretRound1, nil)
	updatedC2s := make([]kyber.Point, len(prevC2s))
	for i, c2 := range prevC2s {
		updatedC2s[i] = suite.Point().Add(c2, blindingFactor)
	}

	return &Round1Bundle{
		TallierID:        t.ID,
		UpdatedC2s:       updatedC2s,
		FreshSecretProof: freshSecretProof,
	}, nil
}

// PerformRound2 performs the re-masking and partial decryption step.
func (t *Tallier) PerformRound2(suite proof.Suite, prevC1s, prevC2s []kyber.Point) (*PartialTagBundle, error) {
	numCiphertexts := len(prevC1s)
	if numCiphertexts != len(prevC2s) {
		return nil, xerrors.New("input C1 and C2 slices must have the same length")
	}

	nextC1s := make([]kyber.Point, numCiphertexts)
	nextC2s := make([]kyber.Point, numCiphertexts)
	proofsA := make([]*ZKPProof, numCiphertexts)
	proofsB := make([]*ZKPProof, numCiphertexts)

	for i := 0; i < numCiphertexts; i++ {
		nextC1s[i], nextC2s[i] = t.remaskCiphertext(suite, t.FreshSecretRound2, prevC1s[i], prevC2s[i])
		proofA, proofB, err := t.proveRemasking(suite, t.FreshSecretRound2, prevC1s[i], prevC2s[i], nextC1s[i], nextC2s[i])
		if err != nil {
			return nil, xerrors.Errorf("failed to generate proofs for index %d: %w", i, err)
		}
		proofsA[i] = proofA
		proofsB[i] = proofB
	}

	return &PartialTagBundle{
		TallierID:        t.ID,
		C1s:              nextC1s,
		C2s:              nextC2s,
		RemaskingProofsA: proofsA,
		RemaskingProofsB: proofsB,
	}, nil
}

// proveFreshSecret is a private helper for generating a proof of knowledge for a scalar.
func (t *Tallier) proveFreshSecret(suite proof.Suite, freshSecret kyber.Scalar, context string) (*ZKPProof, error) {
	pred := proof.Rep("S", "s", "B")
	secrets := map[string]kyber.Scalar{"s": freshSecret}
	S_i := suite.Point().Mul(freshSecret, nil)
	public := map[string]kyber.Point{"S": S_i, "B": suite.Point().Base()}
	prover := pred.Prover(suite, secrets, public, nil)
	proofBytes, err := proof.HashProve(suite, context, prover)
	if err != nil {
		return nil, xerrors.Errorf("tallier %d failed to prove fresh secret: %w", t.ID, err)
	}
	return &ZKPProof{Proof: proofBytes, Public: public}, nil
}

// remaskCiphertext is a private helper for the Round 2 transformation.
func (t *Tallier) remaskCiphertext(suite proof.Suite, freshSecret kyber.Scalar, C1, C2 kyber.Point) (kyber.Point, kyber.Point) {
	newC1 := suite.Point().Mul(freshSecret, C1)
	partialDec := suite.Point().Mul(t.SecretShare, C1)
	c2Term := suite.Point().Sub(C2, partialDec)
	newC2 := suite.Point().Mul(freshSecret, c2Term)
	return newC1, newC2
}

// proveRemasking is a private helper to generate the ZKPs for the Round 2 transformation.
func (t *Tallier) proveRemasking(suite proof.Suite, freshSecret kyber.Scalar, C1, C2, newC1, newC2 kyber.Point) (*ZKPProof, *ZKPProof, error) {
	// Proof A: C1' = s_i * C1
	predA := proof.Rep("C1_new", "s", "C1_old")
	secretsA := map[string]kyber.Scalar{"s": freshSecret}
	publicA := map[string]kyber.Point{"C1_new": newC1, "C1_old": C1}
	proverA := predA.Prover(suite, secretsA, publicA, nil)
	proofABytes, err := proof.HashProve(suite, "RemaskingProofA", proverA)
	if err != nil {
		return nil, nil, xerrors.Errorf("proof A failed: %w", err)
	}
	proofA := &ZKPProof{Proof: proofABytes, Public: publicA}

	// Proof B: C2' = s_i*C2 - (s_i*x_i)*C1
	predB := proof.Rep("C2_new", "s", "C2_old", "sx", "C1_old_neg")
	sx := suite.Scalar().Mul(freshSecret, t.SecretShare)
	secretsB := map[string]kyber.Scalar{"s": freshSecret, "sx": sx}
	publicB := map[string]kyber.Point{
		"C2_new":     newC2,
		"C2_old":     C2,
		"C1_old_neg": suite.Point().Neg(C1),
	}
	proverB := predB.Prover(suite, secretsB, publicB, nil)
	proofBBytes, err := proof.HashProve(suite, "RemaskingProofB", proverB)
	if err != nil {
		return nil, nil, xerrors.Errorf("proof B failed: %w", err)
	}
	proofB := &ZKPProof{Proof: proofBBytes, Public: publicB}

	return proofA, proofB, nil
}

// --- Orchestration Chains & Verification ---

// performRound1Chain now returns the full history of bundles for the final proof object.
func performRound1Chain(ctx *context.OperationContext, suite proof.Suite, initialC1s, initialC2s []kyber.Point, talliers []*Tallier) ([]kyber.Point, []kyber.Point, []*Round1Bundle, error) {
	history := make([]*Round1Bundle, len(talliers))
	currentC2s := initialC2s

	for i, tallier := range talliers {
		bundle, err := tallier.PerformRound1(suite, currentC2s)
		if err != nil {
			return nil, nil, nil, err
		}

		if err = VerifyRound1Bundle(suite, currentC2s, bundle); err != nil {
			return nil, nil, nil, err
		}

		history[i] = bundle
		currentC2s = bundle.UpdatedC2s
	}
	// Return the final state of ciphertexts AND the full history.
	return initialC1s, currentC2s, history, nil
}

// performRound2Chain now returns the full history of bundles for the final proof object.
func performRound2Chain(ctx *context.OperationContext, suite proof.Suite, initialC1s, initialC2s []kyber.Point, talliers []*Tallier) ([]kyber.Point, []kyber.Point, []*PartialTagBundle, error) {
	history := make([]*PartialTagBundle, len(talliers))
	currentC1s, currentC2s := initialC1s, initialC2s

	for i, tallier := range talliers {
		bundle, err := tallier.PerformRound2(suite, currentC1s, currentC2s)
		if err != nil {
			return nil, nil, nil, err
		}

		err = VerifyRound2Bundle(suite, currentC1s, currentC2s, bundle)
		if err != nil {
			return nil, nil, nil, err
		}

		history[i] = bundle
		currentC1s = bundle.C1s
		currentC2s = bundle.C2s
	}

	return currentC1s, currentC2s, history, nil
}

// VerifyRound1Bundle checks the proofs from a tallier's Round 1 contribution.
func VerifyRound1Bundle(suite proof.Suite, prevC2s []kyber.Point, bundle *Round1Bundle) error {
	predS := proof.Rep("S", "s", "B")
	verifierS := predS.Verifier(suite, bundle.FreshSecretProof.Public)
	if err := proof.HashVerify(suite, "FreshSecretProofR1", verifierS, bundle.FreshSecretProof.Proof); err != nil {
		return xerrors.Errorf("fresh secret proof for tallier %d failed: %w", bundle.TallierID, err)
	}

	expectedBlindingFactor := bundle.FreshSecretProof.Public["S"]
	if len(prevC2s) != len(bundle.UpdatedC2s) {
		return xerrors.New("mismatch in C2 counts")
	}
	for i, prevC2 := range prevC2s {
		expectedC2 := suite.Point().Add(prevC2, expectedBlindingFactor)
		if !expectedC2.Equal(bundle.UpdatedC2s[i]) {
			return xerrors.Errorf("C2 at index %d was not updated correctly in Round 1 for tallier %d", i, bundle.TallierID)
		}
	}
	log.Debug("Verification of Tallier %d's Round 1 work successful.", bundle.TallierID)
	return nil
}

// VerifyRound2Bundle checks the proofs from a tallier's Round 2 contribution.
func VerifyRound2Bundle(suite proof.Suite, prevC1s, prevC2s []kyber.Point, bundle *PartialTagBundle) error {
	if len(prevC1s) != len(bundle.RemaskingProofsA) || len(prevC2s) != len(bundle.RemaskingProofsB) {
		return xerrors.New("mismatch in ciphertext and proof counts")
	}

	for i := 0; i < len(prevC1s); i++ {
		// Verify Proof A
		proofA := bundle.RemaskingProofsA[i]
		predA := proof.Rep("C1_new", "s", "C1_old")
		verifierA := predA.Verifier(suite, proofA.Public)
		if err := proof.HashVerify(suite, "RemaskingProofA", verifierA, proofA.Proof); err != nil {
			return xerrors.Errorf("re-masking proof A for index %d failed for tallier %d: %w", i, bundle.TallierID, err)
		}

		// Verify Proof B
		proofB := bundle.RemaskingProofsB[i]
		predB := proof.Rep("C2_new", "s", "C2_old", "sx", "C1_old_neg")
		verifierB := predB.Verifier(suite, proofB.Public)
		if err := proof.HashVerify(suite, "RemaskingProofB", verifierB, proofB.Proof); err != nil {
			return xerrors.Errorf("re-masking proof B for index %d failed for tallier %d: %w", i, bundle.TallierID, err)
		}
	}
	log.Debug("Verification of Tallier %d's Round 2 work successful.", bundle.TallierID)
	return nil
}
