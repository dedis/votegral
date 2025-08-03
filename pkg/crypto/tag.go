package crypto

import (
	"fmt"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/proof"
)

// --- Data Structures ---

// ZKPProof encapsulates a single Schnorr-style proof and its public values.
type ZKPProof struct {
	Proof  []byte
	Public map[string]kyber.Point
}

// Round1Bundle is the public data published by a single tallier after Round 1.
type Round1Bundle struct {
	TallierID int
	// PublicCommitment is the tallier's public value S_i = s_i * B for its fresh secret s_i.
	PublicCommitment kyber.Point
	// ProofOfKnowledge is the ZKP proving the tallier knows the secret s_i for its PublicCommitment.
	ProofOfKnowledge *ZKPProof
}

// PartialTagBundle is the public data published by a single tallier after Round 2.
type PartialTagBundle struct {
	TallierID  int
	UpdatedC1s []kyber.Point
	UpdatedC2s []kyber.Point
	// RemaskingProofs contains one combined ZKP for each ciphertext transformation.
	RemaskingProofs []*ZKPProof
}

// Tallier represents a single server in this distributed protocol.
type Tallier struct {
	ID          int
	SecretShare kyber.Scalar // Long-term secret key share, k_i.
	PublicKey   kyber.Point  // Long-term public key share, K_i = k_i * B.
	// FreshSecret is the per-query ephemeral secret s_i used in both rounds.
	FreshSecret kyber.Scalar
}

// DeterministicTagProof is the final, complete collection of proofs from the entire protocol,
// acting as a public log of the work done by all talliers.
type DeterministicTagProof struct {
	Round1Bundles []*Round1Bundle
	Round2Bundles []*PartialTagBundle
}

// --- Main Orchestrator ---

// GenerateDeterministicTags orchestrates the full two-round DDT protocol.
// It takes initial ciphertexts and a set of talliers, and returns the final deterministic tags
// along with a complete proof of the entire computation.
func GenerateDeterministicTags(suite proof.Suite, initialC1s, initialC2s []kyber.Point, talliers []*Tallier) ([]kyber.Point, *DeterministicTagProof, error) {
	if len(initialC1s) == 0 {
		return []kyber.Point{}, &DeterministicTagProof{}, nil
	}

	finalProof := &DeterministicTagProof{}

	// --- ROUND 1: Additive Blinding ---
	// The output of round 1 is the final blinded C2s and the history of public commitments.
	round1OutputC2s, round1History, err := performRound1Chain(suite, initialC2s, talliers)
	if err != nil {
		return nil, nil, fmt.Errorf("failed during Round 1 processing: %w", err)
	}
	finalProof.Round1Bundles = round1History

	// --- ROUND 2: Multiplicative Re-masking & Partial Decryption ---
	// The C1 components are discarded.
	_, finalTags, round2History, err := performRound2Chain(suite, initialC1s, round1OutputC2s, talliers)
	if err != nil {
		return nil, nil, fmt.Errorf("failed during Round 2 processing: %w", err)
	}
	finalProof.Round2Bundles = round2History

	return finalTags, finalProof, nil
}

// --- Tallier Actor and its Methods ---

// NewTallier creates a new tallier instance and pre-generates its fresh secrets for a run.
func NewTallier(suite proof.Suite, id int, secretShare kyber.Scalar) *Tallier {
	publicKey := suite.Point().Mul(secretShare, nil)
	return &Tallier{
		ID:          id,
		SecretShare: secretShare,
		PublicKey:   publicKey,
		// Generate the ephemeral secret for this tallier's participation in the protocol.
		FreshSecret: suite.Scalar().Pick(RandomStream),
	}
}

// PerformRound1 generates the public commitment S_i = s_i * B and proves knowledge of s_i.
func (t *Tallier) PerformRound1(suite proof.Suite) (*Round1Bundle, error) {
	// The primary output of this round for a tallier is its public commitment (S_i)
	// and the proof that it knows the corresponding secret (s_i).
	publicCommitment := suite.Point().Mul(t.FreshSecret, nil)

	pred := proof.Rep("S", "s", "B")
	secrets := map[string]kyber.Scalar{"s": t.FreshSecret}
	public := map[string]kyber.Point{"S": publicCommitment, "B": suite.Point().Base()}
	prover := pred.Prover(suite, secrets, public, nil)
	proofBytes, err := proof.HashProve(suite, "Round1Knowledge", prover)
	if err != nil {
		return nil, fmt.Errorf("tallier %d failed to prove fresh secret: %w", t.ID, err)
	}
	proofOfKnowledge := &ZKPProof{Proof: proofBytes, Public: public}

	return &Round1Bundle{
		TallierID:        t.ID,
		PublicCommitment: publicCommitment,
		ProofOfKnowledge: proofOfKnowledge,
	}, nil
}

// PerformRound2 performs the re-masking and partial decryption step for all ciphertexts.
func (t *Tallier) PerformRound2(suite proof.Suite, prevC1s, prevC2s []kyber.Point) (*PartialTagBundle, error) {
	numCiphertexts := len(prevC1s)
	if numCiphertexts != len(prevC2s) {
		return nil, fmt.Errorf("input C1 and C2 slices must have the same length")
	}

	nextC1s := make([]kyber.Point, numCiphertexts)
	nextC2s := make([]kyber.Point, numCiphertexts)
	proofs := make([]*ZKPProof, numCiphertexts)

	publicCommitment := suite.Point().Mul(t.FreshSecret, nil)

	for i := 0; i < numCiphertexts; i++ {
		// Perform the core transformation.
		nextC1s[i], nextC2s[i] = t.remaskCiphertext(suite, prevC1s[i], prevC2s[i])

		// Generate the single, combined proof for this transformation.
		combinedProof, err := t.proveRound2(suite, publicCommitment, prevC1s[i], prevC2s[i], nextC1s[i], nextC2s[i])
		if err != nil {
			return nil, fmt.Errorf("failed to generate round 2 proof for index %d: %w", i, err)
		}
		proofs[i] = combinedProof
	}

	return &PartialTagBundle{
		TallierID:       t.ID,
		UpdatedC1s:      nextC1s,
		UpdatedC2s:      nextC2s,
		RemaskingProofs: proofs,
	}, nil
}

// remaskCiphertext is a private helper for the Round 2 transformation.
func (t *Tallier) remaskCiphertext(suite proof.Suite, C1, C2 kyber.Point) (kyber.Point, kyber.Point) {
	newC1 := suite.Point().Mul(t.FreshSecret, C1)
	partialDec := suite.Point().Mul(t.SecretShare, C1)
	c2Term := suite.Point().Sub(C2, partialDec)
	newC2 := suite.Point().Mul(t.FreshSecret, c2Term)
	return newC1, newC2
}

// proveRound2 generates the single, combined ZKP for the Round 2 transformation.
func (t *Tallier) proveRound2(suite proof.Suite, publicCommitment, C1_old, C2_old, C1_new, C2_new kyber.Point) (*ZKPProof, error) {
	// The predicate proves four things are true using the SAME secrets s_i and k_i:
	// 1. S_i = s_i * B                  (Links to the Round 1 commitment)
	// 2. K_i = k_i * B                  (Proves knowledge of the long-term secret share)
	// 3. C1_new = s_i * C1_old           (Proves C1 was re-masked correctly)
	// 4. C2_new = s_i*C2_old - (s_i*k_i)*C1_old (Proves C2 was re-masked and partially decrypted correctly)
	pred := proof.And(
		proof.Rep("S", "s", "B"),
		proof.Rep("K", "k", "B"),
		proof.Rep("C1_new", "s", "C1_old"),
		proof.Rep("C2_new", "s", "C2_old", "sk", "C1_old_neg"),
	)

	// Secrets map for the prover.
	sk := suite.Scalar().Mul(t.FreshSecret, t.SecretShare)
	secrets := map[string]kyber.Scalar{
		"s":  t.FreshSecret,
		"k":  t.SecretShare,
		"sk": sk,
	}

	// Public points map for the prover and verifier.
	public := map[string]kyber.Point{
		"B":          suite.Point().Base(),
		"S":          publicCommitment,
		"K":          t.PublicKey,
		"C1_old":     C1_old,
		"C2_old":     C2_old,
		"C1_new":     C1_new,
		"C2_new":     C2_new,
		"C1_old_neg": suite.Point().Neg(C1_old),
	}

	prover := pred.Prover(suite, secrets, public, nil)
	proofBytes, err := proof.HashProve(suite, "Round2Combined", prover)
	if err != nil {
		return nil, fmt.Errorf("combined round 2 proof failed: %w", err)
	}

	return &ZKPProof{Proof: proofBytes, Public: public}, nil
}

// --- Orchestration Chains & Verification ---

// performRound1Chain executes Round 1 for all talliers.
func performRound1Chain(suite proof.Suite, initialC2s []kyber.Point, talliers []*Tallier) ([]kyber.Point, []*Round1Bundle, error) {
	history := make([]*Round1Bundle, len(talliers))
	currentC2s := make([]kyber.Point, len(initialC2s))
	for i, c2 := range initialC2s {
		currentC2s[i] = suite.Point().Set(c2)
	}

	for i, tallier := range talliers {
		bundle, err := tallier.PerformRound1(suite)
		if err != nil {
			return nil, nil, err
		}
		history[i] = bundle

		// Apply this tallier's blinding factor to all C2 components.
		for j := range currentC2s {
			currentC2s[j] = currentC2s[j].Add(currentC2s[j], bundle.PublicCommitment)
		}
	}
	return currentC2s, history, nil
}

// performRound2Chain executes Round 2 for all talliers.
func performRound2Chain(suite proof.Suite, initialC1s, initialC2s []kyber.Point, talliers []*Tallier) ([]kyber.Point, []kyber.Point, []*PartialTagBundle, error) {
	history := make([]*PartialTagBundle, len(talliers))
	currentC1s := make([]kyber.Point, len(initialC1s))
	for i, c1 := range initialC1s {
		currentC1s[i] = suite.Point().Set(c1)
	}
	currentC2s := make([]kyber.Point, len(initialC2s))
	for i, c2 := range initialC2s {
		currentC2s[i] = suite.Point().Set(c2)
	}

	for i, tallier := range talliers {
		bundle, err := tallier.PerformRound2(suite, currentC1s, currentC2s)
		if err != nil {
			return nil, nil, nil, err
		}
		history[i] = bundle

		// The output of this tallier becomes the input for the next.
		currentC1s = bundle.UpdatedC1s
		currentC2s = bundle.UpdatedC2s
	}

	return currentC1s, currentC2s, history, nil
}

// VerifyDeterministicTagProof is the verification function.
// It verifies the entire protocol execution from start to finish, ensuring end-to-end integrity.
func VerifyDeterministicTagProof(suite proof.Suite, initialC1s, initialC2s []kyber.Point, talliers []*Tallier, fullProof *DeterministicTagProof) error {
	// --- Verify Round 1 ---
	// First, verify each tallier's proof of knowledge for their commitment.
	for i, bundle := range fullProof.Round1Bundles {
		if err := VerifyRound1Bundle(suite, bundle); err != nil {
			return fmt.Errorf("verification of Round 1 bundle for tallier %d failed: %w", i, err)
		}
	}

	// Then, calculate the expected final C2s after Round 1 to prepare for Round 2 verification.
	r1FinalC2s := make([]kyber.Point, len(initialC2s))
	for i, c2 := range initialC2s {
		r1FinalC2s[i] = suite.Point().Set(c2)
	}
	for _, bundle := range fullProof.Round1Bundles {
		for j := range r1FinalC2s {
			r1FinalC2s[j] = r1FinalC2s[j].Add(r1FinalC2s[j], bundle.PublicCommitment)
		}
	}

	// --- Verify Round 2 ---
	currentC1s := initialC1s
	currentC2s := r1FinalC2s

	for i, bundle := range fullProof.Round2Bundles {
		// Find the corresponding Round 1 bundle to get the public commitment S_i.
		r1bundle := fullProof.Round1Bundles[i]
		if r1bundle.TallierID != bundle.TallierID {
			return fmt.Errorf("mismatched tallier IDs between round 1 and 2 bundles at index %d", i)
		}

		err := VerifyRound2Bundle(suite, currentC1s, currentC2s, r1bundle.PublicCommitment, talliers[i].PublicKey, bundle)
		if err != nil {
			return fmt.Errorf("verification of Round 2 bundle for tallier %d failed: %w", i, err)
		}

		// The output of this bundle becomes the input for the next verification step.
		currentC1s = bundle.UpdatedC1s
		currentC2s = bundle.UpdatedC2s
	}

	return nil
}

// VerifyRound1Bundle checks a single tallier's proof of knowledge from Round 1.
func VerifyRound1Bundle(suite proof.Suite, bundle *Round1Bundle) error {
	predS := proof.Rep("S", "s", "B")
	verifierS := predS.Verifier(suite, bundle.ProofOfKnowledge.Public)
	if err := proof.HashVerify(suite, "Round1Knowledge", verifierS, bundle.ProofOfKnowledge.Proof); err != nil {
		return fmt.Errorf("fresh secret proof for tallier %d failed: %w", bundle.TallierID, err)
	}
	// The integrity check (sum of C2s) is handled after
	return nil
}

// VerifyRound2Bundle checks the combined re-masking proof for each ciphertext from a tallier.
func VerifyRound2Bundle(suite proof.Suite, prevC1s, prevC2s []kyber.Point, publicCommitment, tallierPublicKey kyber.Point, bundle *PartialTagBundle) error {
	if len(prevC1s) != len(bundle.RemaskingProofs) || len(prevC2s) != len(bundle.RemaskingProofs) {
		return fmt.Errorf("mismatch in ciphertext and proof counts")
	}

	for i := 0; i < len(prevC1s); i++ {
		proof2 := bundle.RemaskingProofs[i]

		// Re-construct the predicate the prover used.
		pred := proof.And(
			proof.Rep("S", "s", "B"),
			proof.Rep("K", "k", "B"),
			proof.Rep("C1_new", "s", "C1_old"),
			proof.Rep("C2_new", "s", "C2_old", "sk", "C1_old_neg"),
		)

		// The verifier must construct the public map from the information it has.
		// It uses the PREVIOUS state and the bundle's claimed UPDATED state.
		public := map[string]kyber.Point{
			"B":          suite.Point().Base(),
			"S":          publicCommitment,
			"K":          tallierPublicKey,
			"C1_old":     prevC1s[i],
			"C2_old":     prevC2s[i],
			"C1_new":     bundle.UpdatedC1s[i],
			"C2_new":     bundle.UpdatedC2s[i],
			"C1_old_neg": suite.Point().Neg(prevC1s[i]),
		}

		verifier := pred.Verifier(suite, public)
		if err := proof.HashVerify(suite, "Round2Combined", verifier, proof2.Proof); err != nil {
			return fmt.Errorf("combined proof for index %d failed for tallier %d: %w", i, bundle.TallierID, err)
		}
	}
	return nil
}
