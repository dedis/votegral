package crypto

import (
	"fmt"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/proof"
	"go.dedis.ch/kyber/v3/shuffle"
	"votegral/pkg/context"
	"votegral/pkg/log"
	"votegral/pkg/serialization"
)

// SingleShuffleResult encapsulates the output of shuffling a single ElGamal ciphertext list
type SingleShuffleResult struct {
	ShuffledC1s []kyber.Point
	ShuffledC2s []kyber.Point
	Proof       []byte
}

// SequenceShuffleResult encapsulates the output of multiple shuffled ElGamal ciphertexts.
type SequenceShuffleResult struct {
	ShuffledC1s [][]kyber.Point
	ShuffledC2s [][]kyber.Point
	Proof       []byte
	ChallengeE  []kyber.Scalar
}

// ShuffleElGamalCiphertexts shuffles a list of ElGamal ciphertexts by each tallier.
func ShuffleElGamalCiphertexts(ctx *context.OperationContext, eaPK kyber.Point, ciphertexts []*ElGamalCiphertext) ([]*SingleShuffleResult, error) {
	currentInputC1s, currentInputC2s := ExtractElGamalComponents(ciphertexts)
	shuffleChain := make([]*SingleShuffleResult, ctx.Config.Talliers)

	for i := uint64(0); i < ctx.Config.Talliers; i++ {
		if i > 0 {
			// Verify the previous tallier's shuffle
			previousResult := shuffleChain[i-1]

			log.Debug("Tallier %d verifying work of tallier %d...", i, i-1)
			verifier := shuffle.Verifier(
				Suite, nil, eaPK,
				currentInputC1s, currentInputC2s, // Input to shuffle i-1
				previousResult.ShuffledC1s, previousResult.ShuffledC2s, // Output of shuffle i-1
			)
			err := proof.HashVerify(Suite, "SingleShuffle", verifier, previousResult.Proof)
			if err != nil {
				return nil, fmt.Errorf("tallier %d failed to verify previous shuffle: %w", i+1, err)
			}

			currentInputC1s = previousResult.ShuffledC1s
			currentInputC2s = previousResult.ShuffledC2s
		} else {
			log.Debug("Skipping verification of previous shuffle for tallier %d", i+1)
		}

		log.Debug("Tallier %d performing shuffle...", i)
		shuffledC1, shuffledC2, prover := shuffle.Shuffle(
			Suite, nil, eaPK, currentInputC1s, currentInputC2s, RandomStream,
		)

		proofBytes, err := proof.HashProve(Suite, "SingleShuffle", prover)
		if err != nil {
			return nil, fmt.Errorf("tallier %d failed to generate proof: %w", i, err)
		}

		shuffleChain[i] = &SingleShuffleResult{
			ShuffledC1s: shuffledC1,
			ShuffledC2s: shuffledC2,
			Proof:       proofBytes,
		}
		log.Debug("Tallier %d shuffle complete", i)
	}
	return shuffleChain, nil
}

// ShuffleElGamalSequences shuffles multiple ElGamal ciphertexts by each tallier.
func ShuffleElGamalSequences(
	ctx *context.OperationContext,
	eaPk kyber.Point,
	initialX, initialY [][]kyber.Point,
) ([]*SequenceShuffleResult, error) {

	shuffleChain := make([]*SequenceShuffleResult, ctx.Config.Talliers)
	currentInputX, currentInputY := initialX, initialY

	for i := uint64(0); i < ctx.Config.Talliers; i++ {
		tallierID := i + 1
		log.Debug("Tallier %d beginning work...", tallierID)

		if i > 0 {
			previousResult := shuffleChain[i-1]
			log.Debug("Tallier %d verifying work of tallier %d...", tallierID, i)

			err := verifySequenceShuffle(eaPk, currentInputX, currentInputY, previousResult)
			if err != nil {
				return nil, fmt.Errorf("verification of tallier %d's sequence shuffle FAILED: %w", i, err)
			}
			log.Debug("Verification of tallier %d's work successful.", i)

			currentInputX = previousResult.ShuffledC1s
			currentInputY = previousResult.ShuffledC2s
		} else {
			log.Debug("Skipping verification of previous shuffle for tallier %d", i+1)
		}

		newResult, err := performSequenceShuffle(ctx, eaPk, currentInputX, currentInputY)
		if err != nil {
			return nil, fmt.Errorf("tallier %d failed to perform its shuffle: %w", tallierID, err)
		}

		shuffleChain[i] = newResult
		log.Debug("Tallier %d finished and published its result.", tallierID)
	}

	return shuffleChain, nil
}

// performSequenceShuffle encapsulates the logic for a single tallier's sequence shuffle and proof generation.
func performSequenceShuffle(ctx *context.OperationContext, eaPublicKey kyber.Point, X, Y [][]kyber.Point) (*SequenceShuffleResult, error) {
	XBar, YBar, getProver := shuffle.SequencesShuffle(Suite, nil, eaPublicKey, X, Y, RandomStream)
	e, err := deriveNonInteractiveChallenge(eaPublicKey, X, Y, XBar, YBar)
	if err != nil {
		return nil, fmt.Errorf("failed to derive challenge 'e': %w", err)
	}
	prover, err := getProver(e)
	if err != nil {
		return nil, fmt.Errorf("failed to get prover: %w", err)
	}
	proofBytes, err := proof.HashProve(Suite, "Votegral-SequencesShuffle-v1", prover)
	if err != nil {
		return nil, fmt.Errorf("failed to generate shuffle proof: %w", err)
	}
	return &SequenceShuffleResult{ShuffledC1s: XBar, ShuffledC2s: YBar, Proof: proofBytes, ChallengeE: e}, nil
}

// verifySequenceShuffle encapsulates the logic for verifying a shuffle proof from a previous tallier.
func verifySequenceShuffle(eaPublicKey kyber.Point, originalX, originalY [][]kyber.Point, result *SequenceShuffleResult) error {
	XUp, YUp, XDown, YDown := shuffle.GetSequenceVerifiable(Suite, originalX, originalY, result.ShuffledC1s, result.ShuffledC2s, result.ChallengeE)
	verifier := shuffle.Verifier(Suite, nil, eaPublicKey, XUp, YUp, XDown, YDown)
	return proof.HashVerify(Suite, "Votegral-SequencesShuffle-v1", verifier, result.Proof)
}

// deriveNonInteractiveChallenge Fiat-Shamir Heuristic to create the challenge vector `e` for sequences of ElGamal ciphertexts
func deriveNonInteractiveChallenge(eaPublicKey kyber.Point, X, Y, XBar, YBar [][]kyber.Point) ([]kyber.Scalar, error) {
	NQ := len(X)
	k := len(X[0])
	e := make([]kyber.Scalar, NQ)

	s := serialization.NewSerializer()
	s.WriteKyber(eaPublicKey)
	for j := 0; j < NQ; j++ {
		for i := 0; i < k; i++ {
			s.WriteKyber(X[j][i], Y[j][i])
		}
	}
	for j := 0; j < NQ; j++ {
		for i := 0; i < k; i++ {
			s.WriteKyber(XBar[j][i], YBar[j][i])
		}
	}

	payloadBytes, err := s.Bytes()
	if err != nil {
		return nil, fmt.Errorf("failed to serialize data for challenge hash: %w", err)
	}
	challengeHasher := Suite.XOF([]byte("votegral-shuffle-challenge-derivation"))
	if _, err = challengeHasher.Write(payloadBytes); err != nil {
		return nil, fmt.Errorf("failed to write payload to hasher: %w", err)
	}
	for j := 0; j < NQ; j++ {
		e[j] = Suite.Scalar().Pick(challengeHasher)
	}

	return e, nil
}
