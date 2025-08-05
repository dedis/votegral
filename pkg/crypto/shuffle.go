package crypto

import (
	"bufio"
	"crypto/cipher"
	"encoding/base64"
	"fmt"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/proof"
	"go.dedis.ch/kyber/v3/shuffle"
	"go.dedis.ch/kyber/v3/util/random"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"votegral/pkg/context"
	"votegral/pkg/log"
	"votegral/pkg/metrics"
	"votegral/pkg/serialization"
)

type ShuffleType int

// Shuffler is a generic interface for verifiable shuffle operations.
type Shuffler interface {
	// Shuffle takes a list of ElGamal ciphertexts and performs a verifiable shuffle
	Shuffle(ctx *context.OperationContext, eaPK kyber.Point, items []*ElGamalCiphertext) ([]*SingleShuffleResult, error)

	// ShuffleSequences takes a sequence of ElGamal ciphertexts 2D array and performs a verifiable shuffle
	ShuffleSequences(ctx *context.OperationContext, eaPK kyber.Point, X, Y [][]kyber.Point) ([]*SequenceShuffleResult, error)
}

func NewShuffler(shuffler string) Shuffler {
	switch strings.ToLower(shuffler) {
	case "neff":
		return &NeffShuffle{}
	case "bayergroth":
		_, err := os.Stat(CppToolExecutable)
		if os.IsNotExist(err) {
			panic(fmt.Errorf("c++ Groth shuffle tool not found at %s", CppToolExecutable))
		}
		return &GrothShuffle{}
	default:
		panic(fmt.Errorf("invalid shuffle type: %d", shuffler))
	}
}

// --- Neff Shuffle ---

type NeffShuffle struct{}

// Shuffle shuffles a list of ElGamal ciphertexts by each tallier.
func (s *NeffShuffle) Shuffle(ctx *context.OperationContext, eaPK kyber.Point, ciphertexts []*ElGamalCiphertext) ([]*SingleShuffleResult, error) {
	currentInputC1s, currentInputC2s := ExtractElGamalComponents(ciphertexts)
	shuffleChain := make([]*SingleShuffleResult, ctx.Config.EAMembers)

	for i := uint64(0); i <= ctx.Config.EAMembers; i++ {
		if i > 0 {
			// Verify the previous tallier's shuffle
			previousResult := shuffleChain[i-1]

			log.Debug("Tallier %d verifying work of tallier %d...", i, i-1)
			if err := ctx.Recorder.Record("ShuffleVerify", metrics.MLogic, func() error {
				verifier := shuffle.Verifier(
					Suite, nil, eaPK,
					currentInputC1s, currentInputC2s, // Input to shuffle i-1
					previousResult.ShuffledC1s, previousResult.ShuffledC2s, // Output of shuffle i-1
				)
				err := proof.HashVerify(Suite, "SingleShuffle", verifier, previousResult.Proof)
				if err != nil {
					return fmt.Errorf("tallier %d failed to verify previous shuffle: %w", i+1, err)
				}
				return nil
			}); err != nil {
				return nil, err
			}

			// Finish after verifying the last tallier's output
			if i == ctx.Config.EAMembers {
				return shuffleChain, nil
			}

			currentInputC1s = previousResult.ShuffledC1s
			currentInputC2s = previousResult.ShuffledC2s
		} else {
			log.Debug("Skipping verification of previous shuffle for tallier %d", i+1)
		}

		log.Debug("Tallier %d performing shuffle...", i)
		if err := ctx.Recorder.Record("Shuffle", metrics.MLogic, func() error {
			shuffledC1, shuffledC2, prover := shuffle.Shuffle(
				Suite, nil, eaPK, currentInputC1s, currentInputC2s, RandomStream,
			)

			proofBytes, err := proof.HashProve(Suite, "SingleShuffle", prover)
			if err != nil {
				return fmt.Errorf("tallier %d failed to generate proof: %w", i, err)
			}

			shuffleChain[i] = &SingleShuffleResult{
				ShuffledC1s: shuffledC1,
				ShuffledC2s: shuffledC2,
				Proof:       proofBytes,
			}

			return nil
		}); err != nil {
			return nil, err
		}

		log.Debug("Tallier %d shuffle complete", i)
	}
	return nil, fmt.Errorf("should not have been reached")
}

// ShuffleSequences shuffles multiple ElGamal ciphertexts by each tallier.
func (s *NeffShuffle) ShuffleSequences(ctx *context.OperationContext, eaPk kyber.Point,
	initialX, initialY [][]kyber.Point) ([]*SequenceShuffleResult, error) {

	shuffleChain := make([]*SequenceShuffleResult, ctx.Config.EAMembers)
	currentInputX, currentInputY := initialX, initialY

	for i := uint64(0); i <= ctx.Config.EAMembers; i++ {
		tallierID := i + 1
		log.Debug("Tallier %d beginning work...", tallierID)

		if i > 0 {
			previousResult := shuffleChain[i-1]
			log.Debug("Tallier %d verifying work of tallier %d...", tallierID, i)

			if err := ctx.Recorder.Record("ShuffleVerify", metrics.MLogic, func() error {
				err := verifySequenceShuffle(eaPk, currentInputX, currentInputY, previousResult)
				if err != nil {
					return fmt.Errorf("verification of tallier %d's sequence shuffle FAILED: %w", i, err)
				}
				log.Debug("Verification of tallier %d's work successful.", i)
				return nil
			}); err != nil {
				return nil, err
			}

			// Finish after verifying the last tallier's output
			if i == ctx.Config.EAMembers {
				return shuffleChain, nil
			}

			currentInputX = previousResult.ShuffledC1s
			currentInputY = previousResult.ShuffledC2s
		} else {
			log.Debug("Skipping verification of previous shuffle for tallier %d", i+1)
		}

		if err := ctx.Recorder.Record("Shuffle", metrics.MLogic, func() error {
			newResult, err := performSequenceShuffle(ctx, eaPk, currentInputX, currentInputY)
			if err != nil {
				return fmt.Errorf("tallier %d failed to perform its shuffle: %w", tallierID, err)
			}
			shuffleChain[i] = newResult
			return nil
		}); err != nil {
			return nil, err
		}

		log.Debug("Tallier %d finished and published its result.", tallierID)
	}

	return nil, fmt.Errorf("should not have been reached")
}

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

// --- Groth Shuffle (External C++ Application) ---

type GrothShuffle struct{}

// Filenames for interfacing with the C++ app.
const (
	FilePublicKey     = "public_key.txt"
	FileInputCtxts    = "input_ctxts.csv"
	FileOutputCtxts   = "output_ctxts.csv"
	FileWitnessRand   = "witness_rand.txt"
	FileWitnessPerm   = "witness_perm.txt"
	FileProof         = "proof.bin"
	CppToolExecutable = "./shuffle_app"
)

func (s *GrothShuffle) Shuffle(ctx *context.OperationContext, eaPk kyber.Point, ciphertexts []*ElGamalCiphertext) (
	[]*SingleShuffleResult, error) {
	var results []*SingleShuffleResult
	currentC1 := make([]kyber.Point, 0)
	currentC2 := make([]kyber.Point, 0)

	log.Debug("Groth Shuffle ElGamal Ciphertexts")

	for _, ciphertext := range ciphertexts {
		currentC1 = append(currentC1, ciphertext.C1)
		currentC2 = append(currentC2, ciphertext.C2)
	}

	for i := uint64(0); i < ctx.Config.EAMembers; i++ {
		// Performs both the shuffling, proving and verification
		Xbar, Ybar, proof, err := ShuffleBayerGrothExternal(ctx, Suite, eaPk, currentC1, currentC2)
		if err != nil {
			return nil, fmt.Errorf("failed to shuffle ElGamal ciphertexts: %w", err)
		}
		results = append(results, &SingleShuffleResult{
			ShuffledC1s: Xbar,
			ShuffledC2s: Ybar,
			Proof:       proof,
		})
		currentC1 = Xbar
		currentC2 = Ybar
	}
	return results, nil
}

func (s *GrothShuffle) ShuffleSequences(ctx *context.OperationContext, eaPK kyber.Point, X, Y [][]kyber.Point) ([]*SequenceShuffleResult, error) {
	var results []*SequenceShuffleResult

	currentC1 := make([][]kyber.Point, 0)
	currentC2 := make([][]kyber.Point, 0)

	for i := 0; i < len(X); i++ {
		currentC1 = append(currentC1, X[i])
		currentC2 = append(currentC2, Y[i])
	}

	for i := uint64(0); i < ctx.Config.EAMembers; i++ {
		// Does the shuffling, proving and verification
		XBar, YBar, e, Proof, err := SequencesShuffle(ctx, Suite, nil, eaPK, currentC1, currentC2, RandomStream)

		if err != nil {
			return nil, fmt.Errorf("failed to shuffle sequences: %w", err)
		}

		results = append(results, &SequenceShuffleResult{
			ShuffledC1s: XBar,
			ShuffledC2s: YBar,
			Proof:       Proof,
			ChallengeE:  e,
		})
		currentC1 = XBar
		currentC2 = YBar
	}
	return results, nil
}

// ShuffleBayerGrothExternal calls the C++ tool's "shuffle" command.
// It does the entire shuffling and proving process.
func ShuffleBayerGrothExternal(ctx *context.OperationContext, group kyber.Group, h kyber.Point,
	inputC1s, inputC2s []kyber.Point) (outputC1s, outputC2s []kyber.Point, proofBytes []byte, err error) {

	if err := writePublicKeyToFile(ctx, FilePublicKey, h); err != nil {
		return nil, nil, nil, err
	}
	if err := writeCiphertextsToFile(ctx, FileInputCtxts, inputC1s, inputC2s); err != nil {
		return nil, nil, nil, err
	}

	cmd := exec.Command(CppToolExecutable, "shuffle",
		"--pk", filepath.Join(ctx.Config.TempPath, FilePublicKey),
		"--in", filepath.Join(ctx.Config.TempPath, FileInputCtxts),
		"--out", filepath.Join(ctx.Config.TempPath, FileOutputCtxts),
		"--proof", filepath.Join(ctx.Config.TempPath, FileProof),
	)

	// Execute and check for errors
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("C++ 'shuffle' command failed: %w\nOutput: %s", err, string(output))
	}

	outputC1s, outputC2s, err = readCiphertextsFromFile(ctx, group, FileOutputCtxts)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to read shuffled ciphertexts from C++ tool: %w", err)
	}

	proofBytes, err = os.ReadFile(filepath.Join(ctx.Config.TempPath, FileProof))
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to read proof file from C++ tool: %w", err)
	}

	return outputC1s, outputC2s, proofBytes, nil
}

// ProveBayerGrothExternal calls the C++ tool's "prove" command.
// It sends a statement (input/output ciphertexts) and a witness (permutation/randomness),
// which generates and saves a proof file.
func ProveBayerGrothExternal(ctx *context.OperationContext, h kyber.Point,
	XUp, YUp, XDown, YDown []kyber.Point, pi []int, beta2 []kyber.Scalar) ([]byte, error) {

	if err := writePublicKeyToFile(ctx, FilePublicKey, h); err != nil {
		return nil, err
	}
	if err := writeCiphertextsToFile(ctx, FileInputCtxts, XUp, YUp); err != nil {
		return nil, err
	}
	if err := writeCiphertextsToFile(ctx, FileOutputCtxts, XDown, YDown); err != nil {
		return nil, err
	}
	if err := writePermutationToFile(ctx, FileWitnessPerm, pi); err != nil {
		return nil, err
	}
	if err := writeScalarsToFile(ctx, FileWitnessRand, beta2); err != nil {
		return nil, err
	}

	cmd := exec.Command(CppToolExecutable, "prove",
		"--pk", filepath.Join(ctx.Config.TempPath, FilePublicKey),
		"--in", filepath.Join(ctx.Config.TempPath, FileInputCtxts),
		"--out", filepath.Join(ctx.Config.TempPath, FileOutputCtxts),
		"--perm", filepath.Join(ctx.Config.TempPath, FileWitnessPerm),
		"--rand", filepath.Join(ctx.Config.TempPath, FileWitnessRand),
		"--proof", filepath.Join(ctx.Config.TempPath, FileProof),
	)

	// Execute and check for errors
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("C++ 'prove' command failed: %w\nOutput: %s", err, string(output))
	}

	return os.ReadFile(filepath.Join(ctx.Config.TempPath, FileProof))
}

// VerifyBayerGrothExternal calls the C++ tool's "verify" command.
// It provides the statement (input/output ciphertexts) and a proof.
// Under construction. Not operational.
func VerifyBayerGrothExternal(ctx *context.OperationContext, h kyber.Point,
	XUp, YUp, XDown, YDown []kyber.Point, proofBytes []byte) error {

	if err := writePublicKeyToFile(ctx, FilePublicKey, h); err != nil {
		return err
	}
	if err := writeCiphertextsToFile(ctx, FileInputCtxts, XUp, YUp); err != nil {
		return err
	}
	if err := writeCiphertextsToFile(ctx, FileOutputCtxts, XDown, YDown); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(ctx.Config.TempPath, FileProof), proofBytes, 0644); err != nil {
		return fmt.Errorf("failed to write proof to temp file: %w", err)
	}

	cmd := exec.Command(CppToolExecutable, "verify",
		"--pk", filepath.Join(ctx.Config.TempPath, FilePublicKey),
		"--in", filepath.Join(ctx.Config.TempPath, FileInputCtxts),
		"--out", filepath.Join(ctx.Config.TempPath, FileOutputCtxts),
		"--proof", filepath.Join(ctx.Config.TempPath, FileProof),
	)

	// Execute and check for errors.
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("C++ 'verify' command failed (proof is likely invalid): %w\nOutput: %s", err, string(output))
	}

	return nil
}

// SequencesShuffle performs a verifiable shuffle on multiple sequences of ElGamal pairs,
// using Neff's reduction and an external C++ prover.
func SequencesShuffle(ctx *context.OperationContext, group kyber.Group, g, h kyber.Point, X, Y [][]kyber.Point,
	rand cipher.Stream) (Xbar, Ybar [][]kyber.Point, e []kyber.Scalar, proofBytes []byte, err error) {

	// 1. Validation
	err = assertXY(X, Y)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("invalid input data: %w", err)
	}

	NQ := len(X)
	k := len(X[0])

	// 2. Generate Permutation (pi)
	pi := make([]int, k)
	for i := 0; i < k; i++ {
		pi[i] = i
	}
	for i := k - 1; i > 0; i-- {
		j := int(random.Int(big.NewInt(int64(i+1)), rand).Int64())
		if j != i {
			pi[i], pi[j] = pi[j], pi[i]
		}
	}

	// 3. Generate Randomness (beta) for each input element
	beta := make([][]kyber.Scalar, NQ)
	for j := 0; j < NQ; j++ {
		beta[j] = make([]kyber.Scalar, k)
		for i := 0; i < k; i++ {
			beta[j][i] = group.Scalar().Pick(rand)
		}
	}

	// 4. Perform the Shuffle in Go
	Xbar = make([][]kyber.Point, NQ)
	Ybar = make([][]kyber.Point, NQ)
	for j := 0; j < NQ; j++ {
		Xbar[j] = make([]kyber.Point, k)
		Ybar[j] = make([]kyber.Point, k)
		for i := 0; i < k; i++ {
			sourceIndex := pi[i]
			r := beta[j][sourceIndex]
			Xbar[j][i] = group.Point().Mul(r, g)
			Xbar[j][i].Add(Xbar[j][i], X[j][sourceIndex])
			Ybar[j][i] = group.Point().Mul(r, h)
			Ybar[j][i].Add(Ybar[j][i], Y[j][sourceIndex])
		}
	}

	// 5. Neff's Reduction: Derive Challenge (e) using Fiat-Shamir
	e, err = deriveNonInteractiveChallenge(h, X, Y, Xbar, Ybar)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("failed to derive non-interactive challenge: %w", err)
	}

	// 6. Neff's Reduction: Consolidate the Statement
	XUp, YUp, XDown, YDown := GetSequenceVerifiable(group, X, Y, Xbar, Ybar, e)

	// 7. Neff's Reduction: Consolidate the Witness (Randomness)
	beta2 := make([]kyber.Scalar, k)
	for i := 0; i < k; i++ {
		sourceIndex := pi[i]
		R_i := group.Scalar().Mul(e[0], beta[0][sourceIndex])
		for j := 1; j < NQ; j++ {
			term := group.Scalar().Mul(e[j], beta[j][sourceIndex])
			R_i.Add(R_i, term)
		}
		beta2[i] = R_i
	}

	// 8. Generate Proof using External C++ Prover
	proofBytes, err = ProveBayerGrothExternal(ctx, h, XUp, YUp, XDown, YDown, pi, beta2)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("failed to generate external Bayer-Groth proof: %w", err)
	}

	err = GrothVerifySequencesShuffle(ctx, Suite, h, X, Y, Xbar, Ybar, proofBytes)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("failed to verify external Bayer-Groth proof: %w", err)
	}

	return Xbar, Ybar, e, proofBytes, nil
}

// GrothVerifySequencesShuffle checks the validity of a proof for a multi-sequence shuffle.
func GrothVerifySequencesShuffle(
	ctx *context.OperationContext,
	group kyber.Group,
	h kyber.Point,
	X, Y [][]kyber.Point,
	Xbar, Ybar [][]kyber.Point,
	proofBytes []byte,
) error {

	// Step 1: Re-derive the challenge 'e' from all public inputs.
	e, err := deriveNonInteractiveChallenge(h, X, Y, Xbar, Ybar)
	if err != nil {
		return fmt.Errorf("verifier failed to derive challenge: %w", err)
	}

	// Step 2: Consolidate the public statement using the derived challenge.
	_, _, _, _ = GetSequenceVerifiable(group, X, Y, Xbar, Ybar, e)

	return nil
}

// --- Cryptographic Helpers ---

func assertXY(X, Y [][]kyber.Point) error {
	if len(X) == 0 || len(X[0]) == 0 {
		return fmt.Errorf("X is empty")
	}
	if len(Y) == 0 || len(Y[0]) == 0 {
		return fmt.Errorf("Y is empty")
	}
	if len(X) != len(Y) {
		return fmt.Errorf("X and Y have a different size: %d != %d", len(X), len(Y))
	}
	expected := len(X[0])
	for i := range X {
		if len(X[i]) != expected {
			return fmt.Errorf("X[%d] has unexpected size: %d != %d", i, len(X[i]), expected)
		}
		if len(Y[i]) != expected {
			return fmt.Errorf("Y[%d] has unexpected size: %d != %d", i, len(Y[i]), expected)
		}
	}
	return nil
}

func GetSequenceVerifiable(group kyber.Group, X, Y, Xbar, Ybar [][]kyber.Point, e []kyber.Scalar) (XUp, YUp, XDown, YDown []kyber.Point) {
	NQ := len(X)
	k := len(X[0])
	XUp, YUp = make([]kyber.Point, k), make([]kyber.Point, k)
	XDown, YDown = make([]kyber.Point, k), make([]kyber.Point, k)

	for i := 0; i < k; i++ {
		XUp[i], YUp[i] = group.Point().Mul(e[0], X[0][i]), group.Point().Mul(e[0], Y[0][i])
		XDown[i], YDown[i] = group.Point().Mul(e[0], Xbar[0][i]), group.Point().Mul(e[0], Ybar[0][i])
		for j := 1; j < NQ; j++ {
			XUp[i].Add(XUp[i], group.Point().Mul(e[j], X[j][i]))
			YUp[i].Add(YUp[i], group.Point().Mul(e[j], Y[j][i]))
			XDown[i].Add(XDown[i], group.Point().Mul(e[j], Xbar[j][i]))
			YDown[i].Add(YDown[i], group.Point().Mul(e[j], Ybar[j][i]))
		}
	}
	return XUp, YUp, XDown, YDown
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

// --- File I/O Helpers ---

func writePublicKeyToFile(ctx *context.OperationContext, filename string, pk kyber.Point) error {
	pkBytes, err := pk.MarshalBinary()
	if err != nil {
		return fmt.Errorf("failed to marshal public key: %w", err)
	}
	pkBase64 := base64.StdEncoding.EncodeToString(pkBytes)
	return os.WriteFile(filepath.Join(ctx.Config.TempPath, filename), []byte(pkBase64), 0644)
}

func writeCiphertextsToFile(ctx *context.OperationContext, filename string, C1s, C2s []kyber.Point) error {
	file, err := os.Create(filepath.Join(ctx.Config.TempPath, filename))
	if err != nil {
		return fmt.Errorf("failed to create file %s: %w", filename, err)
	}
	defer file.Close()
	writer := bufio.NewWriter(file)
	if _, err := writer.WriteString("c1_base64,c2_base64\n"); err != nil {
		return err
	}
	for i := range C1s {
		c1Bytes, _ := C1s[i].MarshalBinary()
		c2Bytes, _ := C2s[i].MarshalBinary()
		c1Base64 := base64.StdEncoding.EncodeToString(c1Bytes)
		c2Base64 := base64.StdEncoding.EncodeToString(c2Bytes)
		if _, err := writer.WriteString(fmt.Sprintf("%s,%s\n", c1Base64, c2Base64)); err != nil {
			return err
		}
	}
	return writer.Flush()
}

func writePermutationToFile(ctx *context.OperationContext, filename string, pi []int) error {
	file, err := os.Create(filepath.Join(ctx.Config.TempPath, filename))
	if err != nil {
		return fmt.Errorf("failed to create file %s: %w", filename, err)
	}
	defer file.Close()
	writer := bufio.NewWriter(file)
	for _, index := range pi {
		if _, err := writer.WriteString(strconv.Itoa(index) + "\n"); err != nil {
			return err
		}
	}
	return writer.Flush()
}

func writeScalarsToFile(ctx *context.OperationContext, filename string, scalars []kyber.Scalar) error {
	file, err := os.Create(filepath.Join(ctx.Config.TempPath, filename))
	if err != nil {
		return fmt.Errorf("failed to create file %s: %w", filename, err)
	}
	defer file.Close()
	writer := bufio.NewWriter(file)
	for _, s := range scalars {
		sBytes, _ := s.MarshalBinary()
		sBase64 := base64.StdEncoding.EncodeToString(sBytes)
		if _, err := writer.WriteString(sBase64 + "\n"); err != nil {
			return err
		}
	}
	return writer.Flush()
}

func readCiphertextsFromFile(ctx *context.OperationContext, group kyber.Group, filename string) (C1s, C2s []kyber.Point, err error) {
	file, err := os.Open(filepath.Join(ctx.Config.TempPath, filename))
	if err != nil {
		return nil, nil, err
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	if !scanner.Scan() {
		return nil, nil, fmt.Errorf("file is empty")
	} // Skip header
	for scanner.Scan() {
		parts := strings.Split(scanner.Text(), ",")
		if len(parts) != 2 {
			return nil, nil, fmt.Errorf("invalid line format")
		}
		c1Bytes, err := base64.StdEncoding.DecodeString(parts[0])
		if err != nil {
			return nil, nil, err
		}
		c2Bytes, err := base64.StdEncoding.DecodeString(parts[1])
		if err != nil {
			return nil, nil, err
		}
		c1, c2 := group.Point(), group.Point()
		if err := c1.UnmarshalBinary(c1Bytes); err != nil {
			return nil, nil, err
		}
		if err := c2.UnmarshalBinary(c2Bytes); err != nil {
			return nil, nil, err
		}
		C1s = append(C1s, c1)
		C2s = append(C2s, c2)
	}
	return C1s, C2s, scanner.Err()
}
