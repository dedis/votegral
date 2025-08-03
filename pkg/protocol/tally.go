package protocol

import (
	"fmt"
	"go.dedis.ch/kyber/v3"
	"votegral/pkg/actors"
	"votegral/pkg/config"
	"votegral/pkg/context"
	"votegral/pkg/crypto"
	"votegral/pkg/ledger"
	"votegral/pkg/log"
	"votegral/pkg/metrics"
)

// TallyInput is the data required from the main simulation to run the tally.
type TallyInput struct {
	config     *config.Config
	EA         *actors.ElectionAuthority
	RegRecords []*ledger.RegistrationEntry
	Votes      []*ledger.VotingEntry
	Creds      []*ledger.CredentialEntry
}

func NewTallyInput(config *config.Config, ea *actors.ElectionAuthority, l *ledger.Ledger) *TallyInput {
	tally := &TallyInput{
		config:     config,
		EA:         ea,
		RegRecords: l.GetRegistrationRecords(),
		Votes:      l.GetVotingRecords(),
		Creds:      l.GetCredentialRecords(),
	}

	return tally
}

type Tally struct {
	// Shuffled entries on Registration Ledger
	RegRecordsShuffled []*crypto.SingleShuffleResult

	// Shuffled entries on Voting Ledger
	VoteRecordsShuffled []*crypto.SequenceShuffleResult

	// Deterministic Tags on shuffled entries
	RegCredTags       []kyber.Point
	RegCredTagsProof  *crypto.DeterministicTagProof
	VoteCredTags      []kyber.Point
	VoteCredTagsProof *crypto.DeterministicTagProof

	// Real Shuffled Votes
	RealEncVotes []*crypto.ElGamalCiphertext
	RealDecVotes []uint

	// Tally Results
	Results map[uint]uint
	Winner  string
}

func NewTally() *Tally {
	return &Tally{}
}

// RunTally executes the entire backend tallying process.
func RunTally(ctx *context.OperationContext, input *TallyInput) error {
	var err error
	tally := NewTally()
	lastTallier := input.config.EAMembers - 1
	var talliers []*crypto.Tallier
	for i, share := range input.EA.KeyShares() {
		talliers = append(talliers, crypto.NewTallier(crypto.Suite, i+1, share.Sk))
	}

	// Input Validation
	if len(input.RegRecords) < 2 || len(input.Votes) < 2 {
		return fmt.Errorf("not enough registration or voting records to tally")
	}

	// Since this is parallelizable, we do this once, assuming that each node does it simultaneously.
	log.Info("Pre-Tally: Verifying ledger contents...")
	if err = ctx.Recorder.Record("Tally_0_VerifyLedgerContents", metrics.MLogic, func() error {
		return verifyLedgerContents(ctx, input)
	}); err != nil {
		return err
	}

	log.Info("-- Tally Stage 1: Shuffling %d registration records...", len(input.RegRecords))
	if err = ctx.Recorder.Record("Tally_1_ShuffleRegistrationRecords", metrics.MLogic, func() error {
		regCreds := extractRegCredentials(input.RegRecords)
		tally.RegRecordsShuffled, err = crypto.ShuffleElGamalCiphertexts(ctx, input.EA.PublicKey(), regCreds)
		return err
	}); err != nil {
		return err
	}

	log.Info("-- Tally Stage 2: Generate a deterministic tag on each of the %d shuffled registration record...",
		len(tally.RegRecordsShuffled[lastTallier].ShuffledC1s))
	if err = ctx.Recorder.Record("Tally_2_DeterministicTagsOnShuffledRegistrationRecords", metrics.MLogic, func() error {
		if err = ctx.Recorder.Record("GenerateDeterministicTags", metrics.MLogic, func() error {
			tally.RegCredTags, tally.RegCredTagsProof, err = crypto.GenerateDeterministicTags(
				crypto.Suite,
				tally.RegRecordsShuffled[lastTallier].ShuffledC1s,
				tally.RegRecordsShuffled[lastTallier].ShuffledC2s,
				talliers,
			)
			return nil
		}); err != nil {
			return fmt.Errorf("failed to generate deterministic tags: %w", err)
		}
		if err = ctx.Recorder.Record("VerifyDeterministicTags", metrics.MLogic, func() error {
			return crypto.VerifyDeterministicTagProof(
				crypto.Suite,
				tally.RegRecordsShuffled[lastTallier].ShuffledC1s,
				tally.RegRecordsShuffled[lastTallier].ShuffledC2s,
				talliers,
				tally.RegCredTagsProof,
			)
		}); err != nil {
			return fmt.Errorf("failed to verify deterministic tags: %w", err)
		}
		return err
	}); err != nil {
		return err
	}

	log.Info("-- Tally Stage 3: Shuffling %d voting records (credential, vote) pairs...", len(input.Votes))
	if err = ctx.Recorder.Record("Tally_3_ShuffleVotingRecords", metrics.MLogic, func() error {
		voteCredsX, voteCredsY := extractBallotSequences(input.Votes)
		tally.VoteRecordsShuffled, err = crypto.ShuffleElGamalSequences(ctx, input.EA.PublicKey(), voteCredsX, voteCredsY)
		return err
	}); err != nil {
		return err
	}

	log.Info("-- Tally Stage 4: Generate a deterministic tag on each of the %d shuffled voting records...",
		len(tally.VoteRecordsShuffled[lastTallier].ShuffledC1s[0]))
	if err = ctx.Recorder.Record("Tally_4_DeterministicTagsOnShuffledVotingRecords", metrics.MLogic, func() error {
		if err = ctx.Recorder.Record("GenerateDeterministicTags", metrics.MLogic, func() error {
			tally.VoteCredTags, tally.VoteCredTagsProof, err = crypto.GenerateDeterministicTags(
				crypto.Suite,
				tally.VoteRecordsShuffled[lastTallier].ShuffledC1s[0],
				tally.VoteRecordsShuffled[lastTallier].ShuffledC2s[0],
				talliers,
			)
			return nil
		}); err != nil {
			return fmt.Errorf("failed to generate deterministic tags: %w", err)
		}
		if err = ctx.Recorder.Record("VerifyDeterministicTags", metrics.MLogic, func() error {
			return crypto.VerifyDeterministicTagProof(
				crypto.Suite,
				tally.VoteRecordsShuffled[lastTallier].ShuffledC1s[0],
				tally.VoteRecordsShuffled[lastTallier].ShuffledC2s[0],
				talliers,
				tally.VoteCredTagsProof,
			)
		}); err != nil {
			return fmt.Errorf("failed to verify deterministic tags: %w", err)
		}
		return err
	}); err != nil {
		return err
	}

	log.Info("-- Tally Stage 5: Use %d tags to determine real votes...", len(input.Creds))
	if err = ctx.Recorder.Record("Tally_5_FilterRealVotes", metrics.MLogic, func() error {
		tally.RealEncVotes, err = filterForRealVotes(tally, lastTallier)
		return err
	}); err != nil {
		return err
	}

	log.Info("-- Tally Stage 6: Decrypt real votes...")
	if err = ctx.Recorder.Record("Tally_6_DecryptVotes", metrics.MLogic, func() error {
		tally.RealDecVotes, err = decryptVotes(ctx, input, tally.RealEncVotes)
		return err
	}); err != nil {
		return err
	}

	log.Info("-- Tally Stage 7: Calculate tally results...")
	_ = ctx.Recorder.Record("Tally_7_TallyResults", metrics.MLogic, func() error {
		tally.Results = make(map[uint]uint, len(tally.RealDecVotes))
		for _, vote := range tally.RealDecVotes {
			_, ok := tally.Results[vote]
			if !ok {
				tally.Results[vote] = 1
			} else {
				tally.Results[vote] += 1
			}
		}
		if tally.Results[0] > tally.Results[1] {
			tally.Winner = "Option A"
		} else {
			tally.Winner = "Option B"
		}
		return nil
	})

	fmt.Printf("Option A: %d\n", tally.Results[0])
	fmt.Printf("Option B: %d\n", tally.Results[1])
	fmt.Printf("Winner: %s\n", tally.Winner)

	return err
}

// verifyLedgerContents checks the integrity and proofs of all records on the ledger.
func verifyLedgerContents(ctx *context.OperationContext, input *TallyInput) error {
	// Verify Registration Records
	for _, regRecord := range input.RegRecords {
		if err := regRecord.Verify(); err != nil {
			return fmt.Errorf("failed to verify registration record %s: %w", regRecord.VoterID, err)
		}
	}

	// Compile Credential Authorization List: Real and Fake Credentials issued by the Kiosk
	authorizedCredList := make(map[string]struct{})
	for _, v := range input.Creds {
		authorizedCredList[v.CredPk.String()] = struct{}{}
	}

	// Verify voting records by comparing them with the credential authorization list.
	for _, voteRecord := range input.Votes {
		if err := ctx.Recorder.Record("VerifyAVote", metrics.MLogic, func() error {
			if err := voteRecord.Verify(authorizedCredList); err != nil {
				return fmt.Errorf("failed to verify voting record for vote %s: %w", voteRecord, err)
			}
			return nil
		}); err != nil {
			return err
		}

	}
	return nil
}

// extractRegCredentials extracts the encrypted real credentials from the registration ledger.
func extractRegCredentials(records []*ledger.RegistrationEntry) []*crypto.ElGamalCiphertext {
	creds := make([]*crypto.ElGamalCiphertext, len(records))
	for i, record := range records {
		creds[i] = record.EncVoterPk
	}
	return creds
}

// extractBallotSequences extracts the two ElGamal sequences (encrypted credential, encrypted ballot) from the voting ledger.
func extractBallotSequences(votes []*ledger.VotingEntry) ([][]kyber.Point, [][]kyber.Point) {
	k := len(votes)
	if k == 0 {
		return nil, nil
	}

	C1_creds := make([]kyber.Point, k)
	C2_creds := make([]kyber.Point, k)
	C1_votes := make([]kyber.Point, k)
	C2_votes := make([]kyber.Point, k)

	for i, vote := range votes {
		C1_creds[i] = crypto.Suite.Point().Set(vote.EncCredPk.C1)
		C2_creds[i] = crypto.Suite.Point().Set(vote.EncCredPk.C2)
		C1_votes[i] = crypto.Suite.Point().Set(vote.EncVote.C1)
		C2_votes[i] = crypto.Suite.Point().Set(vote.EncVote.C2)
	}

	X := [][]kyber.Point{C1_creds, C1_votes}
	Y := [][]kyber.Point{C2_creds, C2_votes}
	return X, Y
}

// filterForRealVotes filters out invalid votes by matching deterministic tags against the registration record tags.
func filterForRealVotes(tally *Tally, lastTallier uint64) ([]*crypto.ElGamalCiphertext, error) {
	// Build a hash table from the deterministic tag
	tagToReg := make(map[string]struct{}, len(tally.RegCredTags))
	for _, cred := range tally.RegCredTags {
		tagToReg[cred.String()] = struct{}{}
	}

	var realEncVotes = make([]*crypto.ElGamalCiphertext, 0)
	for i, cred := range tally.VoteCredTags {
		if _, ok := tagToReg[cred.String()]; !ok {
			continue
		}

		realEncVotes = append(realEncVotes, &crypto.ElGamalCiphertext{
			C1: tally.VoteRecordsShuffled[lastTallier].ShuffledC1s[1][i],
			C2: tally.VoteRecordsShuffled[lastTallier].ShuffledC2s[1][i],
		})
	}
	return realEncVotes, nil
}

// decryptVotes decrypts a list of encrypted votes using threshold decryption and verifies the generated proofs.
func decryptVotes(ctx *context.OperationContext, input *TallyInput, realEncVotes []*crypto.ElGamalCiphertext) ([]uint, error) {
	log.Info("Tally Step 6: Decrypting %d real votes...", len(realEncVotes))

	var realVotes []uint
	for _, cred := range realEncVotes {
		var M kyber.Point
		var decProofs []*crypto.ElGamalProof
		var err error
		if err = ctx.Recorder.Record("MultiKeyDecryptWithProof", metrics.MLogic, func() error {
			M, decProofs, err = cred.MultiKeyDecryptWithProof(input.EA.KeyShares())
			return nil
		}); err != nil {
			return nil, err
		}

		if err != nil {
			return nil, fmt.Errorf("failed to decrypt vote: %w", err)
		}
		if err = ctx.Recorder.Record("VerifyDecryptionProofs", metrics.MLogic, func() error {
			for _, decProof := range decProofs {
				err = decProof.Verify()
				if err != nil {
					return fmt.Errorf("decryption proof failed: %v", err)
				}
			}
			return nil
		}); err != nil {
			return nil, err
		}

		if M.Equal(crypto.Suite.Point().Null()) {
			log.Debug("Decrypted Vote: %d", 0)
			realVotes = append(realVotes, 0)
		} else if M.Equal(crypto.Suite.Point().Base()) {
			log.Debug("Decrypted Vote: %d", 1)
			realVotes = append(realVotes, 1)
		} else {
			return nil, fmt.Errorf("decryption failed: %s", M)
		}
	}

	return realVotes, nil
}
