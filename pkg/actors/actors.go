package actors

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"go.dedis.ch/kyber/v3"
	"votegral/pkg/config"
	"votegral/pkg/context"
	"votegral/pkg/crypto"
	"votegral/pkg/hardware"
	"votegral/pkg/io"
	"votegral/pkg/ledger"
	"votegral/pkg/log"
	"votegral/pkg/metrics"
)

// --- ElectionAuthority ---

// ElectionAuthority represents those responsible for running the
// election infrastructure. They each hold a share of the secret
// key used to decrypt data encrypted with their public key.
type ElectionAuthority struct {
	shares    []*crypto.DKGShare
	publicKey kyber.Point
}

// NewElectionAuthority creates and initializes an ElectionAuthority.
func NewElectionAuthority(eaMembers uint64) (*ElectionAuthority, error) {
	if eaMembers < 1 {
		return nil, fmt.Errorf("number of trustees must be at least 1")
	}

	// Create secret key shares and a single public key.
	shares, publicKey := crypto.NewDKG(eaMembers)

	return &ElectionAuthority{
		shares:    shares,
		publicKey: publicKey,
	}, nil
}

// PublicKey returns the election authority's collective public key.
func (ea *ElectionAuthority) PublicKey() kyber.Point {
	return ea.publicKey
}

// KeyShares return the secret key shares held by the Election Authority.
// For simulation purposes only.
func (ea *ElectionAuthority) KeyShares() []*crypto.DKGShare {
	return ea.shares
}

// --- ElectionOfficial ---

// ElectionOfficial is the actor responsible for checking in and out voters.
type ElectionOfficial struct {
	signAsymmCred *crypto.SignAsymmetricCredential
	signSymmCred  *crypto.SignSymmetricCredential
}

// NewElectionOfficial creates and initializes an ElectionOfficial.
func NewElectionOfficial() (*ElectionOfficial, error) {
	// Personal signing key pair
	asymm, err := crypto.NewSignAsymmetricCredential()
	if err != nil {
		return nil, fmt.Errorf("failed to create official's asymmetric credential: %w", err)
	}

	// Symmetric key to be shared with the kiosk
	symm, err := crypto.NewSignSymmetricCredential(32)
	if err != nil {
		return nil, fmt.Errorf("failed to create official's symmetric credential: %w", err)
	}
	return &ElectionOfficial{
		signAsymmCred: asymm,
		signSymmCred:  symm,
	}, nil
}

// SignAsymmCredential returns the official's asymmetric signing credential.
func (o *ElectionOfficial) SignAsymmCredential() *crypto.SignAsymmetricCredential {
	return o.signAsymmCred
}

// SignSymmCredential returns the official's symmetric credential used for HMACs.
func (o *ElectionOfficial) SignSymmCredential() *crypto.SignSymmetricCredential {
	return o.signSymmCred
}

// --- EnvelopePrinter ---

// EnvelopePrinter simulates the pre-printing of physical voting materials (envelopes).
type EnvelopePrinter struct {
	signCredential *crypto.SignAsymmetricCredential
	envelopes      []*io.EnvelopeQR
	nextEnvelope   int
}

// NewEnvelopePrinter creates a new EnvelopePrinter.
func NewEnvelopePrinter() (*EnvelopePrinter, error) {
	cred, err := crypto.NewSignAsymmetricCredential()
	if err != nil {
		return nil, fmt.Errorf("failed to create printer credential: %w", err)
	}
	return &EnvelopePrinter{signCredential: cred}, nil
}

// GenerateEnvelopes is a setup step to pre-generate and "print" all envelopes.
// It will generate PDF files for all envelopes. If the hardware is set to
// peripheral and the total number is below config.MaxEnvelopesToPrint, it
// will actually send print jobs to a physical printer, otherwise fail.
func (p *EnvelopePrinter) GenerateEnvelopes(ctx *context.OperationContext, hw hardware.Hardware, l *ledger.Ledger, cfg *config.Config) error {
	// Create just enough envelopes for each voter.
	envelopesToCreate := ctx.Config.Voters * (1 + ctx.Config.FakeCredentialCount)
	log.Info("Generating %d envelopes...", envelopesToCreate)
	p.envelopes = make([]*io.EnvelopeQR, envelopesToCreate)

	// Prevent accidentally creating an abundant number of envelopes when hardware is set to Peripheral.
	if cfg.HardwareType == config.HWPeripheral && envelopesToCreate > config.MaxEnvelopesToPrint {
		return fmt.Errorf("cannot generate more than %d envelopes with peripheral hardware enabled. Change parameters or update MaxEnvelopesToPrint in config.go", config.MaxEnvelopesToPrint)
	} else if cfg.HardwareType == config.HWDisk && envelopesToCreate > config.MaxEnvelopesToSave {
		return fmt.Errorf("cannot generate more than %d envelopes with disk hardware enabled. Change parameters or update MaxEnvelopesToSave in config.go", config.MaxEnvelopesToSave)
	}

	for i := uint64(0); i < envelopesToCreate; i++ {
		if err := ctx.Recorder.Record("CreateAnEnvelope", metrics.MLogic, func() error {
			env := &io.EnvelopeQR{
				PrinterPK: p.signCredential.PublicKey(),
				Challenge: crypto.Suite.Scalar().Pick(crypto.RandomStream),
			}

			msg, err := env.MessageToSign()
			if err != nil {
				return err
			}
			sig, err := crypto.NewSchnorrSignature(p.signCredential.PrivateKey(), p.signCredential.PublicKey(), msg)
			if err != nil {
				return err
			}
			env.SetSignature(sig.Sig)

			// Store the filepath
			tempStorage := io.NewSimpleStorage()
			if err := hw.Write(ctx, tempStorage, env, false); err != nil {
				return fmt.Errorf("failed to write envelope #%d: %w", i, err)
			}
			env.Filepath = tempStorage.Load(io.EnvelopeQRType)

			p.envelopes[i] = env
			log.Trace("Generated envelope #%d: %s", i, env)

			challengeBytes, err := env.Challenge.MarshalBinary()
			if err != nil {
				return err
			}
			ledgerEntry := &ledger.EnvelopeEntry{
				PrinterSig:     sig,
				ChallengeBytes: challengeBytes,
				IsUsed:         false,
			}
			l.AppendEnvelopeRecord(ledgerEntry)
			return nil
		}); err != nil {
			return fmt.Errorf("failed to generate envelope #%d: %w", i, err)
		}
	}
	return nil
}

// NextEnvelope retrieves the next available envelope QR and advances the index.
func (p *EnvelopePrinter) NextEnvelope() (*io.EnvelopeQR, error) {
	if p.nextEnvelope >= len(p.envelopes) {
		return nil, fmt.Errorf("no more envelopes available")
	}
	env := p.envelopes[p.nextEnvelope]
	p.nextEnvelope++
	return env, nil
}

// GetEnvelopeFilepath allows the simulation to know the location of a specific envelope.
// This is a simulation-only helper mimicking the selection of an envelope when
// peripherals are not used.
func (p *EnvelopePrinter) GetEnvelopeFilepath(index int) string {
	if index < 0 || index >= len(p.envelopes) {
		panic("invalid envelope index")
	}

	return p.envelopes[index].Filepath
}

// --- Kiosk ---

// Kiosk is an interactive actor for voter registration.
type Kiosk struct {
	signAsymmCred *crypto.SignAsymmetricCredential
	signSymmCred  *crypto.SignSymmetricCredential // Shared with ElectionOfficial
}

// NewRegistrationKiosk creates and initializes a Kiosk.
func NewRegistrationKiosk(sharedSymmCred *crypto.SignSymmetricCredential) (*Kiosk, error) {
	asymm, err := crypto.NewSignAsymmetricCredential()
	if err != nil {
		return nil, fmt.Errorf("failed to create kiosk's asymmetric credential: %w", err)
	}
	return &Kiosk{
		signAsymmCred: asymm,
		signSymmCred:  sharedSymmCred, // Receives the shared key
	}, nil
}

// Authorize is the Kiosk's internal logic for verifying a check-in barcode.
func (k *Kiosk) Authorize(barcode *io.CheckInBarcode) error {
	h := hmac.New(sha256.New, k.SignSymmCredential().Key())
	voterIDBytes := make([]byte, 8)
	binary.BigEndian.PutUint32(voterIDBytes, uint32(barcode.VoterID))
	h.Write(voterIDBytes)
	expectedTag := h.Sum(nil)

	if !hmac.Equal(barcode.Tag, expectedTag) {
		return fmt.Errorf("kiosk authorization failed: invalid HMAC tag")
	}
	return nil
}

// GenerateCredentialMaterial contains the core cryptographic logic for creating a credential
// isTest is used to designate the creation of a real or test credential.
func (k *Kiosk) GenerateCredentialMaterial(
	ctx *context.OperationContext,
	voter *Voter,
	ea *ElectionAuthority,
	p *EnvelopePrinter,
	hw hardware.Hardware,
	isTest bool,
	realCheckOutTicketForTest *io.CheckOutQR) (*io.VotingMaterials, error) {
	// Create a fresh credential
	m, err := io.NewVotingMaterials()
	if err != nil {
		return nil, err
	}
	var ciphertext *crypto.ElGamalCiphertext

	var prover *crypto.Prover
	var zkpCommit *crypto.ZKPCommitment
	if !isTest { // Real Credential
		// Encrypts the real credential's public key under the EA's key.
		var x kyber.Scalar
		ciphertext, _, x = crypto.ElGamalEncryptPoint(ea.PublicKey(), m.Credential.PublicKey())

		// Real Proof: Calculate and print the ZKP commit
		prover = crypto.NewProver(x)
		zkpCommit = prover.Commit(ea.PublicKey())

		m.Commit = &io.CommitQR{VoterID: voter.VoterID(), Ciphertext: *ciphertext, Commitment: *zkpCommit}

		// Print Commit QR
		if err = k.SignAndWrite(ctx, m, m.Commit, hw, true); err != nil {
			return nil, err
		}
	}

	// Voter picks a physical envelope and the kiosk scans it.
	// For simulation purposes, we have the voter pick the next unused envelope.
	m.Envelope, err = p.NextEnvelope()
	if err != nil {
		return nil, err
	}
	// Save the envelope's filepath to the material object so that read is successful
	// when `Core` or `Disk` HardwareType is set.
	if m.Envelope.Filepath != "" {
		m.Save(io.EnvelopeQRType, m.Envelope.Filepath)
	}

	if _, err = hw.Read(ctx, m, io.EnvelopeQRType); err != nil {
		return nil, err
	}

	var zkpResponse kyber.Scalar

	if !isTest {
		// Real Proof: Finish the sound ZKP.
		zkpResponse = prover.Respond(m.Envelope.Challenge)
	} else {
		// Simulated (Fake) Proof: Generate the complete unsound ZKP.
		// Derive the EA secret `X` from the real credential's ciphertext and its public key: X = C3 - c_pk
		ciphertext = &realCheckOutTicketForTest.EncVoterPk
		derivedX := crypto.Suite.Point().Sub(ciphertext.C2, m.Credential.PublicKey())

		simProver := crypto.NewSimulatedProver()
		zkpCommit, zkpResponse = simProver.CommitAndRespond(m.Envelope.Challenge, ciphertext, derivedX, ea.PublicKey())

		// Print the commit
		m.Commit = &io.CommitQR{VoterID: voter.VoterID(), Ciphertext: *ciphertext, Commitment: *zkpCommit}
		if err = k.SignAndWrite(ctx, m, m.Commit, hw, true); err != nil {
			return nil, err
		}
	}

	// Sign and Print the rest of the QR codes: Check-Out and Response QR codes
	m.CheckOut = &io.CheckOutQR{VoterID: voter.VoterID(), EncVoterPk: *ciphertext, KioskPK: k.SignAsymmCredential().PublicKey()}
	if err = k.SignAndWrite(ctx, m, m.CheckOut, hw, true); err != nil {
		return nil, err
	}
	m.Response = &io.ResponseQR{CredentialSK: m.Credential.PrivateKey(), ZKPResponse: zkpResponse, KioskPK: k.SignAsymmCredential().PublicKey()}
	if err = k.SignAndWrite(ctx, m, m.Response, hw, true); err != nil {
		return nil, err
	}

	return m, nil
}

func (k *Kiosk) SignAndWrite(ctx *context.OperationContext, storage io.CodeStorage, code io.SignableCode, hw hardware.Hardware, cut bool) error {
	msg, err := code.MessageToSign()
	if err != nil {
		return err
	}
	sigma, err := crypto.NewSchnorrSignature(k.signAsymmCred.PrivateKey(), k.signAsymmCred.PublicKey(), msg)
	if err != nil {
		return err
	}
	code.SetSignature(sigma.Sig)
	return hw.Write(ctx, storage, code, cut)
}

// SignAsymmCredential returns the kiosk's asymmetric signing credential.
func (k *Kiosk) SignAsymmCredential() *crypto.SignAsymmetricCredential {
	return k.signAsymmCred
}

// SignSymmCredential returns the kiosk's symmetric HMAC key.
func (k *Kiosk) SignSymmCredential() *crypto.SignSymmetricCredential {
	return k.signSymmCred
}

// --- Voter ---

// Voter represents a voter in the system.
type Voter struct {
	ID             uint64
	realMaterial   *io.VotingMaterials
	testMaterials  []*io.VotingMaterials
	checkInBarcode *io.CheckInBarcode
}

// NewVoter creates a new voter with a given ID.
func NewVoter(id uint64) *Voter {
	return &Voter{ID: id}
}

// VoterID returns the voter's unique identifier.
func (v *Voter) VoterID() uint64 {
	return v.ID
}

// SetCheckInBarcode stores the barcode received during check-in.
func (v *Voter) SetCheckInBarcode(barcode *io.CheckInBarcode) {
	v.checkInBarcode = barcode
}

// CheckInBarcode returns the voter's check-in barcode.
func (v *Voter) CheckInBarcode() *io.CheckInBarcode {
	return v.checkInBarcode
}

// SetRealMaterial stores the voter's real voting materials.
func (v *Voter) SetRealMaterial(m *io.VotingMaterials) {
	log.Trace("Generated real credential material for voter %d: %v", v.ID, m)
	v.realMaterial = m
}

// RealMaterial returns the voter's real voting materials.
func (v *Voter) RealMaterial() *io.VotingMaterials {
	return v.realMaterial
}

// AddTestMaterial appends a new test voting material.
func (v *Voter) AddTestMaterial(m *io.VotingMaterials) {
	log.Trace("Generated test credential material for voter %d: %v", v.ID, m)
	v.testMaterials = append(v.testMaterials, m)
}

// TestMaterials returns voter's test voting materials.
func (v *Voter) TestMaterials() []*io.VotingMaterials {
	return v.testMaterials
}
