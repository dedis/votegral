package protocol

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/proof"
	"votegral/pkg/actors"
	"votegral/pkg/context"
	"votegral/pkg/crypto"
	"votegral/pkg/hardware"
	"votegral/pkg/io"
	"votegral/pkg/ledger"
	"votegral/pkg/log"
	"votegral/pkg/metrics"
)

// Flow encapsulates the logic for the protocol steps, acting as a mediator
// between actors and system components like the ledger and hardware.
type Flow struct {
	official *actors.ElectionOfficial
	kiosk    *actors.Kiosk
	ea       *actors.ElectionAuthority
	printer  *actors.EnvelopePrinter
	ledger   *ledger.Ledger
	hw       hardware.Hardware
}

// NewFlow creates a new protocol flow.
func NewFlow(o *actors.ElectionOfficial, k *actors.Kiosk, ea *actors.ElectionAuthority, p *actors.EnvelopePrinter, l *ledger.Ledger, hw hardware.Hardware) *Flow {
	return &Flow{official: o, kiosk: k, ea: ea, printer: p, ledger: l, hw: hw}
}

// --- Check-In Flow ---

// CheckIn simulates the interaction between the voter and the election official.
func (f *Flow) CheckIn(ctx *context.OperationContext, voter *actors.Voter) error {
	var barcode *io.CheckInBarcode

	// Use a temporary storage for the barcode state
	barcodeTempStorage := io.NewSimpleStorage()

	err := ctx.Recorder.Record("CheckInAVoter_Official", metrics.MLogic, func() error {
		// 1. Official creates an HMAC tag for the voter's ID.
		h := hmac.New(sha256.New, f.official.SignSymmCredential().Key())
		voterIDBytes := make([]byte, 8)
		binary.BigEndian.PutUint32(voterIDBytes, uint32(voter.VoterID()))
		h.Write(voterIDBytes)
		tag := h.Sum(nil)

		// 2. Official creates and "prints" the check-in barcode.
		barcode = io.NewCheckInBarcode(voter.VoterID(), tag)
		if err := f.hw.Write(ctx, barcodeTempStorage, barcode, true); err != nil {
			return err
		}
		voter.SetCheckInBarcode(barcode)
		return nil
	})
	if err != nil {
		return err
	}

	// 3. Kiosk scans and authorizes the barcode.
	err = ctx.Recorder.Record("CheckInAVoter_Kiosk", metrics.MLogic, func() error {
		readCode, err := f.hw.Read(ctx, barcodeTempStorage, io.CheckInBarcodeType)
		if err != nil {
			return err
		}
		scannedBarcode, ok := readCode.(*io.CheckInBarcode)
		if !ok {
			return fmt.Errorf("read code was not a CheckInBarcode")
		}
		return f.kiosk.Authorize(scannedBarcode)
	})
	if err != nil {
		return err
	}
	return nil
}

// --- Credential Creation Flow ---

// CreateRealCredential simulates the Kiosk guiding the voter to create their real credential.
func (f *Flow) CreateRealCredential(ctx *context.OperationContext, voter *actors.Voter) error {
	material, err := f.kiosk.GenerateCredentialMaterial(ctx, voter, f.ea, f.printer, f.hw, false, nil)
	if err != nil {
		return fmt.Errorf("failed to generate credential material: %w", err)
	}
	voter.SetRealMaterial(material)
	return nil
}

// CreateTestCredential simulates the Kiosk guiding the voter to create their test credential.
func (f *Flow) CreateTestCredential(ctx *context.OperationContext, voter *actors.Voter) error {
	// The test credential creation needs the checkout ticket to derive the ElGamal secret.
	if voter.RealMaterial() == nil || voter.RealMaterial().CheckOut == nil {
		return fmt.Errorf("cannot create test credential without a valid real checkout ticket")
	}
	realCheckoutTicket := voter.RealMaterial().CheckOut

	material, err := f.kiosk.GenerateCredentialMaterial(ctx, voter, f.ea, f.printer, f.hw, true, realCheckoutTicket)
	if err != nil {
		return fmt.Errorf("failed to generate credential material: %w", err)
	}
	voter.AddTestMaterial(material)
	return err
}

// --- Check-Out and Activation Flow ---

// CheckOut simulates the voter presenting their checkout ticket to the official.
func (f *Flow) CheckOut(ctx *context.OperationContext, voter *actors.Voter, material *io.VotingMaterials) error {
	// 1. Simulate reading the checkout ticket from the voter.
	readCode, err := f.hw.Read(ctx, material, io.CheckOutQRType)
	if err != nil {
		return err
	}
	ticket, ok := readCode.(*io.CheckOutQR)
	if !ok {
		return fmt.Errorf("read code was not a CheckOutQR")
	}

	// 2. Official verifies the Kiosk's public key and signature.
	if !ticket.KioskPK.Equal(f.kiosk.SignAsymmCredential().PublicKey()) {
		return fmt.Errorf("checkout ticket was not signed by the known kiosk")
	}
	msg, err := ticket.MessageToSign()
	if err != nil {
		return err
	}
	kioskSig := &crypto.SchnorrSignature{Pk: ticket.KioskPK, Sig: ticket.KioskSigma}
	if err := kioskSig.Verify(msg); err != nil {
		return fmt.Errorf("kiosk signature verification failed on checkout ticket: %w", err)
	}

	// 3. Official counter-signs the ticket data.
	msg, err = ledger.RegistrationForOfficialSig(ticket.VoterID, ticket.EncVoterPk.C1, ticket.EncVoterPk.C2, ticket.KioskSigma)
	if err != nil {
		return err
	}
	officialSig, err := crypto.NewSchnorrSignature(
		f.official.SignAsymmCredential().PrivateKey(),
		f.official.SignAsymmCredential().PublicKey(),
		msg)
	if err != nil {
		return err
	}

	// 4. Official appends the final record to the registration ledger.
	entry := &ledger.RegistrationEntry{
		VoterID:     voter.VoterID(),
		EncVoterPk:  &ticket.EncVoterPk,
		KioskSig:    kioskSig,
		OfficialSig: officialSig,
	}
	f.ledger.AppendRegistrationRecord(voter.VoterID(), entry)
	return nil
}

// Activate simulates the voter scanning and verifying a single set of materials to activate a credential.
func (f *Flow) Activate(ctx *context.OperationContext, voter *actors.Voter, m *io.VotingMaterials) error {
	log.Trace("Activating credential %v...", m)

	// 1. Scan QR codes
	commitCode, err := f.hw.Read(ctx, m, io.CommitQRType)
	if err != nil {
		return err
	}
	commitQR := commitCode.(*io.CommitQR)

	envelopeCode, err := f.hw.Read(ctx, m, io.EnvelopeQRType)
	if err != nil {
		return err
	}
	envelopeQR := envelopeCode.(*io.EnvelopeQR)

	responseCode, err := f.hw.Read(ctx, m, io.ResponseQRType)
	if err != nil {
		return err
	}
	responseQR := responseCode.(*io.ResponseQR)

	kioskPK := responseQR.KioskPK

	// 2. Verify signatures
	if err := verifySignature(commitQR, kioskPK); err != nil {
		return fmt.Errorf("commit QR signature verification failed: %w", err)
	}
	if err := verifySignature(responseQR, kioskPK); err != nil {
		return fmt.Errorf("response QR signature verification failed: %w", err)
	}
	if err := verifySignature(envelopeQR, envelopeQR.PrinterPK); err != nil {
		return fmt.Errorf("envelope QR signature verification failed: %w", err)
	}

	// 3. Verify the ZKP.
	// Derive X = C3 - c_pk
	c_pk := crypto.Suite.Point().Mul(responseQR.CredentialSK, nil)
	X := crypto.Suite.Point().Sub(commitQR.Ciphertext.C2, c_pk)

	err = crypto.VerifyProof(
		&commitQR.Commitment,
		envelopeQR.Challenge,
		responseQR.ZKPResponse,
		&commitQR.Ciphertext,
		X,
		f.ea.PublicKey())
	if err != nil {
		return err
	}

	// 4. Verify data against the registration ledger.
	regEntry, ok := f.ledger.GetRegistrationRecord(voter.VoterID())
	if !ok {
		return fmt.Errorf("voter %d not found in registration ledger", voter.VoterID())
	}
	// Compare the Kiosk Public Key and the credential ciphertext against the ledger entry.
	if !regEntry.KioskSig.Pk.Equal(kioskPK) {
		return fmt.Errorf("kiosk public key mismatch between materials and ledger")
	}
	if !regEntry.EncVoterPk.Equal(&commitQR.Ciphertext) {
		return fmt.Errorf("credential ciphertext mismatch between materials and ledger, got %s, expected %s", commitQR.Ciphertext, regEntry.EncVoterPk)
	}
	if regEntry.VoterID != voter.VoterID() {
		return fmt.Errorf("voter ID mismatch between materials and ledger, got %d, expected %d", regEntry.VoterID, voter.VoterID())
	}
	if !regEntry.OfficialSig.Pk.Equal(f.official.SignAsymmCredential().PublicKey()) {
		return fmt.Errorf("official public key mismatch between materials and ledger")
	}

	// 5. Mark the envelope challenge as used on the envelope ledger.
	if _, err := f.ledger.MarkEnvelopeUsed(envelopeQR.Challenge); err != nil {
		return err
	}

	return nil
}

// CastVote creates an encrypted vote containing their credential and vote.
// This function will produce the `ledger.VotingEntry` needed for tallying.
func (f *Flow) CastVote(ctx *context.OperationContext, materials *io.VotingMaterials, vote int) error {
	var votingEntry *ledger.VotingEntry
	// Create fresh new encryption of the credential's public key.
	encCred, X, x := crypto.ElGamalEncryptPoint(f.ea.PublicKey(), materials.Credential.PublicKey())
	// Prove correct encryption: C1, and X = C2/M
	predicate := proof.And(proof.Rep("C1", "x", "G"), proof.Rep("X", "x", "eaPk"))
	points := map[string]kyber.Point{"X": X, "C1": encCred.C1, "G": crypto.G, "eaPk": f.ea.PublicKey()}
	secrets := map[string]kyber.Scalar{"x": x}

	encCredProof, err := crypto.NewElGamalProof(predicate, points, secrets, nil)
	if err != nil {
		return fmt.Errorf("failed to create proof for credential encryption: %w", err)
	}

	// Encrypt Vote with Proof
	encVote, encVoteProof, err := CreateVoteWithProof(f.ea.PublicKey(), vote)
	if err != nil {
		return fmt.Errorf("failed to create vote with proof: %w", err)
	}

	votingEntry = &ledger.VotingEntry{
		CredPk:         materials.Credential.PublicKey(),
		EncCredPk:      encCred,
		EncCredPkProof: encCredProof,
		EncVote:        encVote,
		EncVoteProof:   encVoteProof,
	}
	// Sign the voting record
	if err = votingEntry.Sign(materials.Credential.PrivateKey()); err != nil {
		return fmt.Errorf("failed to sign voting entry: %w", err)
	}

	// Append the vote to the ledger
	f.ledger.AppendVoteRecord(votingEntry)

	return nil
}

// --- Helper methods ---

// CreateVoteWithProof encrypts the vote and generates a non-interactive zero-knowledge proof
// that the given ciphertext (C1, C2) is a valid encryption of either 0 or 1.
func CreateVoteWithProof(eaPK kyber.Point, vote int) (*crypto.ElGamalCiphertext, *crypto.ElGamalProof, error) {
	if vote != 0 && vote != 1 {
		return nil, nil, fmt.Errorf("vote must be 0 or 1")
	}

	var encVote *crypto.ElGamalCiphertext
	var x kyber.Scalar
	if vote == 1 {
		encVote, _, x = crypto.ElGamalEncryptPoint(eaPK, crypto.G)
	} else {
		encVote, _, x = crypto.ElGamalEncryptPoint(eaPK, crypto.Suite.Point().Null())
	}

	// Case 1: Predicate for the vote is 0:
	proofFor0 := proof.And(proof.Rep("C1", "x", "G"), proof.Rep("C2", "x", "eaPk"))

	// Case 2: Predicate for the vote is 1:
	C2Prime := crypto.Suite.Point().Sub(encVote.C2, crypto.G)
	proofFor1 := proof.And(proof.Rep("C1", "x", "G"), proof.Rep("C2Prime", "x", "eaPk"))

	// Combining the predicates
	votePredicate := proof.Or(proofFor0, proofFor1)

	// The right path based on the vote choice
	choice := make(map[proof.Predicate]int)
	choice[votePredicate] = vote

	points := map[string]kyber.Point{"C1": encVote.C1, "C2": encVote.C2, "C2Prime": C2Prime, "G": crypto.G, "eaPk": eaPK}
	secrets := map[string]kyber.Scalar{"x": x}

	Proof, err := crypto.NewElGamalProof(votePredicate, points, secrets, choice)
	if err != nil {
		return nil, nil, err
	}
	return encVote, Proof, nil
}

func verifySignature(code io.SignableCode, pk kyber.Point) error {
	msg, err := code.MessageToSign()
	if err != nil {
		return err
	}
	signature := &crypto.SchnorrSignature{Pk: pk, Sig: code.GetSignature()}
	if err := signature.Verify(msg); err != nil {
		return fmt.Errorf("signature verification failed for code type %v: %w", code.Type(), err)
	}
	return nil
}
