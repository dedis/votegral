package ledger

import (
	"fmt"
	"go.dedis.ch/kyber/v3"
	"votegral/pkg/crypto"
	"votegral/pkg/serialization"
)

// RegistrationEntry is the data stored on the registration sub-ledger.
type RegistrationEntry struct {
	VoterID     uint64
	EncVoterPk  *crypto.ElGamalCiphertext
	KioskSig    *crypto.SchnorrSignature
	OfficialSig *crypto.SchnorrSignature
}

// RegistrationForKioskSig generates the byte slice for the registration entry that the Kiosk signs.
func RegistrationForKioskSig(VoterID uint64, C1, C2 kyber.Point) ([]byte, error) {
	s := serialization.NewSerializer()
	s.WriteUint64(VoterID)
	s.WriteKyber(C1, C2)
	return s.Bytes()
}

// RegistrationForOfficialSig generates the byte slice that the Official counter-signs.
// This includes the Kiosk's signature.
func RegistrationForOfficialSig(VoterID uint64, C1, C2 kyber.Point, KioskSig []byte) ([]byte, error) {
	kioskMsg, err := RegistrationForKioskSig(VoterID, C1, C2)
	if err != nil {
		return nil, fmt.Errorf("failed to create kiosk message: %w", err)
	}

	s := serialization.NewSerializer()
	s.WriteByteSlice(kioskMsg)
	s.WriteByteSlice(KioskSig)
	return s.Bytes()
}

// Verify validates the signatures associated with the registration entry, including the kiosk and official signatures.
func (r *RegistrationEntry) Verify() error {
	// Verify Kiosk Signature
	kioskMsg, err := RegistrationForKioskSig(r.VoterID, r.EncVoterPk.C1, r.EncVoterPk.C2)
	if err != nil {
		return fmt.Errorf("failed to get message for kiosk signature: %w", err)
	}
	if err = r.KioskSig.Verify(kioskMsg); err != nil {
		return fmt.Errorf("failed to verify Kiosk Signature: %w", err)
	}

	// Verify official Signature
	officialMsg, err := RegistrationForOfficialSig(r.VoterID, r.EncVoterPk.C1, r.EncVoterPk.C2, r.KioskSig.Sig)
	if err != nil {
		return fmt.Errorf("failed to get message for official signature: %w", err)
	}
	if err = r.OfficialSig.Verify(officialMsg); err != nil {
		return fmt.Errorf("failed to verify Official Signature: %w", err)
	}

	return nil
}

// EnvelopeEntry is the data stored on the envelope sub-ledger.
type EnvelopeEntry struct {
	ChallengeBytes []byte
	PrinterSig     *crypto.SchnorrSignature
	IsUsed         bool
}

type CredentialEntry struct {
	CredPk kyber.Point
}

func (t CredentialEntry) String() string {
	return fmt.Sprintf("CredPk: %v", t.CredPk)
}

type VotingEntry struct {
	CredPk         kyber.Point
	EncCredPk      *crypto.ElGamalCiphertext
	EncCredPkProof *crypto.ElGamalProof
	EncVote        *crypto.ElGamalCiphertext
	EncVoteProof   *crypto.ElGamalProof
	VoteSig        []byte
}

// SignPayload serializes the VotingEntry structure into a byte array for generating a Schnorr signature.
func (v *VotingEntry) SignPayload() ([]byte, error) {
	s := serialization.NewSerializer()
	s.WriteKyber(v.CredPk, v.EncCredPk.C1, v.EncCredPk.C2)
	s.WriteByteSlice(v.EncCredPkProof.Proof)
	s.WriteKyber(v.EncVote.C1, v.EncVote.C2)
	s.WriteByteSlice(v.EncVoteProof.Proof)
	return s.Bytes()
}

// Sign creates a Schnorr signature for the serialized VotingEntry payload using the given private key.
// Updates the VoteSig field with the generated signature.
func (v *VotingEntry) Sign(sk kyber.Scalar) error {
	msg, err := v.SignPayload()
	if err != nil {
		return err
	}

	sig, err := crypto.NewSchnorrSignature(sk, v.CredPk, msg)
	if err != nil {
		return err
	}
	v.VoteSig = sig.Sig
	return nil
}

// Verify checks the validity of the VotingEntry against the authorized credentials and its cryptographic proofs.
// It performs the following steps:
// 1. Verifies the existence of the credential in the authorized credential list.
// 2. Validates the Schnorr signature over the serialized VotingEntry payload.
// 3. Verifies the zero-knowledge proof for the encrypted credential.
// 4. Verifies the zero-knowledge proof for the encrypted vote.
// Returns an error if any validation step fails; otherwise, returns nil.
func (v *VotingEntry) Verify(authorizedCredList map[string]struct{}) error {
	// Ensure credential is on the public list of credentials
	_, ok := authorizedCredList[v.CredPk.String()]
	if !ok {
		return fmt.Errorf("credential not found in public list of credentials")
	}

	// Signature Verification
	msg, err := v.SignPayload()
	if err != nil {
		return fmt.Errorf("failed to get message for signature: %w", err)
	}

	sig := &crypto.SchnorrSignature{
		Pk:  v.CredPk,
		Sig: v.VoteSig,
	}
	if err = sig.Verify(msg); err != nil {
		return fmt.Errorf("failed to verify signature: %w", err)
	}

	// Proof of encrypted credential
	if err = v.EncCredPkProof.Verify(); err != nil {
		return fmt.Errorf("failed to verify proof of encrypted credential: %w", err)
	}

	// Proof of encrypted vote
	if err = v.EncVoteProof.Verify(); err != nil {
		return fmt.Errorf("failed to verify proof of encrypted vote: %w", err)
	}

	return nil
}
