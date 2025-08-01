package ledger

import (
	"crypto/sha256"
	"fmt"
	"go.dedis.ch/kyber/v3"
)

// Ledger is a data structure available to all actors, it mimics append-only.
type Ledger struct {
	registration map[uint64]*RegistrationEntry
	envelopes    map[[32]byte]*EnvelopeEntry
	credentials  []*CredentialEntry
	votes        []*VotingEntry
}

func NewLedger() *Ledger {
	return &Ledger{
		registration: make(map[uint64]*RegistrationEntry),
		envelopes:    make(map[[32]byte]*EnvelopeEntry),
		votes:        make([]*VotingEntry, 0),
	}
}

// AppendRegistrationRecord adds a record for a voter's registration.
func (l *Ledger) AppendRegistrationRecord(voterID uint64, entry *RegistrationEntry) {
	l.registration[voterID] = entry
}

// GetRegistrationRecord retrieves a voter's registration record.
func (l *Ledger) GetRegistrationRecord(voterID uint64) (*RegistrationEntry, bool) {
	entry, ok := l.registration[voterID]
	return entry, ok
}

// GetRegistrationRecords retrieves all registration entries stored in the `registration` sub-ledger as a slice.
func (l *Ledger) GetRegistrationRecords() []*RegistrationEntry {
	records := make([]*RegistrationEntry, 0, len(l.registration))
	for _, record := range l.registration {
		records = append(records, record)
	}
	return records
}

// AppendEnvelopeRecord adds a record for a generated envelope.
func (l *Ledger) AppendEnvelopeRecord(entry *EnvelopeEntry) {
	key := sha256.Sum256(entry.ChallengeBytes)
	l.envelopes[key] = entry
}

// MarkEnvelopeUsed checks if an envelope challenge exists and marks it as used.
func (l *Ledger) MarkEnvelopeUsed(challenge kyber.Scalar) (*EnvelopeEntry, error) {
	challengeBytes, err := challenge.MarshalBinary()
	if err != nil {
		return nil, err
	}
	key := sha256.Sum256(challengeBytes)

	entry, ok := l.envelopes[key]
	if !ok {
		return nil, fmt.Errorf("envelope with given challenge does not exist on ledger")
	}
	if entry.IsUsed {
		return nil, fmt.Errorf("envelope with given challenge has already been used")
	}
	entry.IsUsed = true
	return entry, nil
}

// AppendCredentialRecord adds a new credential entry to the `credentials` sub-ledger in an append-only manner.
func (l *Ledger) AppendCredentialRecord(entry *CredentialEntry) {
	l.credentials = append(l.credentials, entry)
}

// GetCredentialRecords retrieves all credential entries stored in the `credentials` sub-ledger.
func (l *Ledger) GetCredentialRecords() []*CredentialEntry {
	return l.credentials
}

// AppendVoteRecord adds a new voting entry to the `votes` sub-ledger in an append-only manner.
func (l *Ledger) AppendVoteRecord(entry *VotingEntry) {
	l.votes = append(l.votes, entry)
}

// GetVotingRecords returns all voting entries stored in the `votes` sub-ledger.
func (l *Ledger) GetVotingRecords() []*VotingEntry {
	return l.votes
}
