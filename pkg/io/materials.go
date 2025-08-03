package io

import (
	"fmt"
	"votegral/pkg/crypto"
)

// VotingMaterials is a container for all the cryptographic artifacts and QR codes
// associated with a single voting credential (either real or test).
type VotingMaterials struct {
	// The core credential key pair.
	Credential *crypto.SignAsymmetricCredential

	// The QR codes that constitute the protocol materials.
	Commit   *CommitQR
	Envelope *EnvelopeQR
	Response *ResponseQR
	CheckOut *CheckOutQR

	// Implements io.CodeStorage for saving and writing to various hardware (e.g., Disk, RAM)
	qrCodeStorage map[CodeType]string
}

// NewVotingMaterials creates an initialized container for a new set of materials.
func NewVotingMaterials() (*VotingMaterials, error) {
	cred, err := crypto.NewSignAsymmetricCredential()
	if err != nil {
		return nil, err
	}
	return &VotingMaterials{
		Credential:    cred,
		qrCodeStorage: make(map[CodeType]string),
	}, nil
}

// String returns a formatted string representation of the VotingMaterials, including the Credential and QR code mapping.
func (m *VotingMaterials) String() string {
	return fmt.Sprintf("VotingMaterials{Credential:%v, CommitQR:%v, EnvelopeQR:%v, CheckOutQR:%v, ResponseQR:%v QRCodeStorage:%v}",
		m.Credential, m.Commit, m.Envelope, m.CheckOut, m.Response, m.qrCodeStorage)
}

// Save implements the io.CodeStorage interface.
func (m *VotingMaterials) Save(codeType CodeType, location string) {
	m.qrCodeStorage[codeType] = location
}

// Load implements the io.CodeStorage interface.
func (m *VotingMaterials) Load(codeType CodeType) string {
	return m.qrCodeStorage[codeType]
}

// --- SimpleStorage ---

// SimpleStorage is a minimal, map-based implementation of the io.CodeStorage interface.
// It's used as a temporary object to capture the output of a Write operation.
type SimpleStorage struct {
	paths map[CodeType]string
}

func NewSimpleStorage() *SimpleStorage {
	return &SimpleStorage{paths: make(map[CodeType]string)}
}

func (s *SimpleStorage) Save(codeType CodeType, location string) {
	s.paths[codeType] = location
}

func (s *SimpleStorage) Load(codeType CodeType) string {
	return s.paths[codeType]
}
