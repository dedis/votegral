package crypto

import (
	"go.dedis.ch/kyber/v3"
	"testing"
)

func TestSigmaProofs(t *testing.T) {
	t.Run("TestProver_Commit", func(t *testing.T) {
		InitCryptoParams("votegral")
		tests := []struct {
			name         string
			proverScalar kyber.Scalar
			eaPK         kyber.Point
		}{
			{"valid_commitment", Suite.Scalar().Pick(RandomStream), Suite.Point().Pick(RandomStream)},
			{"zero_eaPK", Suite.Scalar().Pick(RandomStream), Suite.Point().Null()},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				prover := NewProver(tt.proverScalar)
				commitment := prover.Commit(tt.eaPK)

				if commitment == nil {
					t.Fatalf("Commit returned nil commitment")
				}
				if !commitment.Y1.Equal(Suite.Point().Mul(prover.y, G)) {
					t.Errorf("Commitment Y1 is incorrect")
				}
				if !commitment.Y2.Equal(Suite.Point().Mul(prover.y, tt.eaPK)) {
					t.Errorf("Commitment Y3 is incorrect")
				}
			})
		}
	})

	t.Run("TestProver_Respond", func(t *testing.T) {
		InitCryptoParams("votegral")
		tests := []struct {
			name      string
			proverX   kyber.Scalar
			proverY   kyber.Scalar
			challenge kyber.Scalar
		}{
			{"valid_response", Suite.Scalar().Pick(RandomStream), Suite.Scalar().Pick(RandomStream), Suite.Scalar().Pick(RandomStream)},
			{"zero_challenge", Suite.Scalar().Pick(RandomStream), Suite.Scalar().Pick(RandomStream), Suite.Scalar().Zero()},
			{"zero_proverX", Suite.Scalar().Zero(), Suite.Scalar().Pick(RandomStream), Suite.Scalar().Pick(RandomStream)},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				prover := &Prover{x: tt.proverX, y: tt.proverY}
				response := prover.Respond(tt.challenge)

				expected := Suite.Scalar().Sub(prover.y, Suite.Scalar().Mul(tt.challenge, prover.x))
				if !response.Equal(expected) {
					t.Errorf("Response is incorrect, got %v, want %v", response, expected)
				}
			})
		}
	})

	t.Run("TestSimulatedProver_CommitAndRespond", func(t *testing.T) {
		InitCryptoParams("votegral")
		tests := []struct {
			name      string
			challenge kyber.Scalar
			c_pc      *ElGamalCiphertext
			X, eaPK   kyber.Point
		}{
			{
				"valid_simulated_commit",
				Suite.Scalar().Pick(RandomStream),
				&ElGamalCiphertext{
					C1: Suite.Point().Pick(RandomStream),
					C2: Suite.Point().Pick(RandomStream),
				},
				Suite.Point().Pick(RandomStream),
				Suite.Point().Pick(RandomStream),
			},
			{
				"zero_points",
				Suite.Scalar().Pick(RandomStream),
				&ElGamalCiphertext{
					C1: Suite.Point().Null(),
					C2: Suite.Point().Null(),
				},
				Suite.Point().Null(),
				Suite.Point().Null(),
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				prover := NewSimulatedProver()
				commitment, response := prover.CommitAndRespond(tt.challenge, tt.c_pc, tt.X, tt.eaPK)

				if commitment == nil {
					t.Fatalf("CommitAndRespond returned nil commitment")
				}
				if response == nil {
					t.Fatalf("CommitAndRespond returned nil response")
				}

				expectedY1 := Suite.Point().Add(Suite.Point().Mul(response, G), Suite.Point().Mul(tt.challenge, tt.c_pc.C1))
				if !commitment.Y1.Equal(expectedY1) {
					t.Errorf("Commitment Y1 is incorrect")
				}
				expectedY2 := Suite.Point().Add(Suite.Point().Mul(response, tt.eaPK), Suite.Point().Mul(tt.challenge, tt.X))
				if !commitment.Y2.Equal(expectedY2) {
					t.Errorf("Commitment Y2 is incorrect")
				}
			})
		}
	})

	t.Run("TestVerifyProof", func(t *testing.T) {
		InitCryptoParams("votegral")

		// --- ZKP ---
		eaPKProver := Suite.Point().Pick(RandomStream)
		c_pkProver := Suite.Point().Pick(RandomStream)
		c_pcProver, XProver, xProver := ElGamalEncryptPoint(eaPKProver, c_pkProver)

		prover := NewProver(xProver)
		commitmentProver := prover.Commit(eaPKProver)
		challengeProver := Suite.Scalar().Pick(RandomStream)
		responseProver := prover.Respond(challengeProver)

		// --- Simulated ZKP ---
		eaPKSimulated := Suite.Point().Pick(RandomStream)
		c_pkSimulated := Suite.Point().Pick(RandomStream)
		c_pcSimulated, _, _ := ElGamalEncryptPoint(eaPKSimulated, c_pkSimulated)

		XSimulated := Suite.Point().Sub(c_pcSimulated.C2, c_pkSimulated)
		simulatedProver := NewSimulatedProver()
		challengeSimulated := Suite.Scalar().Pick(RandomStream)
		commitmentSimulated, responseSimulated := simulatedProver.CommitAndRespond(challengeSimulated, c_pcSimulated, XSimulated, eaPKSimulated)

		tests := []struct {
			name       string
			commitment *ZKPCommitment
			challenge  kyber.Scalar
			response   kyber.Scalar
			c_pc       *ElGamalCiphertext
			X, eaPK    kyber.Point
			expectErr  bool
		}{
			{"valid_proof_simulated_prover", commitmentSimulated, challengeSimulated, responseSimulated, c_pcSimulated, XSimulated, eaPKSimulated, false},
			{"valid_proof_real_prover", commitmentProver, challengeProver, responseProver, c_pcProver, XProver, eaPKProver, false},
			{"invalid_commitment", &ZKPCommitment{Y1: Suite.Point().Null(), Y2: Suite.Point().Null()}, Suite.Scalar().Pick(RandomStream), Suite.Scalar().Pick(RandomStream), &ElGamalCiphertext{C1: Suite.Point().Pick(RandomStream), C2: Suite.Point().Pick(RandomStream)}, Suite.Point().Pick(RandomStream), Suite.Point().Pick(RandomStream), true},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				err := VerifyProof(tt.commitment, tt.challenge, tt.response, tt.c_pc, tt.X, tt.eaPK)
				if tt.expectErr && err == nil {
					t.Errorf("Expected error, but got none")
				} else if !tt.expectErr && err != nil {
					t.Errorf("Did not expect error, but got one: %v", err)
				}
			})
		}
	})
}
