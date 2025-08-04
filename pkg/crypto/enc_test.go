package crypto

import (
	"bytes"
	"go.dedis.ch/kyber/v3"
	"testing"
)

func TestElGamal(t *testing.T) {
	t.Run("ElGamalEncryptPoint", func(t *testing.T) {
		InitCryptoParams("votegral") // Reset the random stream for this subtest

		pk := Suite.Point().Pick(RandomStream)
		m := Suite.Point().Pick(RandomStream)

		ciphertext, X, x := ElGamalEncryptPoint(pk, m)
		recovered := Suite.Point().Sub(ciphertext.C2, X)
		if !recovered.Equal(m) {
			t.Errorf("expected %v, got %v", m, recovered)
		}
		if !ciphertext.C1.Equal(Suite.Point().Mul(x, G)) {
			t.Errorf("invalid C1 value")
		}
	})

	t.Run("ElGamalCiphertext_Decrypt", func(t *testing.T) {
		InitCryptoParams("votegral") // Reset the random stream for this subtest

		sk := Suite.Scalar().Pick(RandomStream)
		Pk := Suite.Point().Mul(sk, G)
		M := Suite.Point().Pick(RandomStream)
		x := Suite.Scalar().Pick(RandomStream)

		ciphertext := &ElGamalCiphertext{
			C1: Suite.Point().Mul(x, G),
			C2: Suite.Point().Add(M, Suite.Point().Mul(x, Pk)),
		}

		tests := []struct {
			name     string
			cipher   *ElGamalCiphertext
			privKey  kyber.Scalar
			expected kyber.Point
			wantErr  bool
		}{
			{"valid", ciphertext, sk, M, false},
			{"nil key", ciphertext, nil, nil, true},
			{"nil ciphertext", nil, sk, nil, true},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				result, _, err := tt.cipher.Decrypt(tt.privKey)
				if (err != nil) != tt.wantErr {
					t.Errorf("Decrypt() error = %v, wantErr %v", err, tt.wantErr)
					return
				}
				if !tt.wantErr && !result.Equal(tt.expected) {
					t.Errorf("expected %v, got %v", tt.expected, result)
				}
			})
		}
	})

	t.Run("ElGamalCiphertext_DecryptWithProof", func(t *testing.T) {
		InitCryptoParams("votegral") // Reset the random stream for this subtest

		// 1. Create a proper key pair
		privateKey := Suite.Scalar().Pick(RandomStream)
		publicKey := Suite.Point().Mul(privateKey, G)

		// 2. Create a plaintext message
		plaintext := Suite.Point().Pick(RandomStream)

		// 3. Encrypt the message to create a valid ciphertext
		ciphertext, _, _ := ElGamalEncryptPoint(publicKey, plaintext)

		t.Run("valid", func(t *testing.T) {
			// 4. Decrypt with the correct private key and generate the proof
			decryptedPlaintext, decProof, err := ciphertext.DecryptWithProof(publicKey, privateKey)
			if err != nil {
				t.Fatalf("DecryptWithProof() error = %v", err)
			}

			// 5. Assert that the decrypted message matches the original
			if !decryptedPlaintext.Equal(plaintext) {
				t.Errorf("decrypted plaintext does not match original. Got %v, want %v", decryptedPlaintext, plaintext)
			}

			// 6. Verify the proof
			if err := decProof.Verify(); err != nil {
				t.Errorf("proof verification failed: %v", err)
			}
		})
	})

	t.Run("ElGamalCiphertext_MultiKeyDecryptWithProof", func(t *testing.T) {
		InitCryptoParams("votegral")

		privKeys, publicKey := NewDKG(2)
		M := Suite.Point().Pick(RandomStream)

		ciphertext, _, _ := ElGamalEncryptPoint(publicKey, M)

		t.Run("valid", func(t *testing.T) {
			result, proofs, err := ciphertext.MultiKeyDecryptWithProof(privKeys)
			if err != nil {
				t.Fatalf("MultiKeyDecryptWithProof() error = %v", err)
			}
			for i, p := range proofs {
				if err := p.Verify(); err != nil {
					t.Errorf("proof %d verification failed: %v", i, err)
				}
			}
			if !result.Equal(M) {
				t.Errorf("expected %v, got %v", M, result)
			}
		})
	})

	t.Run("ElGamalCiphertext_Equal", func(t *testing.T) {
		InitCryptoParams("votegral")

		c1 := Suite.Point().Pick(RandomStream)
		c2 := Suite.Point().Pick(RandomStream)

		tests := []struct {
			name     string
			cipher1  *ElGamalCiphertext
			cipher2  *ElGamalCiphertext
			expected bool
		}{
			{"equal", &ElGamalCiphertext{C1: c1, C2: c2}, &ElGamalCiphertext{C1: c1, C2: c2}, true},
			{"different", &ElGamalCiphertext{C1: c1, C2: c2}, &ElGamalCiphertext{C1: c2, C2: c1}, false},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				if result := tt.cipher1.Equal(tt.cipher2); result != tt.expected {
					t.Errorf("expected %v, got %v", tt.expected, result)
				}
			})
		}
	})

	t.Run("ElGamalCiphertext_WriteTo", func(t *testing.T) {
		InitCryptoParams("votegral")

		c1 := Suite.Point().Pick(RandomStream)
		c2 := Suite.Point().Pick(RandomStream)
		ciphertext := &ElGamalCiphertext{C1: c1, C2: c2}

		t.Run("valid", func(t *testing.T) {
			var buf bytes.Buffer
			n, err := ciphertext.WriteTo(&buf)
			if err != nil {
				t.Fatalf("WriteTo() error = %v", err)
			}
			if n <= 0 {
				t.Errorf("expected written bytes > 0, got %d", n)
			}
		})
	})

	t.Run("ExtractElGamalComponents", func(t *testing.T) {
		InitCryptoParams("votegral")

		c1 := Suite.Point().Pick(RandomStream)
		c2 := Suite.Point().Pick(RandomStream)
		ciphertext := &ElGamalCiphertext{C1: c1, C2: c2}

		t.Run("valid", func(t *testing.T) {
			C1s, C2s := ExtractElGamalComponents([]*ElGamalCiphertext{ciphertext})
			if len(C1s) != 1 || len(C2s) != 1 {
				t.Errorf("invalid components count")
			}
			if !C1s[0].Equal(c1) || !C2s[0].Equal(c2) {
				t.Errorf("invalid components values")
			}
		})
	})

	t.Run("ElGamalComponentsToCiphertext", func(t *testing.T) {
		InitCryptoParams("votegral")

		c1 := Suite.Point().Pick(RandomStream)
		c2 := Suite.Point().Pick(RandomStream)

		t.Run("valid", func(t *testing.T) {
			ciphers, err := ElGamalComponentsToCiphertext([]kyber.Point{c1}, []kyber.Point{c2})
			if err != nil {
				t.Fatalf("ElGamalComponentsToCiphertext() error = %v", err)
			}
			if len(ciphers) != 1 || !ciphers[0].C1.Equal(c1) || !ciphers[0].C2.Equal(c2) {
				t.Errorf("invalid ciphertexts created")
			}
		})
		t.Run("mismatching lengths", func(t *testing.T) {
			_, err := ElGamalComponentsToCiphertext([]kyber.Point{c1}, []kyber.Point{})
			if err == nil {
				t.Errorf("expected error for mismatching lengths")
			}
		})
	})
}
