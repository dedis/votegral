package crypto

import (
	"crypto/cipher"
	"go.dedis.ch/kyber/v3/suites"
	"go.dedis.ch/kyber/v3/util/random"
	"votegral/pkg/log"
)

// Suite is the elliptic curve suite used for the entire simulation
var Suite = suites.MustFind("Ed25519")

var RandomStream cipher.Stream

// InitCryptoParams initializes the crypto parameters required by the entire simulation.
func InitCryptoParams(seed string) {
	if seed != "" {
		log.Debug("Using deterministic randomness seed: %s", seed)
		RandomStream = random.New(Suite.XOF([]byte(seed)))
	} else {
		log.Debug("Using random source")
		RandomStream = Suite.RandomStream()
	}
}

// G is the standard base point (generator) for the group.
var G = Suite.Point().Base()
