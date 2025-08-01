package crypto

import (
	"fmt"
	"go.dedis.ch/kyber/v3"
	"votegral/pkg/log"
)

// DKGShare represents a single share in a Distributed Key Generation (DKG) process.
type DKGShare struct {
	Sk kyber.Scalar
	Pk kyber.Point
}

func (s *DKGShare) String() string {
	return fmt.Sprintf("Sk: %s, Pk: %s;", s.Sk, s.Pk)
}

// NewDKG performs a simulated Distributed Key Generation (DKG) to create private/public key shares and
// a collective public key. It takes the number of trustees as input and returns the generated
// DKGShares and the collective public key.
func NewDKG(numTrustees uint64) ([]*DKGShare, kyber.Point) {
	var shares []*DKGShare
	var collectivePK kyber.Point

	for i := uint64(0); i < numTrustees; i++ {
		sk := Suite.Scalar().Pick(RandomStream)
		share := &DKGShare{
			Sk: sk,
			Pk: Suite.Point().Mul(sk, G),
		}
		shares = append(shares, share)

		if collectivePK == nil {
			collectivePK = Suite.Point().Set(share.Pk)
		} else {
			collectivePK.Add(collectivePK, share.Pk)
		}
	}

	log.Debug("Generated %d NewDKG shares: %s", numTrustees, shares)
	log.Debug("Generated Collective PK: %s", collectivePK)

	return shares, collectivePK
}
