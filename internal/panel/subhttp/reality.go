package subhttp

import "github.com/thehavlok/whitenet/internal/panel/keygen"

// realityPublicKey derives the public half of a Reality key.
//
// The panel stores only the private key, because that is what the node needs;
// the client's `pbk` is derived on the way out, so the two can never disagree.
func realityPublicKey(privateKey string) (string, error) {
	return keygen.RealityPublicKey(privateKey)
}
