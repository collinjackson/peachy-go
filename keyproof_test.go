package peachy

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// The test vector in peachy-protocol's docs/identity.md, "Taking over a row".
func TestKeyProofVector(t *testing.T) {
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i + 1)
	}
	pub, err := signingPublicKey(seed)
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(pub); got != "79b5562e8fe654f94078b112e8a98ba7901f853ae695bed7e0e3910bad049664" {
		t.Fatalf("public key %s", got)
	}
	want, _ := hex.DecodeString("c35e6f48702cc464c7e1d1cd9b21181c473ff7b331df0f40bff691aa206158d7c01b15e17ebbe199e3f0c1a5d5425a309a9da42f1329aadde4af2d29a5204109")
	got := keyProof(seed, "3f0c2a9e-7b41-4d5e-9a80-1c2d3e4f5a6b", pub, "pst_example-bearer-token-0123456789")
	if !bytes.Equal(got, want) {
		t.Fatalf("proof %x", got)
	}
}
