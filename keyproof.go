package peachy

import (
	"crypto/ed25519"
	"crypto/sha256"
)

// keyProof is RegisterDeviceRequest.key_proof: the device key's Ed25519
// signature over "peachy-device-key-proof-v1" 0x00 install_id 0x00
// signing_key 0x00 SHA-256(bearer token), binding the proof to this login
// (docs/identity.md in peachy-protocol, "Taking over a row").
func keyProof(seed []byte, installID string, signingKey []byte, bearer string) []byte {
	token := sha256.Sum256([]byte(bearer))
	msg := []byte("peachy-device-key-proof-v1")
	msg = append(msg, 0)
	msg = append(msg, installID...)
	msg = append(msg, 0)
	msg = append(msg, signingKey...)
	msg = append(msg, 0)
	msg = append(msg, token[:]...)
	return ed25519.Sign(ed25519.NewKeyFromSeed(seed), msg)
}

// platformName is how Peachy's apps name a device that has no name of its
// own: by its platform.
func platformName(platform string) string {
	switch platform {
	case "ios":
		return "an iPhone"
	case "android":
		return "an Android phone"
	case "mac":
		return "a Mac"
	case "web":
		return "a browser"
	case "":
		return "another device"
	}
	return "a " + platform + " device"
}
