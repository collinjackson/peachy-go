package peachytest

// What the fake server signs and seals, each written from the section of
// peachy-protocol's docs that specifies it: the pdc1 credential and its
// published keys (identity.md "The credential", "The trusted server keys"),
// the account identity key (identity.md "The account identity key"), the
// version-1 account-key box a server-run approver seals (identity.md
// "Fetching and opening the account key"), the account store's sealed values
// (account-store.md "Encryption") and the commit stamp (delivery.md "Commit
// stamps").

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"time"
)

// Kid is a server key's id: the first 8 lowercase hex characters of
// SHA-256 over its raw public key.
func Kid(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:4])
}

// PublishedKeys is the JSON GET /healthz/device-credential-keys answers for
// one current device key.
func PublishedKeys(pub ed25519.PublicKey) string {
	// In the doc's order: kid, publicKey, current, use.
	return fmt.Sprintf(`{"enabled":true,"keys":[{"kid":"%s","publicKey":"%s","current":true,"use":"device"}]}`,
		Kid(pub), base64.StdEncoding.EncodeToString(pub))
}

// MintCredential signs a pdc1 credential. accountKey and accountSig are the
// account identity key and certificate, both nil for an uncertified device.
// The payload is written in the one spelling identity.md requires: keys in
// order, no whitespace, padded standard base64 inside, unpadded base64url
// segments.
func MintCredential(issuer ed25519.PrivateKey, actor, device string, deviceKey, accountKey, accountSig []byte, iat, exp int64) []byte {
	return mintCredential(issuer, false, actor, device, deviceKey, accountKey, accountSig, iat, exp)
}

// MintBotCredential is MintCredential for a bot's device: a pdc3, the same
// payload at v 3 with "kind":"bot" before iat (bots.md "The bot
// credential"). A pdc3 always carries the account certificate.
func MintBotCredential(issuer ed25519.PrivateKey, actor, device string, deviceKey, accountKey, accountSig []byte, iat, exp int64) []byte {
	return mintCredential(issuer, true, actor, device, deviceKey, accountKey, accountSig, iat, exp)
}

func mintCredential(issuer ed25519.PrivateKey, bot bool, actor, device string, deviceKey, accountKey, accountSig []byte, iat, exp int64) []byte {
	b64 := base64.StdEncoding.EncodeToString
	// json.Marshal of a string escapes <, > and &, which ids and base64 never
	// hold, so the "no escapes" rule holds for every value written here.
	q := func(s string) string { b, _ := json.Marshal(s); return string(b) }
	v, kind, prefix := 1, "", "pdc1."
	if bot {
		v, kind, prefix = 3, `"kind":"bot",`, "pdc3."
	}
	payload := fmt.Sprintf(`{"v":%d,"kid":%s,"actor_id":%s,"device_id":%s,"device_key":%s,"account_key":%s,"account_sig":%s,%s"iat":%d,"exp":%d}`,
		v, q(Kid(issuer.Public().(ed25519.PublicKey))), q(actor), q(device), q(b64(deviceKey)),
		q(b64(accountKey)), q(b64(accountSig)), kind, iat, exp)
	sig := ed25519.Sign(issuer, []byte(payload))
	enc := base64.RawURLEncoding.EncodeToString
	return []byte(prefix + enc([]byte(payload)) + "." + enc(sig))
}

// credentialLifetime is iat and exp for a credential issued at now: the UTC
// midnight at or before it, and the UTC midnight at or after it plus 30 days.
func credentialLifetime(now time.Time) (iat, exp int64) {
	day := int64(86400)
	t := now.Unix()
	iat = t - t%day
	end := t + 30*day
	exp = end
	if end%day != 0 {
		exp = end - end%day + day
	}
	return iat, exp
}

func hkdf32(ikm []byte, info string) []byte {
	k, err := hkdf.Key(sha256.New, ikm, nil, info, 32)
	if err != nil {
		panic(err)
	}
	return k
}

// accountIdentity is the account identity key pair derived from the held
// account key's identity root: the key itself in the one-key form (32
// bytes), its second half in the two-key form (64) (account-store.md "The
// held account key").
func accountIdentity(accountKey []byte) ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(hkdf32(accountKey[len(accountKey)-32:], "peachy account identity v1"))
}

// storeKeyOf is the held account key's store key: its first 32 bytes.
func storeKeyOf(accountKey []byte) []byte { return accountKey[:32] }

// certifyDevice is the account certificate over a device's signing key.
func certifyDevice(identity ed25519.PrivateKey, deviceKey []byte) []byte {
	return ed25519.Sign(identity, certificateMessage(deviceKey))
}

func certificateMessage(deviceKey []byte) []byte {
	return append([]byte("peachy-account-device-v1\x00"), deviceKey...)
}

// keyProofMessage is what RegisterDeviceRequest.key_proof signs
// (identity.md "Taking over a row").
func keyProofMessage(installID string, signingKey []byte, bearer string) []byte {
	token := sha256.Sum256([]byte(bearer))
	msg := []byte("peachy-device-key-proof-v1\x00")
	msg = append(msg, installID...)
	msg = append(msg, 0)
	msg = append(msg, signingKey...)
	msg = append(msg, 0)
	return append(msg, token[:]...)
}

// p is 2^255 - 19, the field of Curve25519 and Ed25519.
var p = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 255), big.NewInt(19))

// montgomery maps an Ed25519 public key to its X25519 public key,
// u = (1 + y) / (1 - y) mod p (RFC 7748 §4.1). The keys mapped here are
// ones the fake server took from devices or made itself; it checks only
// that y is in range and the map is defined.
func montgomery(pub []byte) ([]byte, error) {
	if len(pub) != 32 {
		return nil, errors.New("not a 32-byte key")
	}
	le := make([]byte, 32)
	copy(le, pub)
	le[31] &= 0x7f
	y := new(big.Int).SetBytes(reverse(le))
	if y.Cmp(p) >= 0 {
		return nil, errors.New("y out of range")
	}
	one := big.NewInt(1)
	den := new(big.Int).Mod(new(big.Int).Sub(one, y), p)
	if den.Sign() == 0 {
		return nil, errors.New("small-order key")
	}
	u := new(big.Int).Mul(new(big.Int).Add(one, y), new(big.Int).ModInverse(den, p))
	u.Mod(u, p)
	out := make([]byte, 32)
	u.FillBytes(out)
	return reverse(out), nil
}

func reverse(b []byte) []byte {
	out := make([]byte, len(b))
	for i := range b {
		out[len(b)-1-i] = b[i]
	}
	return out
}

// x25519Secret is an Ed25519 seed's X25519 secret: SHA-512(seed)[0..32]
// (crypto/ecdh clamps it).
func x25519Secret(seed []byte) (*ecdh.PrivateKey, error) {
	h := sha512.Sum512(seed)
	return ecdh.X25519().NewPrivateKey(h[:32])
}

// sealAccountKeyV1 seals the account key to a device as a server-run
// approver does: the version-1 box.
func sealAccountKeyV1(approverSeed []byte, recipientKey []byte, deviceID string, accountKey []byte) ([]byte, error) {
	a, err := x25519Secret(approverSeed)
	if err != nil {
		return nil, err
	}
	A := ed25519.NewKeyFromSeed(approverSeed).Public().(ed25519.PublicKey)
	ru, err := montgomery(recipientKey)
	if err != nil {
		return nil, err
	}
	R, err := ecdh.X25519().NewPublicKey(ru)
	if err != nil {
		return nil, err
	}
	e, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	s1, err := e.ECDH(R) // crypto/ecdh refuses an all-zero output
	if err != nil {
		return nil, err
	}
	s2, err := a.ECDH(R)
	if err != nil {
		return nil, err
	}
	info := "peachy account key v1\x00" + string(A) + string(recipientKey) + deviceID
	key := hkdf32(append(s1, s2...), info)
	E := e.PublicKey().Bytes()
	nonce := make([]byte, 12)
	rand.Read(nonce)
	box := append([]byte{1}, E...)
	box = append(box, nonce...)
	return append(box, gcm(key).Seal(nil, nonce, accountKey, E)...), nil
}

func gcm(key []byte) cipher.AEAD {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	g, err := cipher.NewGCM(block)
	if err != nil {
		panic(err)
	}
	return g
}

// storeSeal seals an account store value under its record id.
func storeSeal(accountKey, id, plaintext []byte) []byte {
	key := hkdf32(storeKeyOf(accountKey), "peachy store v1\x00"+string(id))
	padded := append(append([]byte{}, plaintext...), 0x80)
	for len(padded)%256 != 0 {
		padded = append(padded, 0)
	}
	nonce := make([]byte, 12)
	rand.Read(nonce)
	out := append([]byte{1}, nonce...)
	return append(out, gcm(key).Seal(nil, nonce, padded, id)...)
}

// stampSetDigest is SHA-256("peachy stamp set v1" || set), the set's keys
// in the order given (delivery.md "Commit stamps").
func stampSetDigest(set [][]byte) []byte {
	h := sha256.New()
	h.Write([]byte("peachy stamp set v1"))
	for _, k := range set {
		h.Write(k)
	}
	return h.Sum(nil)
}

// stampVerifies is whether stamp is one key of set's Ed25519 signature over
// "peachy commit stamp v1" || handle || BE64(epoch) || SHA-256(commit) ||
// the new set's digest (32 zeros for none).
func stampVerifies(set [][]byte, stamp, handle []byte, epoch uint64, commit []byte, newSet [][]byte) bool {
	if len(stamp) != ed25519.SignatureSize {
		return false
	}
	msg := append([]byte("peachy commit stamp v1"), handle...)
	msg = binary.BigEndian.AppendUint64(msg, epoch)
	sum := sha256.Sum256(commit)
	msg = append(msg, sum[:]...)
	if len(newSet) == 0 {
		msg = append(msg, make([]byte, 32)...)
	} else {
		msg = append(msg, stampSetDigest(newSet)...)
	}
	for _, k := range set {
		if len(k) == ed25519.PublicKeySize && ed25519.Verify(k, msg, stamp) {
			return true
		}
	}
	return false
}

// validStampSet: 1 to 64 keys of 32 bytes, strictly ascending. The fake
// doesn't check that each is a point of large order.
func validStampSet(set [][]byte) bool {
	if len(set) == 0 || len(set) > 64 {
		return false
	}
	for i, k := range set {
		if len(k) != 32 || i > 0 && bytes.Compare(set[i-1], k) >= 0 {
			return false
		}
	}
	return true
}

func randomBytes(n int) []byte {
	b := make([]byte, n)
	rand.Read(b)
	return b
}

func newUUID() string {
	b := randomBytes(16)
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	h := hex.EncodeToString(b)
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
}

func isUUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i, c := range s {
		switch {
		case i == 8 || i == 13 || i == 18 || i == 23:
			if c != '-' {
				return false
			}
		case !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f'):
			return false
		}
	}
	return true
}

// AccountCertificate is the account identity public key derived from
// accountKey and its certificate over deviceKey, the two values a certified
// RegisterDevice carries and a credential repeats.
func AccountCertificate(accountKey, deviceKey []byte) (identityKey, signature []byte) {
	id := accountIdentity(accountKey)
	return id.Public().(ed25519.PublicKey), certifyDevice(id, deviceKey)
}
