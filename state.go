package peachy

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// deviceState is what a linked device keeps between runs: its signing seed,
// install id, session, device id and (once approved) the account key. A JSON
// file in the data directory, next to the MLS store; the same file the Rust
// client wrote, so existing logins carry over.
//
// The seed and account key are secrets held as plain bytes on disk, readable
// only by the bridge's user. They should be encrypted at rest (see PLAN).
type deviceState struct {
	InstallID            string `json:"install_id"`
	SeedHex              string `json:"seed_hex"`
	SessionToken         string `json:"session_token"`
	DeviceID             string `json:"device_id"`
	AccountKeyHex        string `json:"account_key_hex"`
	PublishedKeyPackages bool   `json:"published_key_packages"`
	// When the last-resort key package was last published, Unix seconds
	// (keypackages.go).
	LastResortAt int64 `json:"last_resort_at,omitempty"`
	// Hellos owed, by conversation (accesskey.go).
	Hellos map[string]*owedHello `json:"hellos,omitempty"`
	// The account store's floor per store key (storefloor.go): the highest
	// version read or written under it, never forgotten.
	StoreFloors map[string]int64 `json:"store_floors,omitempty"`
	// The leaf updates owed (leafupdate.go): when this build first swept the
	// groups, and the update due in each group, Unix seconds.
	LeafSweptAt int64            `json:"leaf_swept_at,omitempty"`
	LeafUpdates map[string]int64 `json:"leaf_updates,omitempty"`
}

func statePath(dir string) string { return filepath.Join(dir, "device.json") }

// loadState returns nil when there is no saved device yet.
func loadState(dir string) (*deviceState, error) {
	b, err := os.ReadFile(statePath(dir))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	var s deviceState
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, fmt.Errorf("device.json: %w", err)
	}
	return &s, nil
}

func (s *deviceState) save(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	tmp := statePath(dir) + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, statePath(dir))
}

func (s *deviceState) seed() ([]byte, error) { return hex32(s.SeedHex, "seed") }

// accountKey returns nil until the device is approved: else the key as
// held, 32 bytes or 64 in the two-key form (store key, then identity root;
// peachy-protocol's docs/account-store.md, "The held account key").
func (s *deviceState) accountKey() ([]byte, error) {
	if s.AccountKeyHex == "" {
		return nil, nil
	}
	b, err := hex.DecodeString(s.AccountKeyHex)
	if err != nil || !accountKeyLength(len(b)) {
		return nil, errors.New("account key is not 32 or 64 bytes of hex")
	}
	return b, nil
}

// accountKeyLength: a held account key is 32 bytes, or 64 in the two-key
// form; any other length is refused.
func accountKeyLength(n int) bool { return n == 32 || n == 64 }

func hex32(h, what string) ([]byte, error) {
	b, err := hex.DecodeString(h)
	if err != nil || len(b) != 32 {
		return nil, fmt.Errorf("%s is not 32 bytes of hex", what)
	}
	return b, nil
}
