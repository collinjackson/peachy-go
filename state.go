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
	// Hellos owed, by conversation (accesskey.go).
	Hellos map[string]*owedHello `json:"hellos,omitempty"`
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

// accountKey returns nil until the device is approved.
func (s *deviceState) accountKey() ([]byte, error) {
	if s.AccountKeyHex == "" {
		return nil, nil
	}
	return hex32(s.AccountKeyHex, "account key")
}

func hex32(h, what string) ([]byte, error) {
	b, err := hex.DecodeString(h)
	if err != nil || len(b) != 32 {
		return nil, fmt.Errorf("%s is not 32 bytes of hex", what)
	}
	return b, nil
}
