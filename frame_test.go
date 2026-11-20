package peachy

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Replays the timer cases of Peachy's payload fixture, from a Peachy
// checkout beside this repo (or $PEACHY_PAYLOAD_FIXTURE). Skipped when there
// is none.
func TestFrameTimers(t *testing.T) {
	path := os.Getenv("PEACHY_PAYLOAD_FIXTURE")
	if path == "" {
		path = filepath.Join(protocolDir(), "mls", "fixtures", "formats", "payload.json")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("no Peachy fixture: %v", err)
	}
	var f struct {
		Cases []struct {
			Name      string `json:"name"`
			Plaintext string `json:"plaintext"`
			Expect    struct {
				Kind          string `json:"kind"`
				Text          string `json:"text"`
				ExpireSeconds int64  `json:"expireSeconds"`
			} `json:"expect"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(b, &f); err != nil {
		t.Fatal(err)
	}
	ran := 0
	for _, c := range f.Cases {
		plain, err := base64.StdEncoding.DecodeString(c.Plaintext)
		if err != nil || !strings.Contains(string(plain), `"x"`) {
			continue
		}
		ran++
		t.Run(c.Name, func(t *testing.T) {
			got, ok := readFrame(plain)
			if c.Expect.Kind == "unreadable" {
				if ok {
					t.Fatalf("read %+v, want unreadable", got)
				}
				return
			}
			if !ok || got.text != c.Expect.Text || got.timer != time.Duration(c.Expect.ExpireSeconds)*time.Second {
				t.Fatalf("read %+v (ok %v), want %q with %ds", got, ok, c.Expect.Text, c.Expect.ExpireSeconds)
			}
		})
	}
	if ran == 0 {
		t.Fatal("the fixture has no timer cases")
	}
}
