package peachy

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Replays the signed self-note cases of peachy-protocol's account-store
// fixture (mls/fixtures/account-store.json) through noteSender and
// noteOpenSigned, from a checkout beside this repo. Skipped when there is none.
func TestSelfNoteFixture(t *testing.T) {
	b, err := os.ReadFile(filepath.Join(protocolDir(), "mls", "fixtures", "account-store.json"))
	if err != nil {
		t.Skipf("no peachy-protocol fixture: %v", err)
	}
	var f struct {
		Cases []struct {
			ID, Call, AccountKeyHex, IDHex, ValueHex, DeviceID, SenderKeyHex, ExpectError string
			NowMS                                                                         int64 `json:"nowMs"`
			Expect                                                                        struct {
				SenderDeviceID, PlaintextHex string
			}
		}
	}
	if err := json.Unmarshal(b, &f); err != nil {
		t.Fatal(err)
	}
	h := func(s string) []byte { b, _ := hex.DecodeString(s); return b }
	n := 0
	for _, c := range f.Cases {
		var got []byte
		var err error
		switch c.Call {
		case "noteSender":
			var s string
			s, err = noteSender(h(c.AccountKeyHex), h(c.IDHex), h(c.ValueHex))
			got = []byte(s)
		case "noteOpenSigned":
			got, err = noteOpenSigned(h(c.AccountKeyHex), h(c.IDHex), h(c.ValueHex), c.DeviceID, h(c.SenderKeyHex), c.NowMS)
		default:
			continue
		}
		n++
		if c.ExpectError != "" {
			if err == nil || !strings.Contains(err.Error(), c.ExpectError) {
				t.Errorf("%s: got %v, want an error with %q", c.ID, err, c.ExpectError)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: %v", c.ID, err)
			continue
		}
		want := []byte(c.Expect.SenderDeviceID)
		if c.Call == "noteOpenSigned" {
			want = h(c.Expect.PlaintextHex)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("%s: got %q, want %q", c.ID, got, want)
		}
	}
	if n == 0 {
		t.Fatal("no signed-note cases in the fixture")
	}
}
