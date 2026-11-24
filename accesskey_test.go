package peachy

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
)

// Replays Peachy's hello fixture.
func TestHelloFixture(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(protocolDir(), "mls/fixtures/formats/hello.json"))
	if err != nil {
		t.Skip("no peachy-protocol checkout (build.sh clones one, or set PEACHY_PROTOCOL)")
	}
	var f struct {
		Cases []struct {
			ID    string `json:"id"`
			Call  string `json:"call"`
			Wire  string `json:"wire"`
			Hello struct {
				AccessKey string `json:"accessKey"`
			} `json:"hello"`
			Keys   []string        `json:"keys"`
			Expect json.RawMessage `json:"expect"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	for _, c := range f.Cases {
		t.Run(c.ID, func(t *testing.T) {
			wire := []byte(c.Wire)
			if c.Call == "encode" {
				key, _ := base64.StdEncoding.DecodeString(c.Hello.AccessKey)
				if wire, err = encodeHello(key); err != nil {
					t.Fatal(err)
				}
				var m map[string]json.RawMessage
				_ = json.Unmarshal(wire, &m)
				var keys []string
				for k := range m {
					keys = append(keys, k)
				}
				sort.Strings(keys)
				if strings.Join(keys, ",") != strings.Join(c.Keys, ",") {
					t.Fatalf("keys %v, want %v", keys, c.Keys)
				}
			}
			got := parseHello(wire)
			if string(c.Expect) == "null" {
				if got != nil {
					t.Fatalf("read %x, want nothing", got)
				}
				return
			}
			var want struct {
				AccessKey string `json:"accessKey"`
			}
			_ = json.Unmarshal(c.Expect, &want)
			if base64.StdEncoding.EncodeToString(got) != want.AccessKey {
				t.Fatalf("read %x, want %s", got, want.AccessKey)
			}
		})
	}
}

func TestParseAccessKey(t *testing.T) {
	for s, ok := range map[string]bool{
		"AAECAwQFBgcICQoLDA0ODw==": true,
		"AAECAwQFBgcICQoLDA0ODw":   false, // unpadded
		"AAECAwQFBgcICQoLDA0ODxA=": false, // 17 bytes
		"":                         false,
	} {
		if (parseAccessKey(s) != nil) != ok {
			t.Errorf("parseAccessKey(%q)", s)
		}
	}
}

func TestAccountsAdded(t *testing.T) {
	before := []member{{actorID: "me", deviceID: "d1"}, {actorID: "sam", deviceID: "s1"}}
	if accountsAdded(before, append(before, member{actorID: "sam", deviceID: "s2"}), "me") {
		t.Error("a new device of an account already in the tree owes no hello")
	}
	if accountsAdded(before, append(before, member{actorID: "me", deviceID: "d2"}), "me") {
		t.Error("our own new device owes no hello")
	}
	if !accountsAdded(before, append(before, member{actorID: "kim", deviceID: "k1"}), "me") {
		t.Error("a new account owes a hello")
	}
}

// A second reason keeps the first one's time and takes a fresh retry key; a
// hello that can't go is tried a minute later and dropped a day after its
// latest reason.
func TestOweHello(t *testing.T) {
	d := &Device{dir: t.TempDir(), state: &deviceState{}}
	now := time.UnixMilli(1_800_000_000_000)
	if err := d.oweHello("g", now); err != nil {
		t.Fatal(err)
	}
	h := *d.state.Hellos["g"]
	if h.DueMS < now.UnixMilli() || h.DueMS >= now.Add(helloMaxDelay).UnixMilli() {
		t.Fatalf("due %d not within 30 s", h.DueMS-now.UnixMilli())
	}
	if err := d.oweHello("g", now.Add(5*time.Second)); err != nil {
		t.Fatal(err)
	}
	h2 := d.state.Hellos["g"]
	if h2.DueMS != h.DueMS || h2.RetryKey == h.RetryKey {
		t.Fatalf("second reason: due %d→%d, key kept %v", h.DueMS, h2.DueMS, h2.RetryKey == h.RetryKey)
	}
	saved, _ := loadState(d.dir)
	if saved.Hellos["g"] == nil {
		t.Fatal("an owed hello must survive a restart")
	}
	// No access key yet: retried a minute later, then given up.
	at := now.Add(time.Minute)
	d.sendHellos(context.Background(), at)
	if got := d.state.Hellos["g"]; got == nil || got.DueMS != at.Add(helloRetry).UnixMilli() {
		t.Fatalf("not retried a minute later: %+v", got)
	}
	d.sendHellos(context.Background(), now.Add(25*time.Hour))
	if d.state.Hellos["g"] != nil {
		t.Fatal("a hello owed for over a day is given up")
	}
}
