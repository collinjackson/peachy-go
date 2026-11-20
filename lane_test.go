package peachy

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Replays the parse cases of Peachy's reaction, delete and edit fixtures,
// from a Peachy checkout beside this repo (or $PEACHY_MLS_FIXTURES).
// Skipped when there is none.
func laneFixture(t *testing.T, name string) []map[string]json.RawMessage {
	dir := os.Getenv("PEACHY_MLS_FIXTURES")
	if dir == "" {
		dir = filepath.Join(protocolDir(), "mls/fixtures/formats")
	}
	b, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		t.Skipf("no Peachy fixture: %v", err)
	}
	var f struct {
		Cases []map[string]json.RawMessage `json:"cases"`
	}
	if err := json.Unmarshal(b, &f); err != nil {
		t.Fatal(err)
	}
	return f.Cases
}

func caseString(c map[string]json.RawMessage, key string) string {
	var s string
	_ = json.Unmarshal(c[key], &s)
	return s
}

func TestLaneFixtures(t *testing.T) {
	for _, file := range []struct{ name, kind string }{
		{"reaction.json", laneReact},
		{"delete.json", laneDel},
		{"edit.json", laneEdit},
		{"receipt.json", laneMark},
	} {
		for _, c := range laneFixture(t, file.name) {
			id := caseString(c, "id")
			if !strings.HasPrefix(id, "parse/") {
				continue
			}
			t.Run(file.kind+"/"+id, func(t *testing.T) {
				got := parseLane([]byte(caseString(c, "wire")))
				if got.kind != file.kind {
					got = lane{}
				}
				if string(c["expect"]) == "null" {
					if got.kind != "" {
						t.Fatalf("read %+v, want nothing", got)
					}
					return
				}
				var want struct {
					MessageID string `json:"messageId"`
					Emoji     string `json:"emoji"`
					Remove    bool   `json:"remove"`
					Revision  int    `json:"revision"`
					Body      string `json:"body"`
					Kind      string `json:"kind"`
					Lane      bool   `json:"lane"`
				}
				if err := json.Unmarshal(c["expect"], &want); err != nil {
					t.Fatal(err)
				}
				if got.kind == "" || got.target != want.MessageID || got.emoji != want.Emoji ||
					got.remove != want.Remove || got.revision != want.Revision || got.text != want.Body || got.receipt != want.Kind || got.laneMark != want.Lane {
					t.Fatalf("read %+v, want %+v", got, want)
				}
			})
		}
	}
}

func TestLaneEncodeRoundTrip(t *testing.T) {
	const id = "11111111-1111-1111-1111-111111111111"
	r, _ := encodeReaction(id, "👍🏽", false)
	if l := parseLane(r); l.kind != laneReact || l.emoji != "👍🏽" {
		t.Fatalf("reaction: %+v", l)
	}
	x, _ := encodeReaction(id, "", true)
	if l := parseLane(x); l.kind != laneReact || !l.remove {
		t.Fatalf("clear: %+v", l)
	}
	d, _ := encodeDelete(id)
	if l := parseLane(d); l.kind != laneDel || l.target != id {
		t.Fatalf("delete: %+v", l)
	}
	e, _ := encodeEdit(id, 3, "café 🍑\nline two")
	if l := parseLane(e); l.kind != laneEdit || l.revision != 3 || l.text != "café 🍑\nline two" {
		t.Fatalf("edit: %+v", l)
	}
	if _, err := encodeReaction(id, "CALL NOW", false); err == nil {
		t.Fatal("words sent as a reaction")
	}
}

func TestValidEmoji(t *testing.T) {
	for _, ok := range []string{"👍", "❤️", "👍🏽", "🇩🇪", "👨‍👩‍👧‍👦", "5️⃣", "🏴󠁧󠁢󠁳󠁣󠁴󠁿", "☺️", "🫠"} {
		if !ValidEmoji(ok) {
			t.Errorf("%q refused", ok)
		}
	}
	for _, bad := range []string{"", "a", "5", "👍👍", "🇩", "👍 ", "🏽", ":+1:"} {
		if ValidEmoji(bad) {
			t.Errorf("%q accepted", bad)
		}
	}
}
