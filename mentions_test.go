package peachy

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// sharedFixture reads one of Peachy's shared golden files, from a Peachy checkout
// beside this repo. Skipped when there is none.
func sharedFixture(t *testing.T, name string, v any) {
	b, err := os.ReadFile(filepath.Join(protocolDir(), "mls", "fixtures", "formats", name))
	if err != nil {
		t.Skipf("no Peachy fixture: %v", err)
	}
	if err := json.Unmarshal(b, v); err != nil {
		t.Fatal(err)
	}
}

type fixtureMention struct {
	UserID string `json:"userId"`
	Handle string `json:"handle"`
}

func TestResolveMentions(t *testing.T) {
	var f struct {
		Roster []struct {
			ID     string `json:"id"`
			Handle string `json:"handle"`
		} `json:"roster"`
		Resolve []struct {
			Name    string `json:"name"`
			Body    string `json:"body"`
			IsGroup bool   `json:"isGroup"`
			Expect  struct {
				Mentions []fixtureMention `json:"mentions"`
				Everyone bool             `json:"everyone"`
			} `json:"expect"`
		} `json:"resolve"`
	}
	sharedFixture(t, "mention.json", &f)
	var members []Person
	for _, r := range f.Roster {
		members = append(members, Person{ID: r.ID, Handle: r.Handle})
	}
	for _, c := range f.Resolve {
		t.Run(c.Name, func(t *testing.T) {
			people, everyone := ResolveMentions(c.Body, members, c.IsGroup)
			var got []fixtureMention
			for _, p := range people {
				got = append(got, fixtureMention{p.UserID, p.Handle})
			}
			if !slices.Equal(got, c.Expect.Mentions) && len(got)+len(c.Expect.Mentions) > 0 || everyone != c.Expect.Everyone {
				t.Fatalf("got %v everyone=%v, want %v everyone=%v", got, everyone, c.Expect.Mentions, c.Expect.Everyone)
			}
		})
	}
}

func TestFrameMentions(t *testing.T) {
	var f struct {
		Cases []struct {
			Name      string `json:"name"`
			Plaintext string `json:"plaintext"`
			Expect    struct {
				Text     string           `json:"text"`
				Mentions []fixtureMention `json:"mentions"`
			} `json:"expect"`
		} `json:"cases"`
	}
	sharedFixture(t, "payload.json", &f)
	ran := 0
	for _, c := range f.Cases {
		plain, err := base64.StdEncoding.DecodeString(c.Plaintext)
		if err != nil || !strings.Contains(string(plain), `"m":[`) {
			continue
		}
		ran++
		t.Run(c.Name, func(t *testing.T) {
			got, ok := readFrame(plain)
			var m []fixtureMention
			for _, p := range got.mentions {
				m = append(m, fixtureMention{p.UserID, p.Handle})
			}
			if !ok || got.text != c.Expect.Text || !slices.Equal(m, c.Expect.Mentions) {
				t.Fatalf("read %+v (ok %v), want %q with %v", got, ok, c.Expect.Text, c.Expect.Mentions)
			}
		})
	}
	if ran == 0 {
		t.Fatal("the fixture has no mention cases")
	}
}
