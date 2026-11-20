package peachy

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"slices"
	"testing"

	"github.com/collinjackson/peachy-go/pb"
)

var testAccountKey = bytes.Repeat([]byte{0xa1}, 32)

// sealedStore builds a ReadStoreResponse at version holding records, each
// {kind, key, at, value}, under its hex id.
func sealedStore(t *testing.T, version int64, ids []string, records []map[string]any) *pb.ReadStoreResponse {
	t.Helper()
	manifest, _ := json.Marshal(map[string]any{"version": version, "ids": ids})
	sealedManifest, err := storeSeal(testAccountKey, manifestID, manifest)
	if err != nil {
		t.Fatal(err)
	}
	resp := &pb.ReadStoreResponse{Version: version, Manifest: sealedManifest}
	for i, r := range records {
		id, _ := hex.DecodeString(ids[i])
		plain, _ := json.Marshal(r)
		value, err := storeSeal(testAccountKey, id, plain)
		if err != nil {
			t.Fatal(err)
		}
		resp.Records = append(resp.Records, &pb.StoreRecord{Id: id, Value: value})
	}
	return resp
}

// Replays the merge cases of Peachy's store fixture: for each subject, the
// record kept must be one the fixture keeps.
func TestStoreMergeFixture(t *testing.T) {
	path := os.Getenv("PEACHY_STORE_FIXTURE")
	if path == "" {
		t.Skip("no store merge fixture: peachy-protocol doesn't publish one; set PEACHY_STORE_FIXTURE")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("no Peachy fixture: %v", err)
	}
	var f struct {
		Merge []struct {
			Name    string `json:"name"`
			Records []struct {
				ID   string `json:"id"`
				Kind string `json:"kind"`
				Key  string `json:"key"`
				At   int64  `json:"at"`
			} `json:"records"`
			Keep []string `json:"keep"`
		} `json:"merge"`
	}
	if err := json.Unmarshal(b, &f); err != nil {
		t.Fatal(err)
	}
	for _, c := range f.Merge {
		t.Run(c.Name, func(t *testing.T) {
			var ids []string
			var records []map[string]any
			for _, r := range c.Records {
				// Each record's value names it, so the winner shows.
				value := map[string]any{}
				switch r.Kind {
				case "contact":
					value["contactName"] = r.ID
				case "chat":
					value["mute"] = r.ID
				case "account":
					value["readReceipts"] = !slices.Contains(c.Keep, r.ID)
				}
				ids = append(ids, r.ID)
				records = append(records, map[string]any{"kind": r.Kind, "key": r.Key, "at": r.At, "value": value})
			}
			s, err := openStore(testAccountKey, sealedStore(t, 3, ids, records))
			if err != nil {
				t.Fatal(err)
			}
			for key, contact := range s.Contacts {
				if !slices.Contains(c.Keep, contact.ContactName) {
					t.Errorf("contact %s kept %s", key, contact.ContactName)
				}
			}
			for key, chat := range s.Chats {
				if !slices.Contains(c.Keep, chat.Mute) {
					t.Errorf("chat %s kept %s", key, chat.Mute)
				}
			}
			for _, r := range c.Records {
				if r.Kind == "account" && s.ReadReceipts {
					t.Error("kept the wrong account record")
				}
			}
		})
	}
}

func TestStoreRefusesReplayedManifest(t *testing.T) {
	resp := sealedStore(t, 3, nil, nil)
	resp.Version = 4
	if _, err := openStore(testAccountKey, resp); err == nil {
		t.Fatal("a manifest sealed at version 3 read as version 4")
	}
}

func TestStoreIgnoresRecordsOutsideManifest(t *testing.T) {
	id := "11111111111111111111111111111111"
	resp := sealedStore(t, 2, []string{id}, []map[string]any{{"kind": "contact", "key": "a", "at": 1, "value": map[string]any{"blocked": true}}})
	stray := sealedStore(t, 2, []string{"22222222222222222222222222222222"}, []map[string]any{{"kind": "contact", "key": "b", "at": 1, "value": map[string]any{"blocked": true}}})
	resp.Records = append(resp.Records, stray.Records...)
	s, err := openStore(testAccountKey, resp)
	if err != nil {
		t.Fatal(err)
	}
	if !s.Blocked("a") || s.Blocked("b") {
		t.Fatalf("contacts: %+v", s.Contacts)
	}
}

func TestNameFor(t *testing.T) {
	s := &Store{Contacts: map[string]Contact{
		"chose":   {ContactName: "Mom", NameChoice: "contact"},
		"unchose": {ContactName: "Sam W"},
	}}
	for _, c := range []struct{ actor, peachy, want string }{
		{"chose", "Maria", "Mom"},
		{"unchose", "Sam", "Sam"},
		{"unchose", "", "Sam W"},
		{"nobody", "Lee", "Lee"},
	} {
		if got := s.NameFor(c.actor, c.peachy); got != c.want {
			t.Errorf("NameFor(%s, %q) = %q, want %q", c.actor, c.peachy, got, c.want)
		}
	}
}
