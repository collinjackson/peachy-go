package peachy

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"sync"
	"testing"

	"connectrpc.com/connect"

	"github.com/collinjackson/peachy-go/pb"
)

// fakeStore is Peachy's store service in memory: compare-and-swap writes,
// and optionally one other device's write landing just before ours.
type fakeStore struct {
	mu      sync.Mutex
	version int64
	sealed  []byte // manifest
	records map[string][]byte
	// Applied once, before the first write: another device winning the race.
	race   func(*fakeStore)
	writes int
}

func (f *fakeStore) server(t *testing.T) *httptest.Server {
	mux := http.NewServeMux()
	mux.Handle("/peachy.v1.ChatService/ReadStore", connect.NewUnaryHandler("/peachy.v1.ChatService/ReadStore",
		func(_ context.Context, _ *connect.Request[pb.ReadStoreRequest]) (*connect.Response[pb.ReadStoreResponse], error) {
			f.mu.Lock()
			defer f.mu.Unlock()
			resp := &pb.ReadStoreResponse{Version: f.version, Manifest: f.sealed}
			for id, v := range f.records {
				b, _ := hex.DecodeString(id)
				resp.Records = append(resp.Records, &pb.StoreRecord{Id: b, Value: v})
			}
			return connect.NewResponse(resp), nil
		}))
	mux.Handle("/peachy.v1.ChatService/WriteStore", connect.NewUnaryHandler("/peachy.v1.ChatService/WriteStore",
		func(_ context.Context, req *connect.Request[pb.WriteStoreRequest]) (*connect.Response[pb.WriteStoreResponse], error) {
			f.mu.Lock()
			defer f.mu.Unlock()
			if f.race != nil {
				race := f.race
				f.race = nil
				race(f)
			}
			m := req.Msg
			if m.GetExpectedVersion() != f.version {
				return connect.NewResponse(&pb.WriteStoreResponse{Conflict: true, Version: f.version}), nil
			}
			f.writes++
			for _, id := range m.GetDeletes() {
				delete(f.records, hex.EncodeToString(id))
			}
			for _, r := range m.GetUpserts() {
				f.records[hex.EncodeToString(r.GetId())] = r.GetValue()
			}
			f.version++
			f.sealed = m.GetManifest()
			return connect.NewResponse(&pb.WriteStoreResponse{Version: f.version}), nil
		}))
	s := httptest.NewServer(mux)
	t.Cleanup(s.Close)
	return s
}

// put replaces the whole store with these {id: record JSON}.
func (f *fakeStore) put(t *testing.T, version int64, records map[string]string) {
	t.Helper()
	f.version, f.records = version, map[string][]byte{}
	var ids []string
	for id, plain := range records {
		b, _ := hex.DecodeString(id)
		v, err := storeSeal(testAccountKey, b, []byte(plain))
		if err != nil {
			t.Fatal(err)
		}
		f.records[id] = v
		ids = append(ids, id)
	}
	slices.Sort(ids)
	manifest, _ := json.Marshal(map[string]any{"version": version, "ids": ids})
	sealed, err := storeSeal(testAccountKey, manifestID, manifest)
	if err != nil {
		t.Fatal(err)
	}
	f.sealed = sealed
}

func testDevice(t *testing.T, url string) *Device {
	return &Device{rpc: newRPC(url), dir: t.TempDir(), state: &deviceState{AccountKeyHex: hex.EncodeToString(testAccountKey)}}
}

// A write keeps a record of a kind this build doesn't know in its manifest,
// and doesn't delete it (the fixture's unknown_kinds).
func TestStoreWriteKeepsUnknownKinds(t *testing.T) {
	var fx struct {
		UnknownKinds struct {
			Read struct {
				Records []struct {
					ID   string `json:"id"`
					JSON string `json:"json"`
				} `json:"records"`
			} `json:"read"`
		} `json:"unknown_kinds"`
	}
	storeFixture(t, &fx)
	f := &fakeStore{}
	in := map[string]string{}
	for _, r := range fx.UnknownKinds.Read.Records {
		in[r.ID] = r.JSON
	}
	f.put(t, 3, in)
	d := testDevice(t, f.server(t).URL)
	if err := d.Accept(context.Background(), "11111111-1111-4111-8111-111111111111"); err != nil {
		t.Fatal(err)
	}
	resp, err := call[pb.ReadStoreRequest, pb.ReadStoreResponse](context.Background(), d.rpc, "ReadStore", &pb.ReadStoreRequest{})
	if err != nil {
		t.Fatal(err)
	}
	live, opaque, err := readEntries(testAccountKey, resp)
	if err != nil {
		t.Fatal(err)
	}
	if !opaque["bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"] || len(live) != 2 {
		t.Fatalf("live %v, opaque %v", live, opaque)
	}
	s, err := openStore(testAccountKey, resp)
	if err != nil {
		t.Fatal(err)
	}
	if !s.Contacts["11111111-1111-4111-8111-111111111111"].Accepted || !s.Contacts["5b0f5a52-8a55-4a5b-9d59-1b9a7a3f0c11"].Blocked {
		t.Fatalf("store after: %+v", s.Contacts)
	}
	// Accepting again changes nothing, so writes nothing.
	before := f.writes
	if err := d.Accept(context.Background(), "11111111-1111-4111-8111-111111111111"); err != nil {
		t.Fatal(err)
	}
	if f.writes != before {
		t.Fatal("a patch that changed nothing wrote")
	}
}

// A write that loses a race re-reads and keeps what the other device wrote.
func TestStoreWriteConflict(t *testing.T) {
	const who = "5b0f5a52-8a55-4a5b-9d59-1b9a7a3f0c11"
	f := &fakeStore{}
	f.put(t, 1, map[string]string{"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa": `{"kind":"contact","key":"` + who + `","at":1,"value":{"contactName":"Sam"}}`})
	f.race = func(f *fakeStore) {
		f.put(t, 2, map[string]string{"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb": `{"kind":"contact","key":"` + who + `","at":2,"value":{"contactName":"Sam","nameChoice":"contact"}}`})
	}
	d := testDevice(t, f.server(t).URL)
	if err := d.Accept(context.Background(), who); err != nil {
		t.Fatal(err)
	}
	s, err := d.ReadStore(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	c := s.Contacts[who]
	if !c.Accepted || c.NameChoice != "contact" || c.ContactName != "Sam" || len(f.records) != 1 || f.version != 3 {
		t.Fatalf("after: %+v, %d records, version %d", c, len(f.records), f.version)
	}
}

func storeFixture(t *testing.T, v any) {
	t.Helper()
	path := os.Getenv("PEACHY_STORE_FIXTURE")
	if path == "" {
		t.Skip("no store merge fixture: peachy-protocol doesn't publish one; set PEACHY_STORE_FIXTURE")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("no Peachy fixture: %v", err)
	}
	if err := json.Unmarshal(b, v); err != nil {
		t.Fatal(err)
	}
}
