package peachy

// The encrypted account store: settings a person's own devices share and the
// server can't read (contact names, blocks, per-chat mute and pins, the
// read-receipts setting). A sealed manifest lists the live record ids; each
// record is sealed under the account key and its id, and Peachy's engine
// opens both (peachy_mls_store_open). The bridge only reads it.
//
// A record opens to {kind, key, at, value}. One subject (kind + key) may
// have several records while two devices race; the greatest `at` wins, a
// tie going to the greater id, as Peachy's clients merge.

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/collinjackson/peachy-go/pb"
)

// Store is what the bridge reads from the account store.
type Store struct {
	Version int64
	// Keyed by actor id.
	Contacts map[string]Contact
	// Keyed by conversation id.
	Chats map[string]ChatSettings
	// Off only when the person turned read receipts off.
	ReadReceipts bool
	// The account's access key (16 bytes), nil when the store holds none.
	AccessKey []byte
}

// Contact is what this person keeps about someone.
type Contact struct {
	Blocked bool `json:"blocked"`
	// Let in: they messaged and this person accepted or answered, or this
	// person started the conversation. A DM from someone not let in is a
	// message request.
	Accepted    bool   `json:"accepted"`
	ContactName string `json:"contactName"`
	NameChoice  string `json:"nameChoice"`
}

// ChatSettings is this person's settings for one conversation.
type ChatSettings struct {
	// "hour1", "hours8", "day", "week" (timed, ending at MutedUntil),
	// "always", "mentions" or "peachy"; "" for not muted.
	Mute       string `json:"mute"`
	MutedUntil int64  `json:"mutedUntil"`
	PinnedAt   int64  `json:"pinnedAt"`
	ArchivedAt int64  `json:"archivedAt"`
}

// Muted reports whether the chat is silenced outright at now, and until
// when (the zero time for always). "mentions" and "peachy" let some
// messages through, so they don't count.
func (c ChatSettings) Muted(now time.Time) (bool, time.Time) {
	switch c.Mute {
	case "always":
		return true, time.Time{}
	case "hour1", "hours8", "day", "week":
		until := time.UnixMilli(c.MutedUntil)
		return until.After(now), until
	}
	return false, time.Time{}
}

// NameFor is the name this person sees for someone: the contact name when
// they chose it, or when the person has no Peachy name of their own.
func (s *Store) NameFor(actor, peachyName string) string {
	if s == nil {
		return peachyName
	}
	c := s.Contacts[actor]
	if c.ContactName != "" && (c.NameChoice == "contact" || peachyName == "") {
		return c.ContactName
	}
	return peachyName
}

// Blocked reports whether this person blocked someone.
func (s *Store) Blocked(actor string) bool {
	return s != nil && s.Contacts[actor].Blocked
}

var manifestID = make([]byte, 16)

// ReadStore reads the account store, or answers the copy it already holds
// when nothing has changed since.
func (d *Device) ReadStore(ctx context.Context) (*Store, error) {
	d.mu.Lock()
	key, err := d.state.accountKey()
	if err != nil || key == nil {
		d.mu.Unlock()
		return nil, errors.New("not linked yet")
	}
	since := int64(0)
	if d.store != nil {
		since = d.store.Version
	}
	d.mu.Unlock()
	resp, err := call[pb.ReadStoreRequest, pb.ReadStoreResponse](ctx, d.rpc, "ReadStore", &pb.ReadStoreRequest{SinceVersion: since})
	if err != nil {
		return nil, err
	}
	d.mu.Lock()
	if err := d.checkFloor(key, resp.GetVersion()); err != nil {
		d.mu.Unlock()
		return nil, err
	}
	if since != 0 && resp.GetVersion() == since {
		defer d.mu.Unlock()
		return d.store, nil
	}
	d.mu.Unlock()
	s, err := openStore(key, resp)
	if err != nil {
		return nil, err
	}
	d.mu.Lock()
	d.store = s
	err = d.raiseFloor(key, s.Version)
	d.mu.Unlock()
	if err != nil {
		return nil, err
	}
	d.adoptAccessKey(ctx, s.AccessKey)
	return s, nil
}

func openStore(key []byte, resp *pb.ReadStoreResponse) (*Store, error) {
	s := &Store{Version: resp.GetVersion(), Contacts: map[string]Contact{}, Chats: map[string]ChatSettings{}, ReadReceipts: true}
	if resp.GetVersion() == 0 {
		return s, nil // no store has ever been written
	}
	plain, err := storeOpen(key, manifestID, resp.GetManifest())
	if err != nil {
		return nil, fmt.Errorf("open the store's manifest: %w", err)
	}
	var manifest struct {
		Version int64    `json:"version"`
		IDs     []string `json:"ids"`
	}
	if err := json.Unmarshal(plain, &manifest); err != nil {
		return nil, fmt.Errorf("read the store's manifest: %w", err)
	}
	// A manifest sealed at another version is a replayed old one.
	if manifest.Version != resp.GetVersion() {
		return nil, fmt.Errorf("the store's manifest is version %d, not %d", manifest.Version, resp.GetVersion())
	}
	live := map[string]bool{}
	for _, id := range manifest.IDs {
		live[id] = true
	}

	type record struct {
		id    string
		at    int64
		value json.RawMessage
	}
	newest := map[[2]string]record{}
	for _, r := range resp.GetRecords() {
		id := hex.EncodeToString(r.GetId())
		if !live[id] {
			continue
		}
		plain, err := storeOpen(key, r.GetId(), r.GetValue())
		if err != nil {
			continue // another build's record, or one that won't open
		}
		var rec struct {
			Kind  string          `json:"kind"`
			Key   string          `json:"key"`
			At    int64           `json:"at"`
			Value json.RawMessage `json:"value"`
		}
		if json.Unmarshal(plain, &rec) != nil {
			continue
		}
		subject := [2]string{rec.Kind, rec.Key}
		if old, ok := newest[subject]; ok && (old.at > rec.At || old.at == rec.At && old.id > id) {
			continue
		}
		newest[subject] = record{id, rec.At, rec.Value}
	}
	for subject, r := range newest {
		switch subject[0] {
		case "contact":
			var c Contact
			if json.Unmarshal(r.value, &c) == nil {
				s.Contacts[subject[1]] = c
			}
		case "chat":
			var c ChatSettings
			if json.Unmarshal(r.value, &c) == nil {
				s.Chats[subject[1]] = c
			}
		case "account":
			var a struct {
				ReadReceipts *bool  `json:"readReceipts"`
				AccessKey    string `json:"accessKey"`
			}
			if json.Unmarshal(r.value, &a) == nil {
				if a.ReadReceipts != nil {
					s.ReadReceipts = *a.ReadReceipts
				}
				s.AccessKey = parseAccessKey(a.AccessKey)
			}
		}
	}
	return s, nil
}
