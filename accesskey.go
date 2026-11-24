package peachy

// The account's access key (docs/protocol/delivery.md §Access keys,
// sealed-messages.md §Hellos in Peachy's tree). A peer sends to an account
// through the anonymous door, with no session, only when it holds the key of
// every account it names. So a member that never hands its key out makes every
// other member's sends into the conversation identified to the server. This
// device hands the account's key out the way Peachy's apps do: in the `ak` of
// every message it writes, and in a hello to the conversation after it joins
// and after an account new to the conversation is added.
//
// The key is the account's, kept in the encrypted account store by the
// device that minted it. This device never mints or rotates it: it registers
// the store's key with SetAccessKey (the same key, so the server's copy
// doesn't change) and presents it only once that call succeeded. When the
// store holds another key (a block on the phone mints a new one), it follows.

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"time"

	"github.com/rs/zerolog"

	"github.com/collinjackson/peachy-go/pb"
)

const (
	accessKeyBytes = 16
	// A hello waits up to this long, so the hellos of one add don't leave
	// together.
	helloMaxDelay = 30 * time.Second
	helloRetry    = time.Minute
	helloGiveUp   = 24 * time.Hour
	hintImplicit  = 2
)

// owedHello is a hello this device owes a conversation, kept in device.json
// so a restart inside the wait still sends it.
type owedHello struct {
	DueMS    int64  `json:"due_ms"`
	SinceMS  int64  `json:"since_ms"` // its latest reason
	RetryKey string `json:"retry_key"`
}

// parseAccessKey reads an `ak` or accessKey: standard padded base64 of
// exactly 16 bytes, anything else nil.
func parseAccessKey(s string) []byte {
	if len(s) != 24 {
		return nil
	}
	b, err := base64.StdEncoding.Strict().DecodeString(s)
	if err != nil || len(b) != accessKeyBytes {
		return nil
	}
	return b
}

// adoptAccessKey registers the store's access key with the server and, once
// it holds it, presents it. Not called with d.mu held.
func (d *Device) adoptAccessKey(ctx context.Context, key []byte) {
	d.mu.Lock()
	same := bytes.Equal(key, d.accessKey)
	d.mu.Unlock()
	if same || key == nil {
		return
	}
	if _, err := call[pb.SetAccessKeyRequest, pb.SetAccessKeyResponse](ctx, d.rpc, "SetAccessKey",
		&pb.SetAccessKeyRequest{AccessKey: key}); err != nil {
		zerolog.Ctx(ctx).Warn().Err(err).Msg("Peachy: couldn't register the access key; members send to this device identified")
		return
	}
	d.mu.Lock()
	d.accessKey = bytes.Clone(key)
	d.mu.Unlock()
}

// setUpAccessKey reads the account store and adopts its access key. Not
// called with d.mu held.
func (d *Device) setUpAccessKey(ctx context.Context) {
	s, err := d.ReadStore(ctx)
	if err != nil {
		zerolog.Ctx(ctx).Warn().Err(err).Msg("Peachy: couldn't read the account store for the access key")
		return
	}
	if s.AccessKey == nil {
		zerolog.Ctx(ctx).Warn().Msg("Peachy: the account store holds no access key yet; members send to this device identified")
	}
}

// oweHello notes a hello owed to group. A second reason before the first
// hello went keeps the earlier time and takes a fresh retry key. Called with
// d.mu held.
func (d *Device) oweHello(group string, now time.Time) error {
	key, err := uuidV4()
	if err != nil {
		return err
	}
	if d.state.Hellos == nil {
		d.state.Hellos = map[string]*owedHello{}
	}
	if h := d.state.Hellos[group]; h != nil {
		h.SinceMS, h.RetryKey = now.UnixMilli(), key
	} else {
		wait, err := randBelow(uint64(helloMaxDelay / time.Millisecond))
		if err != nil {
			return err
		}
		d.state.Hellos[group] = &owedHello{DueMS: now.UnixMilli() + int64(wait), SinceMS: now.UnixMilli(), RetryKey: key}
	}
	return d.state.save(d.dir)
}

// sendHellos sends the hellos that are due. Not called with d.mu held.
func (d *Device) sendHellos(ctx context.Context, now time.Time) {
	d.mu.Lock()
	type due struct {
		group string
		h     owedHello
	}
	var todo []due
	for g, h := range d.state.Hellos {
		if h.DueMS <= now.UnixMilli() {
			todo = append(todo, due{g, *h})
		}
	}
	key := d.accessKey
	d.mu.Unlock()
	for _, t := range todo {
		var err error
		if key == nil {
			err = errNoAccessKey
		} else {
			err = d.sendHello(ctx, t.group, key, t.h.RetryKey)
		}
		d.mu.Lock()
		h := d.state.Hellos[t.group]
		switch {
		case h == nil:
		case err == nil && h.RetryKey == t.h.RetryKey:
			delete(d.state.Hellos, t.group)
		case err == nil:
			// A new reason came while it went: owe another, now.
		case now.Sub(time.UnixMilli(h.SinceMS)) > helloGiveUp:
			delete(d.state.Hellos, t.group)
		default:
			h.DueMS = now.Add(helloRetry).UnixMilli()
		}
		_ = d.state.save(d.dir)
		d.mu.Unlock()
		if err != nil && err != errNoAccessKey {
			zerolog.Ctx(ctx).Debug().Err(err).Str("conversation", t.group).Msg("Peachy: a hello didn't go; trying again in a minute")
		}
	}
}

type helloError string

func (e helloError) Error() string { return string(e) }

const errNoAccessKey = helloError("no access key the server holds yet")

// sendHello sends one hello to the whole conversation. A conversation that
// holds only this account is owed nothing.
func (d *Device) sendHello(ctx context.Context, group string, key []byte, retryKey string) error {
	d.mu.Lock()
	if d.mls == nil {
		d.mu.Unlock()
		return helloError("not connected")
	}
	me, _, err := d.mls.identity()
	var others bool
	if err == nil {
		roster, rerr := d.mls.roster([]byte(group))
		err = rerr
		for _, m := range roster {
			others = others || m.actorID != me
		}
	}
	d.mu.Unlock()
	if err != nil {
		if isMLSCode(err, mlsNoSuchGroup) {
			return nil // we left it
		}
		return err
	}
	if !others {
		return nil
	}
	wire, err := encodeHello(key)
	if err != nil {
		return err
	}
	// A hello carries the access key: never to a bot leaf.
	return d.sealHinted(ctx, group, wire, false, retryKey, nil, hintImplicit, botsNone)
}

func encodeHello(key []byte) ([]byte, error) {
	return json.Marshal(map[string]any{"peachy": "hello", "v": 1, "ak": base64.StdEncoding.EncodeToString(key)})
}

// parseHello reads a hello's access key, or nil for anything that isn't one.
func parseHello(plaintext []byte) []byte {
	fields, ok := strictObject(plaintext)
	if !ok {
		return nil
	}
	var kind, ak string
	if json.Unmarshal(fields["peachy"], &kind) != nil || kind != "hello" || string(fields["v"]) != "1" ||
		json.Unmarshal(fields["ak"], &ak) != nil {
		return nil
	}
	return parseAccessKey(ak)
}

// accountsAdded is whether after holds an account that before didn't, other
// than me: the commit that took the tree from one to the other owes a hello.
func accountsAdded(before, after []member, me string) bool {
	had := map[string]bool{}
	for _, m := range before {
		had[m.actorID] = true
	}
	for _, m := range after {
		if m.actorID != me && !had[m.actorID] {
			return true
		}
	}
	return false
}
