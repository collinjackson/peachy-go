package peachy

// Writing the account store, as Peachy's apps do (their account-store
// writer): read everything, drop the merge's losers, replace the subject's
// records with one fresh record, and swap in a manifest one version on. A
// record this build can't open is another build's: it stays in the manifest
// and is never deleted. Another device writing first is a conflict; re-read
// and apply the change again on top.

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/collinjackson/peachy-go/pb"
)

const maxStoreWrites = 5

// The record kinds this build reads, as Peachy's apps list them. Any other
// kind is a newer build's, kept untouched.
var storeKinds = []string{"contact", "chat", "account", "callLink"}

// Accept lets someone in, as answering their message request does: their
// contact record gets accepted, and the chat is no longer a request on this
// account's devices.
func (d *Device) Accept(ctx context.Context, actor string) error {
	return d.patchStore(ctx, "contact", actor, func(v map[string]json.RawMessage) map[string]json.RawMessage {
		v["accepted"] = json.RawMessage("true")
		return v
	})
}

type storeEntry struct {
	kind, key string
	at        int64
	value     map[string]json.RawMessage
}

// patchStore changes one subject's value. A patch that changes nothing
// writes nothing; one that leaves the value empty removes the subject.
func (d *Device) patchStore(ctx context.Context, kind, key string, patch func(map[string]json.RawMessage) map[string]json.RawMessage) error {
	d.mu.Lock()
	accountKey, err := d.state.accountKey()
	d.mu.Unlock()
	if err != nil || accountKey == nil {
		return errors.New("not linked yet")
	}
	for range maxStoreWrites {
		resp, err := call[pb.ReadStoreRequest, pb.ReadStoreResponse](ctx, d.rpc, "ReadStore", &pb.ReadStoreRequest{})
		if err != nil {
			return err
		}
		d.mu.Lock()
		err = d.checkFloor(accountKey, resp.GetVersion())
		d.mu.Unlock()
		if err != nil {
			return err
		}
		if resp.GetVersion() == 0 {
			// The account's first device writes the first manifest.
			return errors.New("this account's settings store isn't set up yet")
		}
		live, opaque, err := readEntries(accountKey, resp)
		if err != nil {
			return err
		}

		// The merge's losers go in this write too.
		deletes := map[string]bool{}
		type best struct {
			id string
			at int64
		}
		newest := map[[2]string]best{}
		for id, e := range live {
			s := [2]string{e.kind, e.key}
			if b, ok := newest[s]; !ok || e.at > b.at || e.at == b.at && id > b.id {
				if ok {
					deletes[b.id] = true
				}
				newest[s] = best{id, e.at}
			} else {
				deletes[id] = true
			}
		}

		subject := [2]string{kind, key}
		current := map[string]json.RawMessage{}
		var prevAt int64
		if b, ok := newest[subject]; ok {
			for k, v := range live[b.id].value {
				current[k] = v
			}
			prevAt = b.at
		}
		before, _ := json.Marshal(current)
		next := patch(current)
		after, _ := json.Marshal(next)
		if bytes.Equal(before, after) {
			return nil
		}
		for id, e := range live {
			if e.kind == kind && e.key == key {
				deletes[id] = true
			}
		}
		var upserts []*pb.StoreRecord
		var ids []string
		for id := range live {
			if !deletes[id] {
				ids = append(ids, id)
			}
		}
		if len(next) > 0 {
			id := make([]byte, 16)
			for {
				if _, err := rand.Read(id); err != nil {
					return err
				}
				h := hex.EncodeToString(id)
				if _, taken := live[h]; !taken && !opaque[h] && !bytes.Equal(id, manifestID) {
					break
				}
			}
			at := max(time.Now().UnixMilli(), prevAt+1)
			// Keys in the apps' order.
			plain, err := json.Marshal(struct {
				Kind  string                     `json:"kind"`
				Key   string                     `json:"key"`
				At    int64                      `json:"at"`
				Value map[string]json.RawMessage `json:"value"`
			}{kind, key, at, next})
			if err != nil {
				return err
			}
			sealed, err := storeSeal(accountKey, id, plain)
			if err != nil {
				return err
			}
			upserts = append(upserts, &pb.StoreRecord{Id: id, Value: sealed})
			ids = append(ids, hex.EncodeToString(id))
		}
		for id := range opaque {
			ids = append(ids, id)
		}
		slices.Sort(ids)
		ids = slices.Compact(ids)
		version := resp.GetVersion()
		manifest, err := json.Marshal(struct {
			Version int64    `json:"version"`
			IDs     []string `json:"ids"`
		}{version + 1, ids})
		if err != nil {
			return err
		}
		sealedManifest, err := storeSeal(accountKey, manifestID, manifest)
		if err != nil {
			return err
		}
		var dels [][]byte
		for id := range deletes {
			b, _ := hex.DecodeString(id)
			dels = append(dels, b)
		}
		w, err := call[pb.WriteStoreRequest, pb.WriteStoreResponse](ctx, d.rpc, "WriteStore", &pb.WriteStoreRequest{
			ExpectedVersion: version, Manifest: sealedManifest, Upserts: upserts, Deletes: dels,
		})
		if err != nil {
			return err
		}
		if !w.GetConflict() {
			d.mu.Lock()
			d.store = nil // re-read on next use
			err := d.raiseFloor(accountKey, version+1)
			d.mu.Unlock()
			return err
		}
	}
	return fmt.Errorf("the settings store kept changing under this write")
}

// readEntries opens every live record. Those that don't open, or that the
// read didn't return, are opaque: kept, never deleted.
func readEntries(accountKey []byte, resp *pb.ReadStoreResponse) (live map[string]storeEntry, opaque map[string]bool, err error) {
	plain, err := storeOpen(accountKey, manifestID, resp.GetManifest())
	if err != nil {
		return nil, nil, fmt.Errorf("open the store's manifest: %w", err)
	}
	var manifest struct {
		Version int64    `json:"version"`
		IDs     []string `json:"ids"`
	}
	if err := json.Unmarshal(plain, &manifest); err != nil {
		return nil, nil, fmt.Errorf("read the store's manifest: %w", err)
	}
	if manifest.Version != resp.GetVersion() {
		return nil, nil, fmt.Errorf("the store's manifest is version %d, not %d", manifest.Version, resp.GetVersion())
	}
	opaque = map[string]bool{}
	for _, id := range manifest.IDs {
		opaque[id] = true
	}
	live = map[string]storeEntry{}
	for _, r := range resp.GetRecords() {
		id := hex.EncodeToString(r.GetId())
		if !opaque[id] {
			continue
		}
		plain, err := storeOpen(accountKey, r.GetId(), r.GetValue())
		if err != nil {
			continue
		}
		var rec struct {
			Kind  string                     `json:"kind"`
			Key   string                     `json:"key"`
			At    *float64                   `json:"at"`
			Value map[string]json.RawMessage `json:"value"`
		}
		if json.Unmarshal(plain, &rec) != nil || !slices.Contains(storeKinds, rec.Kind) || rec.At == nil || rec.Value == nil {
			continue
		}
		delete(opaque, id)
		live[id] = storeEntry{rec.Kind, rec.Key, int64(*rec.At), rec.Value}
	}
	return live, opaque, nil
}
