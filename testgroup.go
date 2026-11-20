//go:build testissuer

package peachy

// Test-only: a Device founding a group and adding and removing members
// through a server, as a person's phone does, so integration tests (and the
// bridge's) can start conversations against a fake server
// (peachytest). peachy-go itself only joins conversations; this is not a
// complete founding: it seats each device with its own add commit rather
// than one seating commit, fetches every package with the session, and
// retries nothing (peachy-protocol's docs/delivery.md "Founding a
// conversation", "SubmitCommit").

/*
#include <stdlib.h>
#include "peachy_mls.h"
*/
import "C"

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sort"
	"unsafe"

	"github.com/collinjackson/peachy-go/pb"
)

const sendKeyLabel = "peachy sealed-sender v1"

func (m *mlsClient) exportSecret(group []byte, pending bool) ([]byte, error) {
	gp, gn := in(group)
	label := C.CString(sendKeyLabel)
	defer C.free(unsafe.Pointer(label))
	return oneBuffer(func(out *C.PeachyMlsBuffer) C.int32_t {
		if pending {
			return C.peachy_mls_group_export_pending_secret(m.c, gp, gn, label, gp, gn, 32, out)
		}
		return C.peachy_mls_group_export_secret(m.c, gp, gn, label, gp, gn, 32, out)
	})
}

func (m *mlsClient) epoch(group []byte) (uint64, error) {
	gp, gn := in(group)
	var e C.uint64_t
	err := ffi(func() C.int32_t { return C.peachy_mls_group_epoch(m.c, gp, gn, &e) })
	return uint64(e), err
}

func (m *mlsClient) setMeta(group, value []byte) ([]byte, error) {
	gp, gn := in(group)
	vp, vn := in(value)
	return oneBuffer(func(out *C.PeachyMlsBuffer) C.int32_t {
		return C.peachy_mls_group_set_meta(m.c, gp, gn, vp, vn, out)
	})
}

func (m *mlsClient) stageAdd(group, keyPackage []byte) (commit, welcome []byte, err error) {
	gp, gn := in(group)
	kp, kn := in(keyPackage)
	var c, w C.PeachyMlsBuffer
	if err := ffi(func() C.int32_t { return C.peachy_mls_group_add_member(m.c, gp, gn, kp, kn, &c, &w) }); err != nil {
		return nil, nil, err
	}
	return take(&c), take(&w), nil
}

func (m *mlsClient) stageRemove(group []byte, leaf uint32, leafKey []byte) ([]byte, error) {
	gp, gn := in(group)
	lp, ln := in(leafKey)
	return oneBuffer(func(out *C.PeachyMlsBuffer) C.int32_t {
		return C.peachy_mls_group_remove_member(m.c, gp, gn, C.uint32_t(leaf), lp, ln, out)
	})
}

func (m *mlsClient) clearPending(group []byte) {
	gp, gn := in(group)
	_ = ffi(func() C.int32_t { return C.peachy_mls_group_clear_pending_commit(m.c, gp, gn) })
}

type leaf struct {
	index         uint32
	actor, device string
	key           []byte
}

func (m *mlsClient) leaves(group []byte) ([]leaf, error) {
	gp, gn := in(group)
	var count C.uintptr_t
	if err := ffi(func() C.int32_t { return C.peachy_mls_group_member_count(m.c, gp, gn, &count) }); err != nil {
		return nil, err
	}
	var out []leaf
	for i := C.uintptr_t(0); i < count; i++ {
		var idx, rejection C.uint32_t
		var a, d, k, lk C.PeachyMlsBuffer
		if err := ffi(func() C.int32_t {
			return C.peachy_mls_group_member(m.c, gp, gn, i, &idx, &a, &d, &k, &lk, &rejection)
		}); err != nil {
			return nil, err
		}
		take(&k)
		out = append(out, leaf{index: uint32(idx), actor: string(take(&a)), device: string(take(&d)), key: take(&lk)})
	}
	return out, nil
}

// FoundGroupForTest founds a conversation with the accounts in others:
// named, with this account as its admin, or with dm a direct chat (no
// name; every member an admin). It returns the conversation id. Built only
// with -tags testissuer.
func (d *Device) FoundGroupForTest(ctx context.Context, name string, dm bool, others []string) (string, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.mls == nil {
		return "", errors.New("not connected")
	}
	me, _, err := d.mls.identity()
	if err != nil {
		return "", err
	}
	gid, err := uuidV4()
	if err != nil {
		return "", err
	}
	group := []byte(gid)
	if err := d.mls.create(group); err != nil {
		return "", err
	}
	handle, err := groupHandle(group)
	if err != nil {
		return "", err
	}
	sendKey, err := d.mls.exportSecret(group, false)
	if err != nil {
		return "", err
	}
	verifier := sha256.Sum256(sendKey)
	if _, err := call[pb.CreateHandleRequest, pb.CreateHandleResponse](ctx, d.rpc, "CreateHandle",
		&pb.CreateHandleRequest{Handle: handle, Verifier: verifier[:]}); err != nil {
		return "", err
	}
	adm := []string{me}
	if dm {
		adm = append(adm, others...)
		sort.Strings(adm)
		adm = slices.Compact(adm)
		name = ""
	}
	meta := struct {
		V   int      `json:"v"`
		N   string   `json:"n"`
		Adm []string `json:"adm"`
		DM  bool     `json:"dm,omitempty"`
	}{1, name, adm, dm}
	value, err := json.Marshal(meta)
	if err != nil {
		return "", err
	}
	commit, err := d.mls.setMeta(group, value)
	if err != nil {
		return "", err
	}
	// The founding's first commit is addressed to nobody.
	if err := d.submitLocked(ctx, group, commit, nil, true); err != nil {
		return "", err
	}
	for _, actor := range others {
		if err := d.addLocked(ctx, group, actor); err != nil {
			return "", err
		}
	}
	return gid, nil
}

// AddMemberForTest adds every device of actor that has a key package to the
// conversation, one commit each. Built only with -tags testissuer.
func (d *Device) AddMemberForTest(ctx context.Context, conversation, actor string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.mls == nil {
		return errors.New("not connected")
	}
	return d.addLocked(ctx, []byte(conversation), actor)
}

// RemoveMemberForTest removes every leaf of actor from the conversation,
// one commit each. Built only with -tags testissuer.
func (d *Device) RemoveMemberForTest(ctx context.Context, conversation, actor string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.mls == nil {
		return errors.New("not connected")
	}
	group := []byte(conversation)
	ls, err := d.mls.leaves(group)
	if err != nil {
		return err
	}
	n := 0
	for _, l := range ls {
		if l.actor != actor {
			continue
		}
		commit, err := d.mls.stageRemove(group, l.index, l.key)
		if err != nil {
			return err
		}
		if err := d.submitLocked(ctx, group, commit, nil, false); err != nil {
			return err
		}
		n++
	}
	if n == 0 {
		return fmt.Errorf("%s holds no leaf here", actor)
	}
	return nil
}

func (d *Device) addLocked(ctx context.Context, group []byte, actor string) error {
	req := &pb.FetchKeyPackagesRequest{UserIds: []string{actor}}
	if me, _, _ := d.mls.identity(); me == actor {
		req.SkipDeviceIds = []string{d.state.DeviceID}
	}
	fetched, err := call[pb.FetchKeyPackagesRequest, pb.FetchKeyPackagesResponse](ctx, d.rpc, "FetchKeyPackages", req)
	if err != nil {
		return err
	}
	if len(fetched.GetKeyPackages()) == 0 {
		return fmt.Errorf("%s has no key packages", actor)
	}
	for _, kp := range fetched.GetKeyPackages() {
		commit, welcome, err := d.mls.stageAdd(group, kp.GetKeyPackage())
		if err != nil {
			return err
		}
		w := []*pb.MlsWelcome{{RecipientDeviceId: kp.GetDeviceId(), RecipientUserId: kp.GetUserId(), Welcome: welcome}}
		if err := d.submitLocked(ctx, group, commit, w, false); err != nil {
			return err
		}
	}
	return nil
}

// submitLocked submits a staged commit, wrapped at the epoch it was built
// in, to every device in the tree before it (none for a founding's), and
// merges it once taken; a refusal clears it. Called with d.mu held.
func (d *Device) submitLocked(ctx context.Context, group, commit []byte, welcomes []*pb.MlsWelcome, toNobody bool) error {
	fail := func(err error) error {
		d.mls.clearPending(group)
		return err
	}
	epoch, err := d.mls.epoch(group)
	if err != nil {
		return fail(err)
	}
	sendKey, err := d.mls.exportSecret(group, false)
	if err != nil {
		return fail(err)
	}
	next, err := d.mls.exportSecret(group, true)
	if err != nil {
		return fail(err)
	}
	nextVerifier := sha256.Sum256(next)
	wrapped, err := d.mls.sealEnvelope(group, envelopeCommit, commit)
	if err != nil {
		return fail(err)
	}
	handle, err := groupHandle(group)
	if err != nil {
		return fail(err)
	}
	var recipients []*pb.SealedRecipient
	if !toNobody {
		roster, err := d.mls.roster(group)
		if err != nil {
			return fail(err)
		}
		for _, m := range roster {
			recipients = append(recipients, &pb.SealedRecipient{UserId: m.actorID, DeviceId: m.deviceID})
		}
		sort.Slice(recipients, func(i, j int) bool { return recipients[i].DeviceId < recipients[j].DeviceId })
	}
	_, err = call[pb.SubmitCommitRequest, pb.SubmitCommitResponse](ctx, d.rpc, "SubmitCommit", &pb.SubmitCommitRequest{
		Handle: handle, Epoch: epoch, Commit: wrapped, SendKey: sendKey, NextVerifier: nextVerifier[:],
		Recipients: recipients, Welcomes: welcomes,
	})
	if err != nil {
		return fail(err)
	}
	return d.mls.merge(group)
}
