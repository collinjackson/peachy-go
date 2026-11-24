package peachy

// Commits this device makes and submits: its own leaf updates (leafupdate.go)
// and, in tests, a founder's adds and removals (testgroup.go). Each is
// stamped as the core says (peachy-protocol's docs/delivery.md,
// "SubmitCommit", "Commit stamps", "Own-scope commits").

/*
#include <stdlib.h>
#include "peachy_mls.h"
*/
import "C"

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"unsafe"

	"connectrpc.com/connect"

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

func (m *mlsClient) merge(group []byte) error {
	p, n := in(group)
	var epoch C.uint64_t
	return ffi(func() C.int32_t { return C.peachy_mls_group_merge_pending_commit(m.c, p, n, &epoch) })
}

func (m *mlsClient) clearPending(group []byte) {
	gp, gn := in(group)
	_ = ffi(func() C.int32_t { return C.peachy_mls_group_clear_pending_commit(m.c, gp, gn) })
}

// stageSelfUpdate stages a commit of this device's own new leaf, made by
// this core, so it lists what this build advertises.
func (m *mlsClient) stageSelfUpdate(group []byte) ([]byte, error) {
	gp, gn := in(group)
	return oneBuffer(func(out *C.PeachyMlsBuffer) C.int32_t { return C.peachy_mls_group_self_update(m.c, gp, gn, out) })
}

// stamp is the core's answer for a staged commit: the admin stamp it takes
// (nil for none), the handle's new stamp set when the commit changes it, and
// own for an unstamped own-scope commit on a governed handle.
type stamp struct {
	stamp []byte
	set   [][]byte
	own   bool
}

// commitStamp asks the core how to submit the commit staged in group, as
// the bytes submitted carry it.
func (m *mlsClient) commitStamp(group, submitted []byte) (stamp, error) {
	gp, gn := in(group)
	sp, sn := in(submitted)
	raw, err := oneBuffer(func(out *C.PeachyMlsBuffer) C.int32_t {
		return C.peachy_mls_group_commit_stamp(m.c, gp, gn, sp, sn, out)
	})
	if err != nil {
		return stamp{}, err
	}
	return parseStamp(raw)
}

func parseStamp(raw []byte) (stamp, error) {
	var answer struct {
		Stamp *string  `json:"stamp"`
		Set   []string `json:"set"`
		Own   bool     `json:"own"`
	}
	if err := json.Unmarshal(raw, &answer); err != nil {
		return stamp{}, fmt.Errorf("the core's commit stamp: %w", err)
	}
	var s stamp
	s.own = answer.Own
	if answer.Stamp != nil {
		b, err := base64.RawURLEncoding.DecodeString(*answer.Stamp)
		if err != nil || len(b) != 64 {
			return stamp{}, errors.New("the core's commit stamp isn't 64 bytes of base64url")
		}
		s.stamp = b
	}
	for _, k := range answer.Set {
		b, err := base64.RawURLEncoding.DecodeString(k)
		if err != nil || len(b) != 32 {
			return stamp{}, errors.New("a key of the core's stamp set isn't 32 bytes of base64url")
		}
		s.set = append(s.set, b)
	}
	return s, nil
}

// submitLocked submits a staged commit, wrapped at the epoch it was built
// in and stamped as the core says, to every device in the tree before it
// (none for a founding's), and merges it once taken. A refusal clears it;
// a call that failed without an answer is settled by the head first.
// Called with d.mu held.
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
	st, err := d.mls.commitStamp(group, wrapped)
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
	sort.Slice(welcomes, func(i, j int) bool { return welcomes[i].RecipientDeviceId < welcomes[j].RecipientDeviceId })
	req := &pb.SubmitCommitRequest{
		Handle: handle, Epoch: epoch, Commit: wrapped, SendKey: sendKey, NextVerifier: nextVerifier[:],
		Recipients: recipients, Welcomes: welcomes, Stamp: st.stamp, StampSet: st.set,
	}
	if st.own {
		req.Scope = pb.CommitScope_COMMIT_SCOPE_OWN
	}
	d.rememberSent(wrapped, nowFunc())
	if _, err = call[pb.SubmitCommitRequest, pb.SubmitCommitResponse](ctx, d.rpc, "SubmitCommit", req); err != nil {
		if answerLost(err) && d.headTook(ctx, handle, epoch+1, nextVerifier[:]) {
			return d.mls.merge(group)
		}
		return fail(err)
	}
	return d.mls.merge(group)
}

// answerLost is a call that failed without the server's answer: the commit
// may have been taken.
func answerLost(err error) bool {
	switch connect.CodeOf(err) {
	case connect.CodeUnknown, connect.CodeUnavailable, connect.CodeDeadlineExceeded, connect.CodeCanceled:
		return true
	}
	return false
}

// headTook is whether the server's head for handle stands at epoch under
// verifier: a commit whose answer was lost was taken.
func (d *Device) headTook(ctx context.Context, handle []byte, epoch uint64, verifier []byte) bool {
	resp, err := call[pb.FetchConversationHeadRequest, pb.FetchConversationHeadResponse](context.WithoutCancel(ctx), d.rpc,
		"FetchConversationHead", &pb.FetchConversationHeadRequest{Handles: [][]byte{handle}})
	if err != nil {
		return false
	}
	for _, h := range resp.GetHeads() {
		if bytes.Equal(h.GetHandle(), handle) {
			return h.GetEpoch() == epoch && bytes.Equal(h.GetVerifier(), verifier)
		}
	}
	return false
}
