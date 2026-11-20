package peachy

// Group recovery: when this device's copy of a group fell behind or forked,
// the MLS engine decides whether to forget the group and ask back in
// (peachy-protocol's docs/mls-core.md, "Group recovery", and docs/delivery.md,
// "A message that will not open"). This file reads the heads it asks for and
// acts on its answer; it decides nothing by itself.

/*
#include <stdlib.h>
#include "peachy_mls.h"
*/
import "C"

import (
	"bytes"
	"context"
	"errors"
	"time"

	"github.com/rs/zerolog"

	"github.com/collinjackson/peachy-go/pb"
)

const (
	mlsStaleCopy = C.PEACHY_MLS_ERR_STALE_COPY

	headReadCheck       = C.PEACHY_MLS_HEAD_READ_CHECK
	headReadSealedAhead = C.PEACHY_MLS_HEAD_READ_SEALED_AHEAD
	headReadLost        = C.PEACHY_MLS_HEAD_READ_LOST

	recoveryReadHead      = C.PEACHY_MLS_RECOVERY_READ_HEAD
	recoveryReadAgain     = C.PEACHY_MLS_RECOVERY_READ_AGAIN
	recoveryRejoinForked  = C.PEACHY_MLS_RECOVERY_REJOIN_FORKED
	recoveryRejoinStuck   = C.PEACHY_MLS_RECOVERY_REJOIN_STUCK
	recoveryRejoinLost    = C.PEACHY_MLS_RECOVERY_REJOIN_LOST
	recoverySettleFirst   = C.PEACHY_MLS_RECOVERY_SETTLE_FIRST
	recoveryBackoff       = C.PEACHY_MLS_RECOVERY_BACKOFF
	maxSweepPages         = 1000
	sweepReuse            = 30 * time.Second
	conversationHandleLen = 32
	noGroupCheckEvery     = 10 * time.Minute
)

// errNoGroup is an envelope that opened for no group this device holds.
var errNoGroup = errors.New("an envelope that opened for no group")

func groupHandle(group []byte) ([]byte, error) {
	gp, gn := in(group)
	return oneBuffer(func(out *C.PeachyMlsBuffer) C.int32_t { return C.peachy_mls_group_handle(gp, gn, out) })
}

func (m *mlsClient) recoveryReadDue(group []byte, sealedAhead bool, now time.Time) (bool, error) {
	gp, gn := in(group)
	var due C.bool
	err := ffi(func() C.int32_t {
		return C.peachy_mls_group_recovery_read_due(m.c, gp, gn, C.bool(sealedAhead), C.int64_t(now.UnixMilli()), &due)
	})
	return bool(due), err
}

func (m *mlsClient) recoveryBegin(group []byte) (int, error) {
	gp, gn := in(group)
	var step C.uint32_t
	err := ffi(func() C.int32_t { return C.peachy_mls_group_recovery_begin(m.c, gp, gn, &step) })
	return int(step), err
}

func (m *mlsClient) recoveryJudge(group []byte, kind int, head *pb.ConversationHead, fresh bool, now time.Time) (int, error) {
	gp, gn := in(group)
	var epoch uint64
	var verifier []byte
	if head != nil {
		epoch, verifier = head.GetEpoch(), head.GetVerifier()
	}
	vp, vn := inOrEmpty(verifier)
	var step C.uint32_t
	err := ffi(func() C.int32_t {
		return C.peachy_mls_group_recovery_judge(m.c, gp, gn, C.uint32_t(kind), C.bool(head != nil),
			C.uint64_t(epoch), vp, vn, C.bool(fresh), C.int64_t(now.UnixMilli()), &step)
	})
	return int(step), err
}

// headSweep is one read of every head on the server (FetchConversationHead
// with every), by handle.
type headSweep struct {
	began time.Time
	heads map[string]*pb.ConversationHead
}

// sweepHeads reads every page of the sweep, as the protocol requires of a
// client that checks a group it didn't just commit to; it reuses a sweep for
// 30 seconds unless fresh. Called with d.mu held.
func (d *Device) sweepHeads(ctx context.Context, fresh bool) (*headSweep, error) {
	if !fresh && d.sweep != nil && time.Since(d.sweep.began) < sweepReuse {
		return d.sweep, nil
	}
	s := &headSweep{began: time.Now(), heads: map[string]*pb.ConversationHead{}}
	var after []byte
	for range maxSweepPages {
		page, err := call[pb.FetchConversationHeadRequest, pb.FetchConversationHeadResponse](ctx, d.rpc,
			"FetchConversationHead", &pb.FetchConversationHeadRequest{Every: true, After: after})
		if err != nil {
			return nil, err
		}
		for _, h := range page.GetHeads() {
			s.heads[string(h.GetHandle())] = h
		}
		heads := page.GetHeads()
		if !page.GetMore() || len(heads) == 0 {
			break
		}
		after = heads[len(heads)-1].GetHandle()
		if len(after) != conversationHandleLen {
			break
		}
	}
	d.sweep = s
	return s, nil
}

// recoverGroup asks the engine whether this copy of group must be forgotten
// and asked back into, reading the head it wants, and rejoins only when it
// says so. kind is a headRead* value. Called with d.mu held, after the
// mailbox page is acknowledged.
func (d *Device) recoverGroup(ctx context.Context, group string, kind int) {
	log := zerolog.Ctx(ctx).With().Str("group", group).Logger()
	g := []byte(group)
	handle, err := groupHandle(g)
	if err != nil {
		log.Warn().Err(err).Msg("Peachy: couldn't derive a group's handle")
		return
	}
	step, fresh := recoveryReadAgain, false
	for range 2 { // a read, and one fresh read again when the engine asks
		if step, err = d.mls.recoveryBegin(g); err != nil || step != recoveryReadHead {
			if err != nil {
				log.Warn().Err(err).Msg("Peachy: couldn't begin a head read")
			}
			return
		}
		begun := time.Now()
		sweep, err := d.sweepHeads(ctx, fresh)
		if err != nil {
			log.Warn().Err(err).Msg("Peachy: couldn't read the conversation heads")
			return
		}
		head := sweep.heads[string(handle)]
		if head != nil && !bytes.Equal(head.GetHandle(), handle) {
			head = nil
		}
		if step, err = d.mls.recoveryJudge(g, kind, head, !sweep.began.Before(begun), time.Now()); err != nil {
			log.Warn().Err(err).Msg("Peachy: couldn't judge a group's head")
			return
		}
		if step != recoveryReadAgain {
			break
		}
		fresh = true
	}
	switch step {
	case recoveryRejoinForked, recoveryRejoinStuck, recoveryRejoinLost:
		log.Error().Int("step", step).Msg("Peachy: this device's copy of the group fell behind or forked; " +
			"forgetting it and asking the members to seat this device again")
		if err := d.rejoin(ctx, group, nil); err != nil {
			log.Error().Err(err).Msg("Peachy: couldn't rejoin the group; the engine will ask again")
		}
	case recoverySettleFirst, recoveryBackoff:
		log.Info().Int("step", step).Msg("Peachy: a group's copy isn't in step; the engine says wait")
	}
}

// checkAllGroups judges every group this device holds against its head,
// as the protocol asks after a lost mailbox. Called with d.mu held.
func (d *Device) checkAllGroups(ctx context.Context, kind int) {
	groups, err := d.mls.groupIDs()
	if err != nil {
		zerolog.Ctx(ctx).Warn().Err(err).Msg("Peachy: couldn't list groups to check against their heads")
		return
	}
	for _, g := range groups {
		d.recoverGroup(ctx, string(g), kind)
	}
}
