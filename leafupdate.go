package peachy

// The leaf self-update (peachy-protocol's docs/bots.md, "The chat's bot
// keys", "The leaf self-update"). 0xF1AB appears on this device's leaf only
// once it sends a leaf a 0.3.0 core made, and a group can seat a bot only
// when every leaf lists it. So in each group whose own leaf lacks it, this
// device sends one ordinary MLS self-update: 0 to 60 seconds after joining,
// and once after the first launch of a build that reads bots, spread over
// twelve hours by device and group (leafUpdateDue). Opening a chat triggers
// nothing. Cases: mls/fixtures/formats/bot-addressing.json (leafUpdate,
// leafUpdateDue).

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"time"

	"connectrpc.com/connect"
	"github.com/rs/zerolog"
)

const (
	firstLaunchSpread = 12 * time.Hour   // firstLaunchSpreadSeconds
	leafUpdateJitter  = 60 * time.Second // leafUpdateJitterSeconds
	leafUpdateLate    = 10 * time.Minute // leafUpdateLateSeconds
	leafUpdateRetry   = 10 * time.Minute
)

// leafUpdateDue is when a group's update is due, Unix seconds: on a join,
// when the Welcome was taken (seenAt); on a first launch, sweptAt plus the
// first four bytes of SHA-256(deviceID || 0x00 || groupID), big-endian, mod
// the spread.
func leafUpdateDue(firstLaunch bool, deviceID, groupID string, sweptAt, seenAt int64) int64 {
	if !firstLaunch {
		return seenAt
	}
	sum := sha256.Sum256([]byte(deviceID + "\x00" + groupID))
	return sweptAt + int64(binary.BigEndian.Uint32(sum[:4])%uint32(firstLaunchSpread/time.Second))
}

// jitter is a random wait below max, in seconds. A variable for tests.
var jitter = defaultJitter

func defaultJitter(max time.Duration) int64 {
	n, err := randBelow(uint64(max / time.Second))
	if err != nil {
		return 0
	}
	return int64(n)
}

// leafStaleForTest, when set, makes a test's own leaf read as lacking
// 0xF1AB: this core's leaves always list it, and only an older core makes
// one that doesn't.
var leafStaleForTest func(group string) bool

// ownLeafAware is whether this device's leaf in group lists 0xF1AB; found
// is false when it holds none there. Called with d.mu held.
func (d *Device) ownLeafAware(group []byte) (aware, found bool, err error) {
	roster, err := d.mls.roster(group)
	if err != nil {
		return false, false, err
	}
	for _, m := range roster {
		if m.deviceID == d.state.DeviceID {
			if leafStaleForTest != nil && leafStaleForTest(string(group)) {
				return false, true, nil
			}
			return m.botAware, true, nil
		}
	}
	return false, false, nil
}

// oweLeafUpdate schedules group's update at due (Unix seconds) plus the
// jitter, unless its own leaf already lists 0xF1AB or one is already owed.
// Called with d.mu held; the caller saves the state.
func (d *Device) oweLeafUpdate(group []byte, due int64) {
	if _, owed := d.state.LeafUpdates[string(group)]; owed {
		return
	}
	if aware, found, err := d.ownLeafAware(group); err != nil || !found || aware {
		return
	}
	if d.state.LeafUpdates == nil {
		d.state.LeafUpdates = map[string]int64{}
	}
	d.state.LeafUpdates[string(group)] = due + jitter(leafUpdateJitter)
}

// sweepLeaves runs once per process, after the store opens: on this build's
// first launch it owes every group's update, spread; on a later one, an
// update whose time passed while the device was closed goes 0 to 10
// minutes after now. Called with d.mu held.
func (d *Device) sweepLeaves(now time.Time) error {
	groups, err := d.mls.groupIDs()
	if err != nil {
		return err
	}
	if d.state.LeafSweptAt == 0 {
		d.state.LeafSweptAt = now.Unix()
		for _, g := range groups {
			d.oweLeafUpdate(g, leafUpdateDue(true, d.state.DeviceID, string(g), d.state.LeafSweptAt, 0))
		}
	} else {
		for g, due := range d.state.LeafUpdates {
			if due < now.Unix() {
				d.state.LeafUpdates[g] = now.Unix() + jitter(leafUpdateLate)
			}
		}
	}
	return d.state.save(d.dir)
}

// sendLeafUpdates sends the updates that are due. Not called with d.mu held.
func (d *Device) sendLeafUpdates(ctx context.Context, now time.Time) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.mls == nil {
		return
	}
	changed := false
	for g, due := range d.state.LeafUpdates {
		if due > now.Unix() {
			continue
		}
		group := []byte(g)
		aware, found, err := d.ownLeafAware(group)
		if err != nil || !found || aware {
			// Gone from the group, or its leaf already lists it.
			delete(d.state.LeafUpdates, g)
			changed = true
			continue
		}
		log := zerolog.Ctx(ctx).With().Str("conversation", g).Logger()
		if err := d.selfUpdateLocked(ctx, group); err != nil {
			wait := leafUpdateRetry
			if connect.CodeOf(err) == connect.CodeFailedPrecondition {
				// The head moved: the next drain catches up, then it goes again.
				wait = leafUpdateJitter
			}
			d.state.LeafUpdates[g] = now.Add(wait).Unix() + jitter(leafUpdateJitter)
			log.Debug().Err(err).Msg("Peachy: a leaf update didn't go; trying again later")
		} else {
			delete(d.state.LeafUpdates, g)
			log.Info().Msg("Peachy: sent this device's leaf update (bot support) to a conversation")
		}
		changed = true
	}
	if changed {
		_ = d.state.save(d.dir)
	}
}

// selfUpdateLocked commits a new leaf of this device's own. Called with
// d.mu held.
func (d *Device) selfUpdateLocked(ctx context.Context, group []byte) error {
	commit, err := d.mls.stageSelfUpdate(group)
	if err != nil {
		d.mls.clearPending(group)
		return err
	}
	return d.submitLocked(ctx, group, commit, nil, false)
}
