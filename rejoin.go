package peachy

// Getting back into a group whose copy fell off the ratchet, as Peachy's
// protocol has a device do it (delivery.md §Rejoin with a sealed seat ask):
// remember the leaves it last saw, forget the group, and send them a signed
// seat ask. A member's device that drains the ask seats this device again, and
// its Welcome lands in the mailbox like any other. Asks repeat, doubling from
// 10 minutes up to 6 hours, until it does.

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"time"

	"github.com/rs/zerolog"

	"github.com/collinjackson/peachy-go/pb"
)

const (
	envelopeSeatAsk = 3
	rejoinFile      = "rejoins.json"
	rejoinFirstWait = 10 * time.Minute
	rejoinMaxWait   = 6 * time.Hour
)

// Recipient is one device of a group, as a seat ask is addressed.
type Recipient struct {
	User   string `json:"user"`
	Device string `json:"device"`
}

// rejoin is a group this device forgot and asked to be seated in again.
type rejoin struct {
	Recipients []Recipient `json:"recipients"`
	SinceMS    int64       `json:"since_ms"`
	Asks       int         `json:"asks"`
	NextMS     int64       `json:"next_ms"`
}

// rejoinWait is how long to wait after the asks-th ask before the next.
func rejoinWait(asks int) time.Duration {
	w := rejoinFirstWait
	for i := 1; i < asks && w < rejoinMaxWait; i++ {
		w *= 2
	}
	return min(w, rejoinMaxWait)
}

func loadRejoins(dir string) (map[string]*rejoin, error) {
	b, err := os.ReadFile(filepath.Join(dir, rejoinFile))
	if errors.Is(err, fs.ErrNotExist) {
		return map[string]*rejoin{}, nil
	} else if err != nil {
		return nil, err
	}
	m := map[string]*rejoin{}
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, fmt.Errorf("%s: %w", rejoinFile, err)
	}
	return m, nil
}

func saveRejoins(dir string, m map[string]*rejoin) error {
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	tmp := filepath.Join(dir, rejoinFile+".tmp")
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(dir, rejoinFile))
}

// loadedRejoins reads rejoins.json once. Called with d.mu held.
func (d *Device) loadedRejoins() (map[string]*rejoin, error) {
	if d.rejoins == nil {
		m, err := loadRejoins(d.dir)
		if err != nil {
			return nil, err
		}
		d.rejoins = m
	}
	return d.rejoins, nil
}

// Rejoin forgets the group and asks its members to seat this device again.
// For a group this device still holds, the ask goes to the leaves of its copy
// and to is ignored; for one it already forgot, to the devices named in to, or
// else to those of an earlier Rejoin. RetryRejoins repeats the ask until a
// Welcome seats it.
func (d *Device) Rejoin(ctx context.Context, group string, to []Recipient) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.rejoin(ctx, group, to)
}

// rejoin is Rejoin with d.mu held.
func (d *Device) rejoin(ctx context.Context, group string, to []Recipient) error {
	if d.mls == nil {
		return errors.New("not connected")
	}
	rejoins, err := d.loadedRejoins()
	if err != nil {
		return err
	}
	held, err := d.holds(group)
	if err != nil {
		return err
	}
	r := &rejoin{SinceMS: time.Now().UnixMilli()}
	if held {
		// The leaves, remembered before the forget: nothing names them after.
		if r.Recipients, err = d.others(group); err != nil {
			return err
		}
	} else if len(to) > 0 {
		r.Recipients = to
	} else if old := rejoins[group]; old != nil {
		r = old
	}
	if len(r.Recipients) == 0 {
		return fmt.Errorf("no devices to ask for a seat in %s", group)
	}
	if held {
		// Refused (SETTLE_FIRST) while a commit is saved: then nothing changed.
		if err := d.mls.forget([]byte(group)); err != nil {
			return fmt.Errorf("forgetting %s: %w", group, err)
		}
	}
	rejoins[group] = r
	if err := saveRejoins(d.dir, rejoins); err != nil {
		return err
	}
	zerolog.Ctx(ctx).Warn().Str("group", group).Int("devices", len(r.Recipients)).
		Msg("Peachy: forgot a group copy that fell behind; asking its members to seat this device again")
	return d.askSeat(ctx, group, r)
}

// Roster is the group's devices other than this one: whom a seat ask goes to.
func (d *Device) Roster(group string) ([]Recipient, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.mls == nil {
		return nil, errors.New("not connected")
	}
	return d.others(group)
}

// others is Roster with d.mu held.
func (d *Device) others(group string) ([]Recipient, error) {
	roster, err := d.mls.roster([]byte(group))
	if err != nil {
		return nil, err
	}
	var out []Recipient
	for _, m := range roster {
		if m.deviceID != d.state.DeviceID {
			out = append(out, Recipient{User: m.actorID, Device: m.deviceID})
		}
	}
	return out, nil
}

// holds says whether this device has a copy of the group. Called with d.mu held.
func (d *Device) holds(group string) (bool, error) {
	ids, err := d.mls.groupIDs()
	if err != nil {
		return false, err
	}
	return slices.ContainsFunc(ids, func(id []byte) bool { return string(id) == group }), nil
}

// seatAsk is the inner bytes of a seat ask: {"d","a","p"}, the proof in
// standard padded base64.
func seatAsk(deviceID, actorID string, proof []byte) ([]byte, error) {
	return json.Marshal(map[string]string{"d": deviceID, "a": actorID, "p": base64.StdEncoding.EncodeToString(proof)})
}

// askSeat sends one signed seat ask and schedules the next. Not urgent: an
// ask is no message. Called with d.mu held.
func (d *Device) askSeat(ctx context.Context, group string, r *rejoin) error {
	r.Asks++
	r.NextMS = time.Now().Add(rejoinWait(r.Asks)).UnixMilli()
	err := d.sendSeatAsk(ctx, group, r)
	if serr := saveRejoins(d.dir, d.rejoins); err == nil {
		err = serr
	}
	l := zerolog.Ctx(ctx).Info()
	if err != nil {
		l = zerolog.Ctx(ctx).Warn().Err(err)
	}
	l.Str("group", group).Int("ask", r.Asks).Time("next", time.UnixMilli(r.NextMS)).Msg("Peachy: asked for a seat")
	return err
}

func (d *Device) sendSeatAsk(ctx context.Context, group string, r *rejoin) error {
	actor, device, err := d.mls.identity()
	if err != nil {
		return err
	}
	proof, err := d.mls.signJoinRequest([]byte(group))
	if err != nil {
		return err
	}
	inner, err := seatAsk(device, actor, proof)
	if err != nil {
		return err
	}
	payload, err := d.mls.sealEnvelope([]byte(group), envelopeSeatAsk, inner)
	if err != nil {
		return err
	}
	clientID, err := uuidV4()
	if err != nil {
		return err
	}
	var recipients []*pb.SealedRecipient
	for _, to := range r.Recipients {
		recipients = append(recipients, &pb.SealedRecipient{UserId: to.User, DeviceId: to.Device})
	}
	sent, err := call[pb.SendSealedRequest, pb.SendSealedResponse](ctx, d.rpc, "SendSealed", &pb.SendSealedRequest{
		Payload: payload, Urgent: false, ClientMessageId: clientID, Recipients: recipients,
	})
	if err != nil {
		return err
	}
	// Devices that are gone get no more asks, as long as one is left to ask.
	if stale := sent.GetStaleDeviceIds(); len(stale) > 0 {
		left := slices.DeleteFunc(slices.Clone(r.Recipients), func(to Recipient) bool { return slices.Contains(stale, to.Device) })
		if len(left) > 0 {
			r.Recipients = left
		}
	}
	return nil
}

// RetryRejoins asks again in each group whose wait is over, and drops the
// groups a Welcome has seated this device in since. Call it every minute or so.
func (d *Device) RetryRejoins(ctx context.Context) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.mls == nil {
		return
	}
	rejoins, err := d.loadedRejoins()
	if err != nil {
		zerolog.Ctx(ctx).Warn().Err(err).Msg("Peachy: couldn't read the groups waiting for a seat")
		return
	}
	now := time.Now().UnixMilli()
	for group, r := range rejoins {
		if held, err := d.holds(group); err != nil {
			return
		} else if held {
			d.rejoined(ctx, group)
		} else if now >= r.NextMS {
			_ = d.askSeat(ctx, group, r)
		}
	}
}

// rejoined drops the group's rejoin once a Welcome seated this device in it
// again. Called with d.mu held.
func (d *Device) rejoined(ctx context.Context, group string) {
	rejoins, err := d.loadedRejoins()
	if err != nil || rejoins[group] == nil {
		return
	}
	r := rejoins[group]
	delete(rejoins, group)
	if err := saveRejoins(d.dir, rejoins); err != nil {
		zerolog.Ctx(ctx).Warn().Err(err).Msg("Peachy: couldn't save the groups waiting for a seat")
	}
	zerolog.Ctx(ctx).Info().Str("group", group).Int("asks", r.Asks).
		Dur("after", time.Since(time.UnixMilli(r.SinceMS)).Round(time.Second)).Msg("Peachy: seated again in a group it had lost")
}
