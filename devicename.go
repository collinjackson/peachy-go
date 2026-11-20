package peachy

import (
	"context"
	"encoding/json"

	"github.com/rs/zerolog"

	"github.com/collinjackson/peachy-go/pb"
)

// maxDeviceName is the longest name account.deviceNames holds, in characters.
const maxDeviceName = 120

// nameSelf writes this device's name into the account store, the only place
// Peachy keeps device names (account.deviceNames in peachy-protocol's
// docs/account-store.md): under this device's row ids, dropping entries for
// rows no longer on the account's device list. Best effort: a device with no
// entry is shown by its platform.
func (d *Device) nameSelf(ctx context.Context) {
	if d.name == "" {
		return
	}
	list, err := call[pb.ListDevicesRequest, pb.ListDevicesResponse](ctx, d.rpc, "ListDevices", &pb.ListDevicesRequest{})
	if err != nil {
		zerolog.Ctx(ctx).Warn().Err(err).Msg("Peachy: couldn't list devices to name this one")
		return
	}
	d.mu.Lock()
	me := d.state.DeviceID
	d.mu.Unlock()
	mine, live := ownRows(me, list.GetDevices())
	name := []rune(d.name)
	if len(name) > maxDeviceName {
		name = name[:maxDeviceName]
	}
	err = d.patchStore(ctx, "account", "", func(v map[string]json.RawMessage) map[string]json.RawMessage {
		v["deviceNames"] = renamed(v["deviceNames"], mine, live, string(name))
		return v
	})
	if err != nil {
		zerolog.Ctx(ctx).Warn().Err(err).Msg("Peachy: couldn't write this device's name to the account store")
	}
}

// ownRows is this device's row ids (its own and any twin) and every live row
// id on the account.
func ownRows(me string, devices []*pb.Device) (mine []string, live map[string]bool) {
	live = map[string]bool{}
	twin := ""
	for _, dev := range devices {
		if dev.GetRevokedAt() != nil {
			continue
		}
		live[dev.GetId()] = true
		if dev.GetId() == me {
			twin = dev.GetTwinOf()
		}
	}
	mine = []string{me}
	if twin != "" && live[twin] {
		mine = append(mine, twin)
	}
	for _, dev := range devices {
		if live[dev.GetId()] && dev.GetTwinOf() == me && dev.GetId() != me {
			mine = append(mine, dev.GetId())
		}
	}
	return mine, live
}

// renamed is the deviceNames object with name under each of mine and the
// entries of rows not in live dropped. Entries it doesn't understand are kept
// as they are, unless their row is gone.
func renamed(raw json.RawMessage, mine []string, live map[string]bool, name string) json.RawMessage {
	names := map[string]json.RawMessage{}
	_ = json.Unmarshal(raw, &names) // not an object: start over
	for id := range names {
		if !live[id] {
			delete(names, id)
		}
	}
	quoted, _ := json.Marshal(name)
	for _, id := range mine {
		names[id] = quoted
	}
	out, _ := json.Marshal(names)
	return out
}
