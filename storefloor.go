package peachy

// The account store's floor (peachy-protocol's docs/account-store.md, "The
// manifest"): the highest version this device has read or written under a
// store key. A ReadStore answer below it, version 0 included, is a replay or
// a rolled-back server, and is refused. Floors are kept per store key, under
// the id the reference clients use, and never forgotten.

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

// floorID files a store key's floor: the first 16 bytes of
// SHA-256("peachy store floor v1" || 0x00 || store key), in hex. The store
// key is the held account key's first 32 bytes, in either form.
func floorID(accountKey []byte) string {
	sum := sha256.Sum256(append([]byte("peachy store floor v1\x00"), accountKey[:32]...))
	return hex.EncodeToString(sum[:16])
}

// checkFloor refuses a store version below the floor. Called with d.mu held.
func (d *Device) checkFloor(accountKey []byte, version int64) error {
	if floor := d.state.StoreFloors[floorID(accountKey)]; version < floor {
		return fmt.Errorf("the server's account store is at version %d, below the %d this device already read; keeping what it holds", version, floor)
	}
	return nil
}

// raiseFloor notes a version read or written. Called with d.mu held.
func (d *Device) raiseFloor(accountKey []byte, version int64) error {
	id := floorID(accountKey)
	if version <= d.state.StoreFloors[id] {
		return nil
	}
	if d.state.StoreFloors == nil {
		d.state.StoreFloors = map[string]int64{}
	}
	d.state.StoreFloors[id] = version
	return d.state.save(d.dir)
}
