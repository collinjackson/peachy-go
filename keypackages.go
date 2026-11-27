package peachy

// KeyPackages keep this device addable (delivery.md §Replenish). Each one
// that someone adds this device with is used up. When the pool runs dry and
// the last-resort package is gone too, nobody can add this device to a new
// chat, so its person's other devices end up in chats it never hears of.
//
// The device reads its own entry of KeyPackagePoolStatus on connect, when
// the server pokes STATE_DOMAIN_MLS, and every keyPackageCheckEvery besides,
// and when it is low or has no last resort, publishes up to 2 × low_water
// ordinary packages and a last resort. The last resort is also replaced every
// lastResortRotation.

import (
	"context"
	"time"

	"github.com/rs/zerolog"

	"github.com/collinjackson/peachy-go/pb"
)

const (
	keyPackageCheckEvery = 15 * time.Minute
	lastResortRotation   = 48 * time.Hour // LAST_RESORT_ROTATION_INTERVAL_SECONDS
	maxPublish           = 100            // PublishKeyPackages takes 1 to 100
)

// keyPackagesDue asks for a pool check at the next quiet poll: the server
// poked STATE_DOMAIN_MLS.
func (d *Device) keyPackagesDue() { d.kpDue.Store(true) }

// replenishKeyPackages checks this device's pool, at most every
// keyPackageCheckEvery unless due, and tops it up. Failures are logged and
// tried at the next check.
func (d *Device) replenishKeyPackages(ctx context.Context, now time.Time) {
	due := d.kpDue.Swap(false)
	d.mu.Lock()
	if d.mls == nil || d.state.DeviceID == "" || !due && now.Sub(d.kpCheckedAt) < keyPackageCheckEvery {
		d.mu.Unlock()
		if due {
			d.kpDue.Store(true)
		}
		return
	}
	d.kpCheckedAt = now
	r, deviceID := d.rpc, d.state.DeviceID
	rotate := now.Unix()-d.state.LastResortAt >= int64(lastResortRotation/time.Second)
	d.mu.Unlock()

	log := zerolog.Ctx(ctx)
	status, err := call[pb.KeyPackagePoolStatusRequest, pb.KeyPackagePoolStatusResponse](ctx, r, "KeyPackagePoolStatus",
		&pb.KeyPackagePoolStatusRequest{})
	if err != nil {
		log.Warn().Err(err).Msg("Peachy: couldn't read this device's key package pool")
		return
	}
	var mine *pb.DeviceKeyPackagePool
	for _, p := range status.GetDevices() {
		if p.GetDeviceId() == deviceID {
			mine = p
		}
	}
	if mine == nil {
		log.Warn().Msg("Peachy: the key package pool doesn't list this device")
		return
	}
	ordinary := 0
	if mine.GetLow() || !mine.GetHasLastResort() {
		ordinary = 2*int(status.GetLowWater()) - int(mine.GetAvailable())
	}
	lastResort := !mine.GetHasLastResort() || rotate
	if ordinary < 0 {
		ordinary = 0
	}
	if ordinary > maxPublish-1 {
		ordinary = maxPublish - 1
	}
	if ordinary == 0 && !lastResort {
		return
	}

	d.mu.Lock()
	if d.mls == nil {
		d.mu.Unlock()
		return
	}
	var packages []*pb.MlsKeyPackage
	for i := 0; i < ordinary+1; i++ {
		last := i == ordinary
		if last && !lastResort {
			break
		}
		kp, err := d.mls.keyPackage(last)
		if err != nil {
			d.mu.Unlock()
			log.Warn().Err(err).Msg("Peachy: couldn't make key packages")
			return
		}
		packages = append(packages, &pb.MlsKeyPackage{Ciphersuite: uint32(kp.ciphersuite), KeyPackage: kp.pkg,
			KeyPackageRef: kp.ref, LastResort: last})
	}
	d.mu.Unlock()

	resp, err := call[pb.PublishKeyPackagesRequest, pb.PublishKeyPackagesResponse](ctx, r, "PublishKeyPackages",
		&pb.PublishKeyPackagesRequest{DeviceId: deviceID, KeyPackages: packages})
	if err != nil {
		log.Warn().Err(err).Msg("Peachy: couldn't publish key packages")
		d.mu.Lock()
		d.kpCheckedAt = time.Time{} // try again at the next quiet poll
		d.mu.Unlock()
		return
	}
	if lastResort {
		d.mu.Lock()
		d.state.LastResortAt = now.Unix()
		_ = d.state.save(d.dir)
		d.mu.Unlock()
	}
	log.Info().Int("ordinary", ordinary).Bool("last_resort", lastResort).
		Uint32("available", resp.GetAvailable()).Msg("Peachy: published key packages")
}
