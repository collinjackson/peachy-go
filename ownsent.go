package peachy

import "time"

// Own sends come back (peachy-protocol docs/delivery.md, "Own sends come
// back"): a device that names itself among the recipients receives its own
// envelopes, and acknowledges them without processing them. An envelope is
// known by its nonce, the 12 bytes after the version byte.
//
// The memory is in process only, where the spec asks for it to be durable:
// an own envelope that comes back after a restart is harmless, since the
// engine answers an own message, or a commit still staged, as an echo.

const (
	nonceBytes   = 12
	ownSentKeep  = time.Hour
	ownSentLimit = 10000
)

func envelopeNonce(payload []byte) (string, bool) {
	if len(payload) < 1+nonceBytes {
		return "", false
	}
	return string(payload[1 : 1+nonceBytes]), true
}

// rememberSent notes an envelope about to be sent. Called with d.mu held.
func (d *Device) rememberSent(payload []byte, now time.Time) {
	n, ok := envelopeNonce(payload)
	if !ok {
		return
	}
	if d.ownSent == nil {
		d.ownSent = map[string]time.Time{}
	}
	if len(d.ownSent) >= ownSentLimit {
		for k, at := range d.ownSent {
			if now.Sub(at) > ownSentKeep {
				delete(d.ownSent, k)
			}
		}
	}
	if len(d.ownSent) < ownSentLimit {
		d.ownSent[n] = now
	}
}

// sentByUs reports whether an envelope is one this device sent, and forgets
// it. Called with d.mu held.
func (d *Device) sentByUs(payload []byte) bool {
	n, ok := envelopeNonce(payload)
	if !ok {
		return false
	}
	if _, ok := d.ownSent[n]; !ok {
		return false
	}
	delete(d.ownSent, n)
	return true
}

// nowFunc is time.Now, for files that do not import time.
func nowFunc() time.Time { return time.Now() }
