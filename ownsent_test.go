package peachy

import (
	"testing"
	"time"
)

func TestOwnSendsAreKnownByNonceOnce(t *testing.T) {
	d := &Device{}
	now := time.Now()
	sent := append([]byte{3}, []byte("twelve-bytes-and-the-rest")...)
	other := append([]byte{3}, []byte("another-nonce-and-the-rest")...)
	if d.sentByUs(sent) {
		t.Fatal("an envelope not yet sent counted as ours")
	}
	d.rememberSent(sent, now)
	if d.sentByUs(other) {
		t.Fatal("another envelope counted as ours")
	}
	if !d.sentByUs(sent) {
		t.Fatal("our own envelope wasn't recognised")
	}
	if d.sentByUs(sent) {
		t.Fatal("an own envelope is recognised only once")
	}
	d.rememberSent([]byte{3, 1, 2}, now) // too short to carry a nonce
	if len(d.ownSent) != 0 {
		t.Fatal("a short payload was remembered")
	}
}
