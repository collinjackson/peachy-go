package peachy

// The cgo binding to Peachy's MLS engine, through its own C interface
// (peachy-mls-cabi, header mls/cabi/include/peachy_mls.h), which the iPhone
// and Android apps use too. build.sh builds the library from a Peachy checkout
// beside this repository.
//
// Every call runs on a locked OS thread: the library's error message is
// thread-local and is read right after the call that failed. A client is not
// safe for concurrent use; Device serializes its calls.

/*
#cgo CFLAGS: -I${SRCDIR}/include
#cgo LDFLAGS: -lpeachy_mls_cabi
#cgo darwin LDFLAGS: -framework Security -framework CoreFoundation
#cgo linux LDFLAGS: -lm -ldl -lpthread
#include <stdlib.h>
#include "peachy_mls.h"
*/
import "C"

import (
	"errors"
	"fmt"
	"runtime"
	"unsafe"
)

const (
	envelopeMessage = 1
	envelopeCommit  = 2

	mlsAlreadyAMember = C.PEACHY_MLS_ERR_ALREADY_A_MEMBER
	mlsNoSuchGroup    = C.PEACHY_MLS_ERR_NO_SUCH_GROUP
	// Drop in silence (peachy_mls.h): the wrong door, a removed or signed-out sender, a repeat.
	mlsWrongDoor      = C.PEACHY_MLS_ERR_WRONG_DOOR
	mlsNotFromAMember = C.PEACHY_MLS_ERR_NOT_FROM_A_MEMBER
	mlsDuplicate      = C.PEACHY_MLS_ERR_DUPLICATE

	incomingApplication = C.PEACHY_MLS_INCOMING_APPLICATION
	incomingCommit      = C.PEACHY_MLS_INCOMING_COMMIT
)

// MLSError is a refusal from the MLS engine.
type MLSError struct {
	Code    int
	Message string
}

func (e *MLSError) Error() string { return fmt.Sprintf("mls: %s (code %d)", e.Message, e.Code) }

func isMLSCode(err error, code int) bool {
	var e *MLSError
	return errors.As(err, &e) && e.Code == code
}

// ffi runs one library call and turns a failure into an MLSError.
func ffi(call func() C.int32_t) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if rc := call(); rc != C.PEACHY_MLS_OK {
		msg := "unknown error"
		if p := C.peachy_mls_last_error(); p != nil {
			msg = C.GoString(p)
		}
		return &MLSError{Code: int(rc), Message: msg}
	}
	return nil
}

// in passes a Go slice in. cgo lets C read Go memory for the duration of the
// call as long as it holds no Go pointers, which a []byte never does.
func in(b []byte) (*C.uint8_t, C.uintptr_t) {
	if len(b) == 0 {
		return nil, 0
	}
	return (*C.uint8_t)(unsafe.Pointer(&b[0])), C.uintptr_t(len(b))
}

// noBytes backs inOrEmpty's pointer for an empty slice.
var noBytes [1]byte

// inOrEmpty is in for an argument where length 0 means "none" but the library
// still refuses a null pointer.
func inOrEmpty(b []byte) (*C.uint8_t, C.uintptr_t) {
	if len(b) == 0 {
		return (*C.uint8_t)(unsafe.Pointer(&noBytes[0])), 0
	}
	return in(b)
}

// take copies a library buffer out and frees it.
func take(b *C.PeachyMlsBuffer) []byte {
	defer C.peachy_mls_buffer_free(b)
	if b.data == nil || b.len == 0 {
		return nil
	}
	return C.GoBytes(unsafe.Pointer(b.data), C.int(b.len))
}

func oneBuffer(call func(out *C.PeachyMlsBuffer) C.int32_t) ([]byte, error) {
	var out C.PeachyMlsBuffer
	if err := ffi(func() C.int32_t { return call(&out) }); err != nil {
		return nil, err
	}
	return take(&out), nil
}

// ---- Calls that need no client ---------------------------------------------

func generateSeed() ([]byte, error) {
	return oneBuffer(func(out *C.PeachyMlsBuffer) C.int32_t { return C.peachy_mls_generate_signing_key_seed(out) })
}

func signingPublicKey(seed []byte) ([]byte, error) {
	p, n := in(seed)
	return oneBuffer(func(out *C.PeachyMlsBuffer) C.int32_t { return C.peachy_mls_signing_key_public_key(p, n, out) })
}

func accountIdentityPublicKey(accountKey []byte) ([]byte, error) {
	p, n := in(accountKey)
	return oneBuffer(func(out *C.PeachyMlsBuffer) C.int32_t {
		return C.peachy_mls_account_identity_public_key(p, n, out)
	})
}

func signAccountDevice(accountKey, deviceKey []byte) ([]byte, error) {
	kp, kn := in(accountKey)
	dp, dn := in(deviceKey)
	return oneBuffer(func(out *C.PeachyMlsBuffer) C.int32_t {
		return C.peachy_mls_sign_account_device(kp, kn, dp, dn, out)
	})
}

// accountKeyAccept opens the account-key box through the vouched door: only a
// box from confirmedApproverKey (the approver whose number the person picked on
// this device) opens, and only a version 3 box sealed to the link key this
// device posted (linkSeed), unless serverApproval allows the version 1 box a
// local test server seals for itself. approverKey comes from our own
// ListDevices, never from the response that carried the box.
func accountKeyAccept(seed, approverKey []byte, deviceID string, box, linkSeed, confirmedApproverKey []byte, serverApproval bool) ([]byte, error) {
	sp, sn := in(seed)
	ap, an := in(approverKey)
	bp, bn := in(box)
	lp, ln := inOrEmpty(linkSeed)
	cp, cn := inOrEmpty(confirmedApproverKey)
	cid := C.CString(deviceID)
	defer C.free(unsafe.Pointer(cid))
	return oneBuffer(func(out *C.PeachyMlsBuffer) C.int32_t {
		return C.peachy_mls_account_key_accept_hybrid(sp, sn, ap, an, cid, bp, bn, lp, ln, cp, cn,
			C.bool(serverApproval), out)
	})
}

const (
	linkAnswer      = C.PEACHY_MLS_LINK_ANSWER
	linkContinue    = C.PEACHY_MLS_LINK_CONTINUE
	linkIgnore      = C.PEACHY_MLS_LINK_IGNORE
	linkInterrupted = C.PEACHY_MLS_LINK_INTERRUPTED
)

// linkWaiterStep is the core's one-exchange-per-pairing rule. bound* are
// empty until the pairing has answered an exchange.
func linkWaiterStep(boundID string, boundKey, boundCommitment []byte, approverID string, approverKey, commitment []byte) (int, error) {
	cb := C.CString(boundID)
	defer C.free(unsafe.Pointer(cb))
	ca := C.CString(approverID)
	defer C.free(unsafe.Pointer(ca))
	bkp, bkn := inOrEmpty(boundKey)
	bcp, bcn := inOrEmpty(boundCommitment)
	akp, akn := in(approverKey)
	acp, acn := in(commitment)
	var step C.uint32_t
	err := ffi(func() C.int32_t {
		return C.peachy_mls_device_link_waiter_step(cb, bkp, bkn, bcp, bcn, ca, akp, akn, acp, acn, &step)
	})
	return int(step), err
}

// verifyLinkCommitment checks the approver's signature S over its commitment,
// for this device's own id and key as we hold them.
func verifyLinkCommitment(approverKey []byte, deviceID string, deviceKey, commitment, signature []byte) bool {
	cid := C.CString(deviceID)
	defer C.free(unsafe.Pointer(cid))
	ap, an := in(approverKey)
	dp, dn := in(deviceKey)
	cp, cn := in(commitment)
	sp, sn := in(signature)
	var ok C.bool
	if err := ffi(func() C.int32_t {
		return C.peachy_mls_verify_device_link_commitment(ap, an, cid, dp, dn, cp, cn, sp, sn, &ok)
	}); err != nil {
		return false
	}
	return bool(ok)
}

func generateLinkKemSeed() ([]byte, error) {
	return oneBuffer(func(out *C.PeachyMlsBuffer) C.int32_t { return C.peachy_mls_generate_device_link_kem_seed(out) })
}

func linkKemPublicKey(linkSeed []byte) ([]byte, error) {
	p, n := in(linkSeed)
	return oneBuffer(func(out *C.PeachyMlsBuffer) C.int32_t { return C.peachy_mls_device_link_kem_public_key(p, n, out) })
}

// signLinkKem is T, this device's signature over the link key it posts.
func signLinkKem(seed []byte, deviceID string, commitment, deviceNonce, linkKey []byte) ([]byte, error) {
	cid := C.CString(deviceID)
	defer C.free(unsafe.Pointer(cid))
	sp, sn := in(seed)
	cp, cn := in(commitment)
	np, nn := in(deviceNonce)
	lp, ln := in(linkKey)
	return oneBuffer(func(out *C.PeachyMlsBuffer) C.int32_t {
		return C.peachy_mls_sign_device_link_kem(sp, sn, cid, cp, cn, np, nn, lp, ln, out)
	})
}

func deviceLinkApproverNumber(deviceKey, approverKey, commitment, deviceNonce, approverNonce []byte) (string, error) {
	dp, dn := in(deviceKey)
	ap, an := in(approverKey)
	cp, cn := in(commitment)
	np, nn := in(deviceNonce)
	xp, xn := in(approverNonce)
	b, err := oneBuffer(func(out *C.PeachyMlsBuffer) C.int32_t {
		return C.peachy_mls_device_link_approver_number(dp, dn, ap, an, cp, cn, np, nn, xp, xn, out)
	})
	return string(b), err
}

// serverKeysPinned narrows the server's published credential keys to the
// ones this build of the engine carries for set ("production").
func serverKeysPinned(published, set string) (string, error) {
	cp := C.CString(published)
	defer C.free(unsafe.Pointer(cp))
	cs := C.CString(set)
	defer C.free(unsafe.Pointer(cs))
	b, err := oneBuffer(func(out *C.PeachyMlsBuffer) C.int32_t { return C.peachy_mls_server_keys_pinned(cp, cs, out) })
	return string(b), err
}

// serverKeyPinReport is empty when the published keys match the carried ones,
// else one line for the device's own log.
func serverKeyPinReport(published, set string) (string, error) {
	cp := C.CString(published)
	defer C.free(unsafe.Pointer(cp))
	cs := C.CString(set)
	defer C.free(unsafe.Pointer(cs))
	b, err := oneBuffer(func(out *C.PeachyMlsBuffer) C.int32_t { return C.peachy_mls_server_key_pin_report(cp, cs, out) })
	return string(b), err
}

func deviceLinkCommitment(approverNonce []byte) ([]byte, error) {
	p, n := in(approverNonce)
	return oneBuffer(func(out *C.PeachyMlsBuffer) C.int32_t { return C.peachy_mls_device_link_commitment(p, n, out) })
}

func deviceLinkNumber(deviceKey, approverKey, commitment, deviceNonce, approverNonce []byte) (string, error) {
	dp, dn := in(deviceKey)
	ap, an := in(approverKey)
	cp, cn := in(commitment)
	np, nn := in(deviceNonce)
	xp, xn := in(approverNonce)
	b, err := oneBuffer(func(out *C.PeachyMlsBuffer) C.int32_t {
		return C.peachy_mls_device_link_number(dp, dn, ap, an, cp, cn, np, nn, xp, xn, out)
	})
	return string(b), err
}

// noteSender is the device a signed self-note says sent it, to look up in
// the account's device list before noteOpenSigned believes it.
func noteSender(accountKey, id, value []byte) (string, error) {
	kp, kn := in(accountKey)
	ip, inn := in(id)
	vp, vn := in(value)
	b, err := oneBuffer(func(out *C.PeachyMlsBuffer) C.int32_t {
		return C.peachy_mls_note_sender(kp, kn, ip, inn, vp, vn, out)
	})
	return string(b), err
}

// noteOpenSigned opens a self-note only when senderDevice signed it under
// signingKey (the key the account's device list gives that device), issued
// within the engine's window around nowMS.
func noteOpenSigned(accountKey, id, value []byte, senderDevice string, signingKey []byte, nowMS int64) ([]byte, error) {
	kp, kn := in(accountKey)
	ip, inn := in(id)
	vp, vn := in(value)
	sp, sn := in(signingKey)
	cs := C.CString(senderDevice)
	defer C.free(unsafe.Pointer(cs))
	return oneBuffer(func(out *C.PeachyMlsBuffer) C.int32_t {
		return C.peachy_mls_note_open_signed(kp, kn, ip, inn, vp, vn, cs, sp, sn, C.int64_t(nowMS), out)
	})
}

func storeSeal(accountKey, id, plaintext []byte) ([]byte, error) {
	kp, kn := in(accountKey)
	ip, inn := in(id)
	pp, pn := in(plaintext)
	return oneBuffer(func(out *C.PeachyMlsBuffer) C.int32_t {
		return C.peachy_mls_store_seal(kp, kn, ip, inn, pp, pn, out)
	})
}

func storeOpen(accountKey, id, value []byte) ([]byte, error) {
	kp, kn := in(accountKey)
	ip, inn := in(id)
	vp, vn := in(value)
	return oneBuffer(func(out *C.PeachyMlsBuffer) C.int32_t {
		return C.peachy_mls_store_open(kp, kn, ip, inn, vp, vn, out)
	})
}

// ---- One device's MLS client -----------------------------------------------

type mlsClient struct {
	c *C.PeachyMlsClient
}

// openMLS opens the device's client over its SQLite store, encrypted under
// storeKey (32 bytes, storekey.go), reopening every group already in it.
// accountKey (nil until the device is approved) gives the account identity the
// library checks a certified credential against.
// checkABI refuses an engine built for another C ABI than the header this
// package carries (include/peachy_mls.h), as peachy-protocol asks of every
// binding.
func checkABI() error {
	if got, want := C.peachy_mls_abi_version(), C.uint32_t(C.PEACHY_MLS_ABI_VERSION); got != want {
		return fmt.Errorf("the linked MLS engine speaks C ABI %d; this build of peachy-go needs %d (see peachy-protocol.commit)", got, want)
	}
	return nil
}

func openMLS(credential, seed []byte, trustedKeysJSON, storePath string, storeKey, accountKey []byte) (*mlsClient, error) {
	if err := checkABI(); err != nil {
		return nil, err
	}
	cp, cn := in(credential)
	sp, sn := in(seed)
	ctrusted := C.CString(trustedKeysJSON)
	defer C.free(unsafe.Pointer(ctrusted))
	cpath := C.CString(storePath)
	defer C.free(unsafe.Pointer(cpath))
	var identity []byte
	if accountKey != nil {
		ap, an := in(accountKey)
		var err error
		identity, err = oneBuffer(func(out *C.PeachyMlsBuffer) C.int32_t {
			return C.peachy_mls_account_identity_public_key(ap, an, out)
		})
		if err != nil {
			return nil, err
		}
	}
	kp, kn := in(storeKey)
	ip, inn := in(identity)
	var client *C.PeachyMlsClient
	err := ffi(func() C.int32_t {
		return C.peachy_mls_client_open(cp, cn, sp, sn, ctrusted, cpath, kp, kn, ip, inn, &client)
	})
	if err != nil {
		return nil, err
	}
	m := &mlsClient{c: client}
	if accountKey != nil {
		// The stamp keys derive from it; the core holds it in memory only, so
		// it goes in after every open (peachy-protocol 0.3.0).
		if err := m.setAccountKey(accountKey); err != nil {
			m.close()
			return nil, err
		}
	}
	return m, nil
}

// setAccountKey hands the core the account key as held (32 or 64 bytes).
func (m *mlsClient) setAccountKey(key []byte) error {
	kp, kn := in(key)
	return ffi(func() C.int32_t { return C.peachy_mls_client_set_account_key(m.c, kp, kn) })
}

func (m *mlsClient) close() {
	if m.c != nil {
		C.peachy_mls_client_free(m.c)
		m.c = nil
	}
}

func (m *mlsClient) identity() (actorID, deviceID string, err error) {
	var a, d C.PeachyMlsBuffer
	if err = ffi(func() C.int32_t { return C.peachy_mls_client_identity(m.c, &a, &d) }); err != nil {
		return
	}
	return string(take(&a)), string(take(&d)), nil
}

type keyPackage struct {
	pkg, ref    []byte
	ciphersuite uint16
}

func (m *mlsClient) keyPackage(lastResort bool) (keyPackage, error) {
	var p, r C.PeachyMlsBuffer
	var suite C.uint16_t
	err := ffi(func() C.int32_t {
		if lastResort {
			return C.peachy_mls_last_resort_key_package_with_ref(m.c, &p, &r, &suite)
		}
		return C.peachy_mls_key_package_with_ref(m.c, &p, &r, &suite)
	})
	if err != nil {
		return keyPackage{}, err
	}
	return keyPackage{pkg: take(&p), ref: take(&r), ciphersuite: uint16(suite)}, nil
}

func (m *mlsClient) join(welcome []byte) ([]byte, error) {
	p, n := in(welcome)
	return oneBuffer(func(out *C.PeachyMlsBuffer) C.int32_t { return C.peachy_mls_group_join(m.c, p, n, out) })
}

// openEnvelope finds which of our groups an envelope belongs to. A nil group
// means none of them: not an error.
func (m *mlsClient) openEnvelope(envelope []byte) (group []byte, kind uint8, inner []byte, err error) {
	p, n := in(envelope)
	var g, i C.PeachyMlsBuffer
	var k C.uint8_t
	if err = ffi(func() C.int32_t { return C.peachy_mls_open_envelope(m.c, p, n, &g, &k, &i) }); err != nil {
		return
	}
	return take(&g), uint8(k), take(&i), nil
}

type incoming struct {
	kind                  int
	senderActor, senderID string
	plaintext             []byte
}

// process opens one group message through the door for its envelope kind: commits through
// the commit door, everything else through the message door (the core has no doorless form
// since 2026-10-28). receivedAt is the mailbox's received time in Unix seconds, 0 if unknown.
func (m *mlsClient) process(group, message []byte, commit bool, receivedAt int64) (incoming, error) {
	gp, gn := in(group)
	mp, mn := in(message)
	door := C.uint32_t(C.PEACHY_MLS_DOOR_MESSAGE)
	if commit {
		door = C.PEACHY_MLS_DOOR_COMMIT
	}
	var out C.PeachyMlsIncoming
	if err := ffi(func() C.int32_t {
		return C.peachy_mls_group_process_door(m.c, gp, gn, mp, mn, door, C.int64_t(receivedAt), &out)
	}); err != nil {
		return incoming{}, err
	}
	inc := incoming{
		kind:        int(out.kind),
		senderActor: string(take(&out.sender_actor_id)),
		senderID:    string(take(&out.sender_device_id)),
		plaintext:   take(&out.plaintext),
	}
	C.peachy_mls_incoming_free(&out)
	return inc, nil
}

func (m *mlsClient) groupIDs() ([][]byte, error) {
	var count C.uintptr_t
	if err := ffi(func() C.int32_t { return C.peachy_mls_group_count(m.c, &count) }); err != nil {
		return nil, err
	}
	ids := make([][]byte, 0, int(count))
	for i := C.uintptr_t(0); i < count; i++ {
		id, err := oneBuffer(func(out *C.PeachyMlsBuffer) C.int32_t { return C.peachy_mls_group_id_at(m.c, i, out) })
		if err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, nil
}

// forget drops every trace of group from this device: the local half of a
// rejoin, for a copy that fell off the ratchet. The next Welcome into the id
// creates it fresh instead of colliding with the stale copy.
func (m *mlsClient) forget(group []byte) error {
	p, n := in(group)
	return ffi(func() C.int32_t { return C.peachy_mls_group_forget(m.c, p, n) })
}

// signJoinRequest signs this device's ask to be seated in group: the proof a
// seat ask carries. Needs no copy of the group, so it works after forget.
func (m *mlsClient) signJoinRequest(group []byte) ([]byte, error) {
	p, n := in(group)
	return oneBuffer(func(out *C.PeachyMlsBuffer) C.int32_t { return C.peachy_mls_sign_join_request(m.c, p, n, out) })
}

type member struct {
	actorID, deviceID string
	// bot: the leaf's credential is a pdc3 (docs/bots.md). botAware: the
	// leaf lists peachy_bot_aware (0xF1AB), as a 0.3.0 core's leaves do.
	bot, botAware bool
}

// roster is the group's members whose credentials verify. A leaf that
// doesn't verify is left out: it has no identity to show or address.
func (m *mlsClient) roster(group []byte) ([]member, error) {
	gp, gn := in(group)
	var count C.uintptr_t
	if err := ffi(func() C.int32_t { return C.peachy_mls_group_member_count(m.c, gp, gn, &count) }); err != nil {
		return nil, err
	}
	var out []member
	for i := C.uintptr_t(0); i < count; i++ {
		var leaf, rejection C.uint32_t
		var a, d, k, lk C.PeachyMlsBuffer
		err := ffi(func() C.int32_t {
			return C.peachy_mls_group_member(m.c, gp, gn, i, &leaf, &a, &d, &k, &lk, &rejection)
		})
		if err != nil {
			return nil, err
		}
		actor, device := string(take(&a)), string(take(&d))
		take(&k)
		take(&lk)
		if rejection == 0 && actor != "" {
			bot, aware := m.memberKind(gp, gn, i)
			out = append(out, member{actorID: actor, deviceID: device, bot: bot, botAware: aware})
		}
	}
	return out, nil
}

// memberKind reads the roster entry at pos: whether its leaf is a bot's,
// and whether it lists 0xF1AB. A kind this build doesn't know, or a failed
// read, is a person's, as the core asks.
func (m *mlsClient) memberKind(gp *C.uint8_t, gn C.uintptr_t, pos C.uintptr_t) (bot, aware bool) {
	var kind, ownerKind C.uint32_t
	var owner C.PeachyMlsBuffer
	if ffi(func() C.int32_t {
		return C.peachy_mls_group_member_kind(m.c, gp, gn, pos, &kind, &ownerKind, &owner)
	}) == nil {
		bot = kind == C.PEACHY_MLS_MEMBER_BOT
	}
	take(&owner)
	var supports C.bool
	if ffi(func() C.int32_t { return C.peachy_mls_group_member_supports_bot(m.c, gp, gn, pos, &supports) }) == nil {
		aware = bool(supports)
	}
	return bot, aware
}

// meta is the group's name-and-photo JSON, or nil when none is set.
func (m *mlsClient) meta(group []byte) ([]byte, error) {
	gp, gn := in(group)
	return oneBuffer(func(out *C.PeachyMlsBuffer) C.int32_t { return C.peachy_mls_group_meta(m.c, gp, gn, out) })
}

// sealEnvelope wraps inner as an envelope of a group this client holds: by
// the epoch's keys (version 3) when every leaf reads that, else by the group id
// (version 2). Never the clientless door, whose version 2 marks a send as from
// a client other than Peachy's own and opens for anyone who held the group id.
func (m *mlsClient) sealEnvelope(group []byte, kind uint8, inner []byte) ([]byte, error) {
	gp, gn := in(group)
	ip, inn := in(inner)
	return oneBuffer(func(out *C.PeachyMlsBuffer) C.int32_t {
		return C.peachy_mls_client_seal_envelope(m.c, gp, gn, C.uint8_t(kind), ip, inn, out)
	})
}

// encryptWithHint is encrypt with a content hint in the message's
// authenticated data (2: a receiver that can't open it shows nothing).
func (m *mlsClient) encryptWithHint(group, plaintext []byte, hint uint8) ([]byte, error) {
	gp, gn := in(group)
	pp, pn := in(plaintext)
	return oneBuffer(func(out *C.PeachyMlsBuffer) C.int32_t {
		return C.peachy_mls_group_encrypt_with_hint(m.c, gp, gn, pp, pn, C.uint8_t(hint), out)
	})
}

func (m *mlsClient) encrypt(group, plaintext []byte) ([]byte, error) {
	gp, gn := in(group)
	pp, pn := in(plaintext)
	return oneBuffer(func(out *C.PeachyMlsBuffer) C.int32_t {
		return C.peachy_mls_group_encrypt(m.c, gp, gn, pp, pn, out)
	})
}
