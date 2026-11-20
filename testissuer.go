//go:build testissuer

package peachy

// Test-only doors into the MLS engine, for a test that plays the other side
// of a group (rejoin_issuer_test.go): a credential issuer and the member's
// half of a group. Built only with `-tags testissuer`, against a library built
// with its test-issuer feature:
//
//	PEACHY_FEATURES=peachy-mls-cabi/test-issuer ./build.sh
//	CGO_LDFLAGS=-L$PWD/target/lib go test -tags testissuer ./...
//
// A shipped library has no issuer, and a shipped build of this package none of this.

/*
#define PEACHY_MLS_TEST_ISSUER 1
#include <stdlib.h>
#include "peachy_mls.h"
*/
import "C"

import (
	"crypto/sha256"
	"time"
	"unsafe"
)

type testIssuer struct{ i *C.PeachyMlsTestIssuer }

func newTestIssuer(seed []byte) (*testIssuer, error) {
	p, n := in(seed)
	var i *C.PeachyMlsTestIssuer
	if err := ffi(func() C.int32_t { return C.peachy_mls_test_issuer_new(p, n, &i) }); err != nil {
		return nil, err
	}
	return &testIssuer{i: i}, nil
}

func (t *testIssuer) close() { C.peachy_mls_test_issuer_free(t.i) }

func (t *testIssuer) publishedKeys() (string, error) {
	b, err := oneBuffer(func(out *C.PeachyMlsBuffer) C.int32_t { return C.peachy_mls_test_issuer_published_keys(t.i, out) })
	return string(b), err
}

func (t *testIssuer) issue(actor, device string, seed []byte) ([]byte, error) {
	ca, cd := C.CString(actor), C.CString(device)
	defer C.free(unsafe.Pointer(ca))
	defer C.free(unsafe.Pointer(cd))
	p, n := in(seed)
	now := time.Now().Unix()
	return oneBuffer(func(out *C.PeachyMlsBuffer) C.int32_t {
		return C.peachy_mls_test_issuer_issue(t.i, ca, cd, p, n, C.int64_t(now-3600), C.int64_t(now+29*86400), out)
	})
}

// newMemoryMLS is a client with no store, for one of the test's devices of
// actor. The issuer certifies a device under its test account key,
// SHA-256("peachy-test-account" || 0 || actor), which the client must hold.
func newMemoryMLS(actor string, credential, seed []byte, trusted string) (*mlsClient, error) {
	accountKey := sha256.Sum256(append([]byte("peachy-test-account\x00"), actor...))
	return openMLS(credential, seed, trusted, "", nil, accountKey[:])
}

func (m *mlsClient) create(group []byte) error {
	p, n := in(group)
	return ffi(func() C.int32_t { return C.peachy_mls_group_create(m.c, p, n) })
}

func (m *mlsClient) merge(group []byte) error {
	p, n := in(group)
	var epoch C.uint64_t
	return ffi(func() C.int32_t { return C.peachy_mls_group_merge_pending_commit(m.c, p, n, &epoch) })
}

// addMember stages and merges an add, returning the Welcome.
func (m *mlsClient) addMember(group, keyPackage []byte) ([]byte, error) {
	gp, gn := in(group)
	kp, kn := in(keyPackage)
	var commit, welcome C.PeachyMlsBuffer
	if err := ffi(func() C.int32_t { return C.peachy_mls_group_add_member(m.c, gp, gn, kp, kn, &commit, &welcome) }); err != nil {
		return nil, err
	}
	take(&commit)
	return take(&welcome), m.merge(group)
}

// selfUpdate stages and merges a key update: an epoch the other side never sees.
func (m *mlsClient) selfUpdate(group []byte) error {
	gp, gn := in(group)
	var commit C.PeachyMlsBuffer
	if err := ffi(func() C.int32_t { return C.peachy_mls_group_self_update(m.c, gp, gn, &commit) }); err != nil {
		return err
	}
	take(&commit)
	return m.merge(group)
}

// replaceMember answers a seat ask from a device that holds a leaf: Remove
// and Add in one commit, merged, returning the Welcome.
func (m *mlsClient) replaceMember(group []byte, leaf uint32, keyPackage []byte) ([]byte, error) {
	gp, gn := in(group)
	kp, kn := in(keyPackage)
	var commit, welcome C.PeachyMlsBuffer
	if err := ffi(func() C.int32_t {
		return C.peachy_mls_group_replace_member(m.c, gp, gn, C.uint32_t(leaf), kp, kn, &commit, &welcome)
	}); err != nil {
		return nil, err
	}
	take(&commit)
	return take(&welcome), m.merge(group)
}

// leafOf is the leaf index the device holds in the group, or false.
func (m *mlsClient) leafOf(group []byte, device string) (uint32, bool, error) {
	gp, gn := in(group)
	var count C.uintptr_t
	if err := ffi(func() C.int32_t { return C.peachy_mls_group_member_count(m.c, gp, gn, &count) }); err != nil {
		return 0, false, err
	}
	for i := C.uintptr_t(0); i < count; i++ {
		var leaf, rejection C.uint32_t
		var a, d, k, lk C.PeachyMlsBuffer
		if err := ffi(func() C.int32_t {
			return C.peachy_mls_group_member(m.c, gp, gn, i, &leaf, &a, &d, &k, &lk, &rejection)
		}); err != nil {
			return 0, false, err
		}
		take(&a)
		take(&k)
		take(&lk)
		if string(take(&d)) == device {
			return uint32(leaf), true, nil
		}
	}
	return 0, false, nil
}

// verifyJoinRequest is a member's verdict on a seat ask: 0 is accepted.
func (m *mlsClient) verifyJoinRequest(group []byte, actor, device string, proof, keyPackage []byte) (int, error) {
	gp, gn := in(group)
	ca, cd := C.CString(actor), C.CString(device)
	defer C.free(unsafe.Pointer(ca))
	defer C.free(unsafe.Pointer(cd))
	pp, pn := in(proof)
	kp, kn := in(keyPackage)
	var verdict C.uint32_t
	err := ffi(func() C.int32_t {
		return C.peachy_mls_verify_join_request(m.c, gp, gn, ca, cd, pp, pn, kp, kn, nil, 0, &verdict)
	})
	return int(verdict), err
}

// head is the group's head as the server would hold it after this member's
// last commit: its epoch, and SHA-256 of the epoch's send key as the verifier
// (peachy-protocol's docs/delivery.md, "The derived values").
func (m *mlsClient) head(group []byte) (epoch uint64, verifier []byte, err error) {
	gp, gn := in(group)
	var e C.uint64_t
	if err := ffi(func() C.int32_t { return C.peachy_mls_group_epoch(m.c, gp, gn, &e) }); err != nil {
		return 0, nil, err
	}
	label := C.CString("peachy sealed-sender v1")
	defer C.free(unsafe.Pointer(label))
	key, err := oneBuffer(func(out *C.PeachyMlsBuffer) C.int32_t {
		return C.peachy_mls_group_export_secret(m.c, gp, gn, label, gp, gn, 32, out)
	})
	if err != nil {
		return 0, nil, err
	}
	sum := sha256.Sum256(key)
	return uint64(e), sum[:], nil
}
