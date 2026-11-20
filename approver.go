package peachy

// The approving device's half of linking, which peachy-go never plays itself
// (it links into an account; it doesn't let devices in). The link tests use it
// to stand in for the person's phone.

/*
#include <stdlib.h>
#include "peachy_mls.h"
*/
import "C"

import "unsafe"

func signLinkCommitment(approverSeed []byte, deviceID string, deviceKey, commitment []byte) ([]byte, error) {
	cid := C.CString(deviceID)
	defer C.free(unsafe.Pointer(cid))
	sp, sn := in(approverSeed)
	dp, dn := in(deviceKey)
	cp, cn := in(commitment)
	return oneBuffer(func(out *C.PeachyMlsBuffer) C.int32_t {
		return C.peachy_mls_sign_device_link_commitment(sp, sn, cid, dp, dn, cp, cn, out)
	})
}

func generateAccountKey() ([]byte, error) {
	return oneBuffer(func(out *C.PeachyMlsBuffer) C.int32_t { return C.peachy_mls_generate_account_key(out) })
}

// sealAccountKey seals the version 3 box to linkKey, or with none the
// version 1 box.
func sealAccountKey(approverSeed, deviceKey, linkKey []byte, deviceID string, accountKey []byte) ([]byte, error) {
	cid := C.CString(deviceID)
	defer C.free(unsafe.Pointer(cid))
	sp, sn := in(approverSeed)
	dp, dn := in(deviceKey)
	lp, ln := in(linkKey)
	kp, kn := in(accountKey)
	return oneBuffer(func(out *C.PeachyMlsBuffer) C.int32_t {
		if linkKey == nil {
			return C.peachy_mls_account_key_seal(sp, sn, dp, dn, cid, kp, kn, out)
		}
		return C.peachy_mls_account_key_seal_hybrid(sp, sn, dp, dn, lp, ln, cid, kp, kn, out)
	})
}
