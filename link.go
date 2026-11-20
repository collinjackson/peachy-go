package peachy

// Linking this device into an account, as Peachy's own apps do it
// (docs/protocol/identity.md §The two-digit number, §The link key, §Fetching
// and opening the account key in Peachy's tree):
//
//  1. An approving device (the person's phone) posts a commitment C, signed
//     for this device's id and key (S). We answer only an exchange whose S
//     holds, from an approved, certified, unrevoked device of the account.
//  2. We post our nonce nN with a post-quantum link key L and our signature
//     T over it. One exchange per pairing: the first we answer binds the
//     pairing, and anything that contradicts it ends the pairing.
//  3. The phone reveals nA; we show the number, and the person taps it there.
//  4. The phone then shows its own number. The person picks it here, among
//     two decoys and "none of these". That pick is what vouches for the
//     approver: only then does the account key the phone sealed to L open.
//
// The server relays every step and can't steer any of them: a box the server
// sealed itself, or one from a device the person never confirmed here, does
// not open.

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"

	"github.com/collinjackson/peachy-go/pb"
)

const (
	LinkWaiting    = "waiting"
	LinkPickNumber = "pick_number"
	// LinkConfirmApprover: the phone approved, and shows a number of its own.
	// Ask the person which of Choices it shows, and pass it to
	// ConfirmApprover; "" means none of them.
	LinkConfirmApprover = "confirm_approver"
	LinkApproved        = "approved"
)

// ErrLinkInterrupted means the pairing saw something it can't trust (another
// commitment, a changed key, a wrong pick). Nothing was approved. Start over
// with RestartLink, and on the phone, remove the device if it shows.
var ErrLinkInterrupted = errors.New("linking was interrupted: nothing was approved; start again on both devices")

// LinkStatus is where linking stands after one LinkStep.
type LinkStatus struct {
	State string
	// For LinkPickNumber: the number to pick on the approving device, and
	// that device's name.
	Number   string
	Approver string
	// For LinkConfirmApprover: the numbers to offer, one of them the phone's.
	Choices []string
}

// pairing is one attempt at linking, from the first LinkStep to approval. It
// lives in memory only: a restarted process is a new pairing, as a relaunched
// app is.
type pairing struct {
	// What the first exchange we answered bound us to.
	approverID              string
	approverKey, commitment []byte
	approverName            string
	// What we posted, the same on every retry.
	nonce, linkSeed, linkKey, linkSig []byte
	// Once revealed. The server deletes the exchange on approval, so we keep
	// them ourselves.
	approverNonce  []byte
	number         string
	approverNumber string
	choices        []string
	// The approver key the person confirmed by picking its number here.
	confirmed   []byte
	interrupted bool
}

// RestartLink starts a new pairing, after ErrLinkInterrupted.
func (d *Device) RestartLink() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.link = nil
}

// ConfirmApprover takes the number the person says the approving device
// shows ("" for none of the choices). The right one vouches for that device;
// anything else ends the pairing.
func (d *Device) ConfirmApprover(pick string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	p := d.link
	if p == nil || p.interrupted || p.approverNumber == "" {
		return errors.New("no approval is waiting to be confirmed")
	}
	if pick == "" || pick != p.approverNumber {
		p.interrupted = true
		return ErrLinkInterrupted
	}
	p.confirmed = p.approverKey
	return nil
}

// localServer is a Peachy server on this machine (a local test server), which
// approves devices itself with a box no person vouched for. Decided from the
// address the person gave, never from anything the server says.
func localServer(base string) bool {
	u, err := url.Parse(base)
	if err != nil {
		return false
	}
	switch u.Hostname() {
	case "localhost", "127.0.0.1", "::1":
		return true
	}
	return false
}

// usableApprover: a device of the account that may let a new one in.
func usableApprover(dev *pb.Device) bool {
	return dev != nil && dev.GetApprovalState() == "approved" && dev.GetAccountCertified() &&
		dev.GetRevokedAt() == nil && len(dev.GetSigningKey()) == 32
}

// LinkStep runs one round of linking; call it every couple of seconds until
// it says LinkApproved.
func (d *Device) LinkStep(ctx context.Context) (LinkStatus, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.state.AccountKeyHex != "" {
		return LinkStatus{State: LinkApproved}, nil
	}
	if d.link == nil {
		d.link = &pairing{}
	}
	p := d.link
	if p.interrupted {
		return LinkStatus{}, ErrLinkInterrupted
	}
	if d.state.DeviceID == "" {
		registered, err := d.register(ctx, false)
		if err != nil {
			return LinkStatus{}, err
		}
		if registered.GetDevice().GetId() == "" {
			return LinkStatus{}, errors.New("RegisterDevice returned no device")
		}
		d.state.DeviceID = registered.GetDevice().GetId()
		if err := d.state.save(d.dir); err != nil {
			return LinkStatus{}, err
		}
	}
	deviceID := d.state.DeviceID
	list, err := call[pb.ListDevicesRequest, pb.ListDevicesResponse](ctx, d.rpc, "ListDevices", &pb.ListDevicesRequest{})
	if err != nil {
		return LinkStatus{}, err
	}
	byID := map[string]*pb.Device{}
	for _, dev := range list.GetDevices() {
		byID[dev.GetId()] = dev
	}
	me := byID[deviceID]
	if me == nil {
		return LinkStatus{}, errors.New("this device was removed")
	}

	fetched, err := call[pb.FetchAccountKeyRequest, pb.FetchAccountKeyResponse](ctx, d.rpc, "FetchAccountKey",
		&pb.FetchAccountKeyRequest{DeviceId: deviceID})
	if err != nil {
		return LinkStatus{}, err
	}
	if len(fetched.GetBox()) > 0 {
		return d.openBox(p, byID, fetched)
	}

	for _, ex := range me.GetLinkExchanges() {
		status, done, err := d.stepExchange(ctx, p, byID, ex)
		if err != nil || done {
			return status, err
		}
	}
	if p.number != "" {
		return LinkStatus{State: LinkPickNumber, Number: p.number, Approver: p.approverName}, nil
	}
	return LinkStatus{State: LinkWaiting}, nil
}

// openBox takes the account key the approver sealed to us. Called with d.mu held.
func (d *Device) openBox(p *pairing, byID map[string]*pb.Device, fetched *pb.FetchAccountKeyResponse) (LinkStatus, error) {
	// The approver's key comes from our own device list, never from the
	// response that carried the box.
	approver := byID[fetched.GetApproverDeviceId()]
	if !usableApprover(approver) {
		return LinkStatus{}, errors.New("the approving device isn't an approved device of this account")
	}
	serverApproval := d.serverApproval
	if !serverApproval {
		if p.approverNumber == "" {
			// Approved in a pairing this process didn't run (a restart after
			// the number): nothing here can vouch for the approver.
			p.interrupted = true
			return LinkStatus{}, fmt.Errorf("%w (approved in an earlier pairing this run never saw)", ErrLinkInterrupted)
		}
		if fetched.GetApproverDeviceId() != p.approverID || !bytes.Equal(approver.GetSigningKey(), p.approverKey) {
			p.interrupted = true
			return LinkStatus{}, ErrLinkInterrupted
		}
		if p.confirmed == nil {
			return LinkStatus{State: LinkConfirmApprover, Approver: p.approverName, Choices: p.choices}, nil
		}
	}
	key, err := accountKeyAccept(d.seed, approver.GetSigningKey(), d.state.DeviceID, fetched.GetBox(),
		p.linkSeed, p.confirmed, serverApproval)
	if err != nil {
		p.interrupted = true
		return LinkStatus{}, fmt.Errorf("the account key didn't open (%v): %w", err, ErrLinkInterrupted)
	}
	d.state.AccountKeyHex = hex.EncodeToString(key)
	if err := d.state.save(d.dir); err != nil {
		return LinkStatus{}, err
	}
	d.link = nil
	return LinkStatus{State: LinkApproved}, nil
}

// stepExchange takes one exchange on our row. done means LinkStep returns
// status. Called with d.mu held.
func (d *Device) stepExchange(ctx context.Context, p *pairing, byID map[string]*pb.Device, ex *pb.DeviceLinkExchange) (LinkStatus, bool, error) {
	approver := byID[ex.GetApproverDeviceId()]
	if !usableApprover(approver) || len(ex.GetApproverCommitment()) == 0 {
		return LinkStatus{}, false, nil
	}
	// S over our OWN id and key as we hold them; an exchange without it is
	// not answered and does not end the pairing.
	if !verifyLinkCommitment(approver.GetSigningKey(), d.state.DeviceID, d.publicKey,
		ex.GetApproverCommitment(), ex.GetApproverSignature()) {
		return LinkStatus{}, false, nil
	}
	step, err := linkWaiterStep(p.approverID, p.approverKey, p.commitment,
		ex.GetApproverDeviceId(), approver.GetSigningKey(), ex.GetApproverCommitment())
	if err != nil {
		return LinkStatus{}, false, nil // a malformed exchange: skip it
	}
	switch step {
	case linkIgnore:
		return LinkStatus{}, false, nil
	case linkInterrupted:
		p.interrupted = true
		return LinkStatus{}, true, ErrLinkInterrupted
	case linkAnswer:
		if err := p.bind(d.seed, d.state.DeviceID, ex, approver); err != nil {
			return LinkStatus{}, true, err
		}
	}
	// Bound to this exchange (just now, or before).
	if len(ex.GetDeviceNonce()) == 0 {
		// Ours isn't listed yet, or the approver restarted with the same C:
		// post the SAME nonce and link key again, never fresh ones.
		_, err := call[pb.StepDeviceLinkRequest, pb.StepDeviceLinkResponse](ctx, d.rpc, "StepDeviceLink", &pb.StepDeviceLinkRequest{
			DeviceId:               d.state.DeviceID,
			ApproverDeviceId:       p.approverID,
			Step:                   &pb.StepDeviceLinkRequest_DeviceNonce{DeviceNonce: p.nonce},
			DeviceLinkKey:          p.linkKey,
			DeviceLinkKeySignature: p.linkSig,
		})
		return LinkStatus{State: LinkWaiting}, true, err
	}
	if !bytes.Equal(ex.GetDeviceNonce(), p.nonce) {
		p.interrupted = true // a nonce we never posted
		return LinkStatus{}, true, ErrLinkInterrupted
	}
	if len(ex.GetApproverNonce()) == 0 || p.number != "" {
		return LinkStatus{}, false, nil
	}
	commitment, err := deviceLinkCommitment(ex.GetApproverNonce())
	if err != nil || !bytes.Equal(commitment, p.commitment) {
		p.interrupted = true // an nA that doesn't open C
		return LinkStatus{}, true, ErrLinkInterrupted
	}
	// Both numbers over the BOUND approver key, never one read later.
	number, err := deviceLinkNumber(d.publicKey, p.approverKey, p.commitment, p.nonce, ex.GetApproverNonce())
	if err != nil {
		return LinkStatus{}, true, err
	}
	approverNumber, err := deviceLinkApproverNumber(d.publicKey, p.approverKey, p.commitment, p.nonce, ex.GetApproverNonce())
	if err != nil {
		return LinkStatus{}, true, err
	}
	choices, err := withDecoys(approverNumber)
	if err != nil {
		return LinkStatus{}, true, err
	}
	p.approverNonce, p.number, p.approverNumber, p.choices = ex.GetApproverNonce(), number, approverNumber, choices
	return LinkStatus{State: LinkPickNumber, Number: number, Approver: p.approverName}, true, nil
}

// bind fixes the pairing to the first exchange it answers, and draws what it
// posts: nN, and the link key L with our signature T over C, nN and L.
func (p *pairing) bind(seed []byte, deviceID string, ex *pb.DeviceLinkExchange, approver *pb.Device) error {
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	linkSeed, err := generateLinkKemSeed()
	if err != nil {
		return err
	}
	linkKey, err := linkKemPublicKey(linkSeed)
	if err != nil {
		return err
	}
	sig, err := signLinkKem(seed, deviceID, ex.GetApproverCommitment(), nonce, linkKey)
	if err != nil {
		return err
	}
	p.approverID = ex.GetApproverDeviceId()
	p.approverKey = bytes.Clone(approver.GetSigningKey())
	// The server keeps no device names (they're sealed in the account
	// store, which this device can't read yet): name the approver by platform.
	p.approverName = platformName(approver.GetPlatform())
	p.commitment = bytes.Clone(ex.GetApproverCommitment())
	p.nonce, p.linkSeed, p.linkKey, p.linkSig = nonce, linkSeed, linkKey, sig
	return nil
}

// withDecoys is the right number among two others, all distinct, in a random
// order, from crypto/rand.
func withDecoys(right string) ([]string, error) {
	out := []string{right}
	for len(out) < 3 {
		n, err := randBelow(100)
		if err != nil {
			return nil, err
		}
		c := fmt.Sprintf("%02d", n)
		dup := false
		for _, o := range out {
			dup = dup || o == c
		}
		if !dup {
			out = append(out, c)
		}
	}
	for i := len(out) - 1; i > 0; i-- {
		j, err := randBelow(uint64(i + 1))
		if err != nil {
			return nil, err
		}
		out[i], out[j] = out[j], out[i]
	}
	return out, nil
}

// randBelow is a uniform draw from [0, n).
func randBelow(n uint64) (uint64, error) {
	limit := ^uint64(0) - ^uint64(0)%n
	var b [8]byte
	for {
		if _, err := rand.Read(b[:]); err != nil {
			return 0, err
		}
		if v := binary.BigEndian.Uint64(b[:]); v < limit {
			return v % n, nil
		}
	}
}
