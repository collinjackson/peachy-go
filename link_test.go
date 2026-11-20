package peachy

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/collinjackson/peachy-go/pb"
)

const (
	testBotID   = "11111111-1111-4111-8111-111111111111"
	testPhoneID = "22222222-2222-4222-8222-222222222222"
	testEvilID  = "33333333-3333-4333-8333-333333333333"
)

// linkServer is the four rpcs linking uses, relaying whatever the test (the
// phone, or a server in the middle) puts on the bot's row.
type linkServer struct {
	mu       sync.Mutex
	devices  []*pb.Device
	exchange *pb.DeviceLinkExchange
	fetched  *pb.FetchAccountKeyResponse
}

func (s *linkServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	body, _ := io.ReadAll(r.Body)
	var resp proto.Message
	switch r.URL.Path[strings.LastIndex(r.URL.Path, "/")+1:] {
	case "RegisterDevice":
		resp = &pb.RegisterDeviceResponse{Device: &pb.Device{Id: testBotID}}
	case "ListDevices":
		bot := &pb.Device{Id: testBotID, ApprovalState: "pending"}
		if s.exchange != nil {
			bot.LinkExchanges = []*pb.DeviceLinkExchange{proto.Clone(s.exchange).(*pb.DeviceLinkExchange)}
		}
		resp = &pb.ListDevicesResponse{Devices: append([]*pb.Device{bot}, s.devices...)}
	case "FetchAccountKey":
		resp = &pb.FetchAccountKeyResponse{}
		if s.fetched != nil {
			resp = s.fetched
		}
	case "StepDeviceLink":
		var req pb.StepDeviceLinkRequest
		_ = proto.Unmarshal(body, &req)
		if s.exchange != nil && req.GetApproverDeviceId() == s.exchange.GetApproverDeviceId() {
			s.exchange.DeviceNonce = req.GetDeviceNonce()
			s.exchange.DeviceLinkKey = req.GetDeviceLinkKey()
			s.exchange.DeviceLinkKeySignature = req.GetDeviceLinkKeySignature()
		}
		resp = &pb.StepDeviceLinkResponse{}
	default:
		http.NotFound(w, r)
		return
	}
	b, _ := proto.Marshal(resp)
	w.Header().Set("Content-Type", "application/proto")
	_, _ = w.Write(b)
}

func (s *linkServer) with(f func()) {
	s.mu.Lock()
	defer s.mu.Unlock()
	f()
}

// phone is the person's approved device.
type phone struct {
	id          string
	seed, key   []byte
	nonce       []byte
	commitment  []byte
	accountKey  []byte
	deviceEntry *pb.Device
}

func newPhone(t *testing.T, id string) *phone {
	t.Helper()
	seed, err := generateSeed()
	if err != nil {
		t.Fatal(err)
	}
	key, _ := signingPublicKey(seed)
	ak, _ := generateAccountKey()
	return &phone{id: id, seed: seed, key: key, accountKey: ak,
		deviceEntry: &pb.Device{Id: id, Platform: "ios", SigningKey: key, ApprovalState: "approved", AccountCertified: true}}
}

// commit draws nA and the signed commitment for the bot as the phone reads it.
func (p *phone) commit(t *testing.T, botKey []byte) *pb.DeviceLinkExchange {
	t.Helper()
	p.nonce = make([]byte, 32)
	_, _ = rand.Read(p.nonce)
	p.commitment, _ = deviceLinkCommitment(p.nonce)
	sig, err := signLinkCommitment(p.seed, testBotID, botKey, p.commitment)
	if err != nil {
		t.Fatal(err)
	}
	return &pb.DeviceLinkExchange{ApproverDeviceId: p.id, ApproverCommitment: p.commitment, ApproverSignature: sig}
}

func newLinkingDevice(t *testing.T) (*Device, *linkServer) {
	t.Helper()
	srv := &linkServer{}
	hs := httptest.NewServer(srv)
	t.Cleanup(hs.Close)
	d, err := Open(hs.URL, t.TempDir(), "bot")
	if err != nil {
		t.Fatal(err)
	}
	d.serverApproval = false // as against production: the test server is on localhost
	return d, srv
}

func step(t *testing.T, d *Device) LinkStatus {
	t.Helper()
	s, err := d.LinkStep(context.Background())
	if err != nil {
		t.Fatalf("LinkStep: %v", err)
	}
	return s
}

// runToApproval drives a whole pairing with the phone and returns the
// approver number the phone would show.
func runToApproval(t *testing.T, d *Device, srv *linkServer, p *phone) string {
	t.Helper()
	srv.with(func() { srv.devices = append(srv.devices, p.deviceEntry) })
	if s := step(t, d); s.State != LinkWaiting {
		t.Fatalf("before any exchange: %s", s.State)
	}
	srv.with(func() { srv.exchange = p.commit(t, d.publicKey) })
	if s := step(t, d); s.State != LinkWaiting {
		t.Fatalf("after posting the nonce: %s", s.State)
	}
	var ex *pb.DeviceLinkExchange
	srv.with(func() { ex = proto.Clone(srv.exchange).(*pb.DeviceLinkExchange) })
	if len(ex.GetDeviceNonce()) != 32 || len(ex.GetDeviceLinkKey()) != 1216 || len(ex.GetDeviceLinkKeySignature()) != 64 {
		t.Fatalf("posted nonce %d, link key %d, signature %d bytes", len(ex.GetDeviceNonce()), len(ex.GetDeviceLinkKey()), len(ex.GetDeviceLinkKeySignature()))
	}
	srv.with(func() { srv.exchange.ApproverNonce = p.nonce })
	s := step(t, d)
	want, _ := deviceLinkNumber(d.publicKey, p.key, p.commitment, ex.GetDeviceNonce(), p.nonce)
	if s.State != LinkPickNumber || s.Number != want {
		t.Fatalf("got %s %q, want pick %q", s.State, s.Number, want)
	}
	// The person taps it on the phone: the phone seals to the link key, and
	// the server deletes the exchange.
	box, err := sealAccountKey(p.seed, d.publicKey, ex.GetDeviceLinkKey(), testBotID, p.accountKey)
	if err != nil {
		t.Fatal(err)
	}
	srv.with(func() {
		srv.exchange = nil
		srv.fetched = &pb.FetchAccountKeyResponse{Box: box, ApproverDeviceId: p.id}
	})
	approverNumber, _ := deviceLinkApproverNumber(d.publicKey, p.key, p.commitment, ex.GetDeviceNonce(), p.nonce)
	return approverNumber
}

func TestLinkByNumber(t *testing.T) {
	d, srv := newLinkingDevice(t)
	p := newPhone(t, testPhoneID)
	approverNumber := runToApproval(t, d, srv, p)
	s := step(t, d)
	if s.State != LinkConfirmApprover || len(s.Choices) != 3 {
		t.Fatalf("got %s %v, want the approver's number among three", s.State, s.Choices)
	}
	found := false
	for _, c := range s.Choices {
		found = found || c == approverNumber
	}
	if !found {
		t.Fatalf("choices %v lack %s", s.Choices, approverNumber)
	}
	if again := step(t, d); strings.Join(again.Choices, ",") != strings.Join(s.Choices, ",") {
		t.Fatal("the choices must not be drawn again")
	}
	if err := d.ConfirmApprover(approverNumber); err != nil {
		t.Fatal(err)
	}
	if s := step(t, d); s.State != LinkApproved {
		t.Fatalf("after confirming: %s", s.State)
	}
	if d.state.AccountKeyHex != hex.EncodeToString(p.accountKey) {
		t.Fatal("the account key isn't the phone's")
	}
}

func TestLinkWrongApproverNumberEndsPairing(t *testing.T) {
	d, srv := newLinkingDevice(t)
	p := newPhone(t, testPhoneID)
	approverNumber := runToApproval(t, d, srv, p)
	s := step(t, d)
	var wrong string
	for _, c := range s.Choices {
		if c != approverNumber {
			wrong = c
		}
	}
	if err := d.ConfirmApprover(wrong); !errors.Is(err, ErrLinkInterrupted) {
		t.Fatalf("a wrong pick: %v", err)
	}
	if _, err := d.LinkStep(context.Background()); !errors.Is(err, ErrLinkInterrupted) {
		t.Fatalf("after a wrong pick: %v", err)
	}
	if d.state.AccountKeyHex != "" {
		t.Fatal("nothing may be approved")
	}
}

// A server in the middle lists a device of its own as approved and certified,
// and seals it an account key of its choosing. It doesn't open.
func TestLinkRefusesServersOwnApprover(t *testing.T) {
	d, srv := newLinkingDevice(t)
	p := newPhone(t, testPhoneID)
	approverNumber := runToApproval(t, d, srv, p)
	evil := newPhone(t, testEvilID)
	var linkKey []byte
	d.mu.Lock()
	linkKey = d.link.linkKey
	d.mu.Unlock()
	box, _ := sealAccountKey(evil.seed, d.publicKey, linkKey, testBotID, evil.accountKey)
	srv.with(func() {
		srv.devices = append(srv.devices, evil.deviceEntry)
		srv.fetched = &pb.FetchAccountKeyResponse{Box: box, ApproverDeviceId: evil.id}
	})
	if _, err := d.LinkStep(context.Background()); !errors.Is(err, ErrLinkInterrupted) {
		t.Fatalf("a box from another approver: %v", err)
	}
	_ = approverNumber
	if d.state.AccountKeyHex != "" {
		t.Fatal("the server's key was taken")
	}
}

// A version 1 box, the kind a server could have sealed with an approver it
// controls, doesn't open even from the confirmed approver.
func TestLinkRefusesVersionOneBox(t *testing.T) {
	d, srv := newLinkingDevice(t)
	p := newPhone(t, testPhoneID)
	approverNumber := runToApproval(t, d, srv, p)
	box, _ := sealAccountKey(p.seed, d.publicKey, nil, testBotID, p.accountKey)
	srv.with(func() { srv.fetched = &pb.FetchAccountKeyResponse{Box: box, ApproverDeviceId: p.id} })
	step(t, d)
	if err := d.ConfirmApprover(approverNumber); err != nil {
		t.Fatal(err)
	}
	if _, err := d.LinkStep(context.Background()); !errors.Is(err, ErrLinkInterrupted) {
		t.Fatalf("a version 1 box: %v", err)
	}
}

// An exchange whose signature doesn't hold for our own id and key is never
// answered; one that changes its commitment after we answered ends the pairing.
func TestLinkExchangeChecks(t *testing.T) {
	d, srv := newLinkingDevice(t)
	p := newPhone(t, testPhoneID)
	srv.with(func() { srv.devices = append(srv.devices, p.deviceEntry) })
	other, _ := generateSeed()
	otherKey, _ := signingPublicKey(other)
	srv.with(func() { srv.exchange = p.commit(t, otherKey) }) // signed for another key
	step(t, d)
	srv.with(func() {
		if len(srv.exchange.GetDeviceNonce()) != 0 {
			t.Fatal("answered an exchange signed for another device key")
		}
	})
	srv.with(func() { srv.exchange = p.commit(t, d.publicKey) })
	step(t, d)
	srv.with(func() {
		nonce := srv.exchange.GetDeviceNonce()
		srv.exchange = p.commit(t, d.publicKey) // a fresh commitment
		srv.exchange.DeviceNonce = nonce
	})
	if _, err := d.LinkStep(context.Background()); !errors.Is(err, ErrLinkInterrupted) {
		t.Fatalf("a changed commitment: %v", err)
	}
}

// The same nonce and link key are posted again when the server lost them.
func TestLinkRepostsSameNonce(t *testing.T) {
	d, srv := newLinkingDevice(t)
	p := newPhone(t, testPhoneID)
	srv.with(func() {
		srv.devices = append(srv.devices, p.deviceEntry)
		srv.exchange = p.commit(t, d.publicKey)
	})
	step(t, d)
	var first []byte
	srv.with(func() {
		first = bytes.Clone(srv.exchange.GetDeviceNonce())
		srv.exchange.DeviceNonce, srv.exchange.DeviceLinkKey, srv.exchange.DeviceLinkKeySignature = nil, nil, nil
	})
	step(t, d)
	srv.with(func() {
		if !bytes.Equal(srv.exchange.GetDeviceNonce(), first) {
			t.Fatal("a fresh nonce was posted")
		}
	})
}

func TestLocalServer(t *testing.T) {
	for base, want := range map[string]bool{
		"http://localhost:8787": true, "http://127.0.0.1:5000": true, "https://api.pchy.app": false,
		"https://localhost.evil.example": false,
	} {
		if localServer(base) != want {
			t.Errorf("localServer(%q) != %v", base, want)
		}
	}
}

func TestWithDecoys(t *testing.T) {
	for i := 0; i < 200; i++ {
		c, err := withDecoys("07")
		if err != nil {
			t.Fatal(err)
		}
		seen := map[string]bool{}
		for _, n := range c {
			if len(n) != 2 || seen[n] {
				t.Fatalf("choices %v", c)
			}
			seen[n] = true
		}
		if !seen["07"] {
			t.Fatalf("choices %v lack the right one", c)
		}
	}
}

func TestDoorFor(t *testing.T) {
	cases := []struct {
		mailbox pb.MailboxKind
		kind    uint8
		want    bool
	}{
		{pb.MailboxKind_MAILBOX_KIND_COMMIT, envelopeCommit, true},
		{pb.MailboxKind_MAILBOX_KIND_MLS, envelopeMessage, true},
		{pb.MailboxKind_MAILBOX_KIND_MLS, envelopeCommit, false}, // a commit through SendSealed skipped the head
		{pb.MailboxKind_MAILBOX_KIND_COMMIT, envelopeMessage, false},
		{pb.MailboxKind_MAILBOX_KIND_MLS, 3, false},
	}
	for _, c := range cases {
		if got := doorFor(c.mailbox, c.kind); got != c.want {
			t.Errorf("doorFor(%v, %d) = %v", c.mailbox, c.kind, got)
		}
	}
}

// A local test server approves a device itself, with a version 1 box and
// no number exchange: only a device talking to this machine takes it.
func TestLinkLocalServerApproval(t *testing.T) {
	d, srv := newLinkingDevice(t)
	d.serverApproval = true
	p := newPhone(t, testPhoneID)
	step(t, d)
	box, _ := sealAccountKey(p.seed, d.publicKey, nil, testBotID, p.accountKey)
	srv.with(func() {
		srv.devices = append(srv.devices, p.deviceEntry)
		srv.fetched = &pb.FetchAccountKeyResponse{Box: box, ApproverDeviceId: p.id}
	})
	if s := step(t, d); s.State != LinkApproved {
		t.Fatalf("local server approval: %s", s.State)
	}
}
