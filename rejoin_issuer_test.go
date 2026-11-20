//go:build testissuer

package peachy

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"

	"github.com/collinjackson/peachy-go/pb"
)

// fakePeachy answers the calls a mailbox pass, a head sweep and a seat ask
// make. heads is what the sweep returns.
type fakePeachy struct {
	mu      sync.Mutex
	mailbox []*pb.MailboxEnvelope
	sent    []*pb.SendSealedRequest
	heads   []*pb.ConversationHead
	sweeps  int
}

func (f *fakePeachy) setHead(h *pb.ConversationHead) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.heads = []*pb.ConversationHead{h}
}

func (f *fakePeachy) deliver(kind pb.MailboxKind, payload []byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	id, _ := uuidV4()
	f.mailbox = append(f.mailbox, &pb.MailboxEnvelope{Id: id, Kind: kind, Payload: payload})
}

func (f *fakePeachy) serve(t *testing.T) *httptest.Server {
	mux := http.NewServeMux()
	mux.Handle("/peachy.v1.ChatService/FetchMailbox", connect.NewUnaryHandler("/peachy.v1.ChatService/FetchMailbox",
		func(_ context.Context, _ *connect.Request[pb.FetchMailboxRequest]) (*connect.Response[pb.FetchMailboxResponse], error) {
			f.mu.Lock()
			defer f.mu.Unlock()
			page := f.mailbox
			f.mailbox = nil
			return connect.NewResponse(&pb.FetchMailboxResponse{Envelopes: page}), nil
		}))
	mux.Handle("/peachy.v1.ChatService/AckMailbox", connect.NewUnaryHandler("/peachy.v1.ChatService/AckMailbox",
		func(_ context.Context, _ *connect.Request[pb.AckMailboxRequest]) (*connect.Response[pb.AckMailboxResponse], error) {
			return connect.NewResponse(&pb.AckMailboxResponse{}), nil
		}))
	mux.Handle("/peachy.v1.ChatService/SendSealed", connect.NewUnaryHandler("/peachy.v1.ChatService/SendSealed",
		func(_ context.Context, req *connect.Request[pb.SendSealedRequest]) (*connect.Response[pb.SendSealedResponse], error) {
			f.mu.Lock()
			defer f.mu.Unlock()
			f.sent = append(f.sent, req.Msg)
			return connect.NewResponse(&pb.SendSealedResponse{}), nil
		}))
	mux.Handle("/peachy.v1.ChatService/FetchConversationHead", connect.NewUnaryHandler("/peachy.v1.ChatService/FetchConversationHead",
		func(_ context.Context, req *connect.Request[pb.FetchConversationHeadRequest]) (*connect.Response[pb.FetchConversationHeadResponse], error) {
			f.mu.Lock()
			defer f.mu.Unlock()
			if !req.Msg.GetEvery() || len(req.Msg.GetHandles()) > 0 {
				return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("only the sweep"))
			}
			f.sweeps++
			return connect.NewResponse(&pb.FetchConversationHeadResponse{Heads: f.heads}), nil
		}))
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func (f *fakePeachy) asks() []*pb.SendSealedRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]*pb.SendSealedRequest(nil), f.sent...)
}

func mustSeed(t *testing.T) []byte {
	s, err := generateSeed()
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// A copy that fell behind (here: commits it never saw) reads nothing and is
// read by nobody. A message sealed past it makes Poll read the group's head;
// when the engine judges the copy behind, Poll forgets it and sends a signed
// seat ask to the leaves it last saw; the member who drains the
// ask verifies it and re-seats the device, whose next mailbox pass takes the
// Welcome, drops the rejoin, and reads the group again.
func TestStuckGroupRejoinsThroughASeatAsk(t *testing.T) {
	issuerSeed := make([]byte, 32)
	issuerSeed[0] = 7
	issuer, err := newTestIssuer(issuerSeed)
	if err != nil {
		t.Fatal(err)
	}
	defer issuer.close()
	trusted, err := issuer.publishedKeys()
	if err != nil {
		t.Fatal(err)
	}
	client := func(actor, device string) *mlsClient {
		seed := mustSeed(t)
		cred, err := issuer.issue(actor, device, seed)
		if err != nil {
			t.Fatal(err)
		}
		m, err := newMemoryMLS(actor, cred, seed, trusted)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(m.close)
		return m
	}
	ada := client("actor-ada", "device-ada")
	bot := client("actor-bot", "device-bot")

	gid, _ := uuidV4()
	group := []byte(gid)
	if err := ada.create(group); err != nil {
		t.Fatal(err)
	}
	kp, err := bot.keyPackage(false)
	if err != nil {
		t.Fatal(err)
	}
	welcome, err := ada.addMember(group, kp.pkg)
	if err != nil {
		t.Fatal(err)
	}

	fake := &fakePeachy{}
	srv := fake.serve(t)
	d := &Device{rpc: newRPC(srv.URL), dir: t.TempDir(), state: &deviceState{DeviceID: "device-bot"}, mls: bot}
	ctx := context.Background()
	poll := func() []Event {
		t.Helper()
		events, _, err := d.Poll(ctx)
		if err != nil {
			t.Fatal(err)
		}
		return events
	}
	say := func(text string) {
		t.Helper()
		id, _ := uuidV4()
		body, _ := json.Marshal(map[string]any{"i": id, "t": text})
		ct, err := ada.encrypt(group, append([]byte{frameByte, frameVersion}, body...))
		if err != nil {
			t.Fatal(err)
		}
		env, err := ada.sealEnvelope(group, envelopeMessage, ct)
		if err != nil {
			t.Fatal(err)
		}
		fake.deliver(pb.MailboxKind_MAILBOX_KIND_MLS, env)
	}
	texts := func(events []Event) []string {
		var out []string
		for _, e := range events {
			if e.Type == EventMessage {
				out = append(out, e.Text)
			}
		}
		return out
	}

	fake.deliver(pb.MailboxKind_MAILBOX_KIND_WELCOME, welcome)
	say("hello")
	if got := texts(poll()); len(got) != 1 || got[0] != "hello" {
		t.Fatalf("before: %v", got)
	}

	handle, err := groupHandle(group)
	if err != nil {
		t.Fatal(err)
	}
	headNow := func(m *mlsClient) *pb.ConversationHead {
		t.Helper()
		epoch, verifier, err := m.head(group)
		if err != nil {
			t.Fatal(err)
		}
		return &pb.ConversationHead{Handle: handle, Epoch: epoch, Verifier: verifier}
	}

	// A message framed past the copy, while the server's head is the bot's
	// own: anyone holding the group id can write that framing, so the engine
	// keeps the copy and nothing is asked.
	botHead := headNow(bot)
	fake.setHead(botHead)
	if err := ada.selfUpdate(group); err != nil {
		t.Fatal(err)
	}
	say("one")
	if got := texts(poll()); len(got) != 0 || len(fake.asks()) != 0 {
		t.Fatalf("head in step: read %v, asked %d times", got, len(fake.asks()))
	}
	if fake.sweeps == 0 {
		t.Fatal("no head read for a message sealed past the copy")
	}
	if held, _ := d.holds(gid); !held {
		t.Fatal("forgot the group on the framing alone")
	}

	// Ada's copy moves on again, and the head now shows the bot behind: the
	// engine strands the copy, and Poll forgets it and asks for a seat.
	if err := ada.selfUpdate(group); err != nil {
		t.Fatal(err)
	}
	fake.setHead(headNow(ada))
	d.sweep = nil              // the next read is after the head moved
	d.allChecked = time.Time{} // and ten minutes on
	say("two")
	poll()

	asks := fake.asks()
	if len(asks) != 1 {
		t.Fatalf("asked %d times with the head ahead", len(asks))
	}
	ask := asks[0]
	if ask.Urgent || len(ask.Recipients) != 1 || ask.Recipients[0].UserId != "actor-ada" || ask.Recipients[0].DeviceId != "device-ada" {
		t.Fatalf("ask went to %v (urgent %v)", ask.Recipients, ask.Urgent)
	}
	if held, _ := d.holds(gid); held {
		t.Fatal("the stuck copy is still held")
	}
	r := d.rejoins[gid]
	if r == nil || r.Asks != 1 || time.Until(time.UnixMilli(r.NextMS)) < 9*time.Minute {
		t.Fatalf("rejoin %+v", r)
	}
	if on, err := loadRejoins(d.dir); err != nil || on[gid] == nil {
		t.Fatalf("rejoin not on disk: %v", err)
	}

	// Not due yet: no second ask.
	d.RetryRejoins(ctx)
	if n := len(fake.asks()); n != 1 {
		t.Fatalf("asked again before the wait: %d", n)
	}

	// Ada drains the ask as a member does (delivery.md: a member serving the ask).
	g, kind, inner, err := ada.openEnvelope(ask.Payload)
	if err != nil || string(g) != gid || kind != envelopeSeatAsk {
		t.Fatalf("ask opened as group %q kind %d: %v", g, kind, err)
	}
	var dap struct{ D, A, P string }
	if err := json.Unmarshal(inner, &dap); err != nil || dap.D != "device-bot" || dap.A != "actor-bot" {
		t.Fatalf("ask %s: %v", inner, err)
	}
	proof, err := base64.StdEncoding.DecodeString(dap.P)
	if err != nil || len(proof) != 89 {
		t.Fatalf("proof %q", dap.P)
	}
	fresh, err := bot.keyPackage(false)
	if err != nil {
		t.Fatal(err)
	}
	if verdict, err := ada.verifyJoinRequest(group, dap.A, dap.D, proof, fresh.pkg); err != nil || verdict != 0 {
		t.Fatalf("verdict %d: %v", verdict, err)
	}
	leaf, ok, err := ada.leafOf(group, dap.D)
	if err != nil || !ok {
		t.Fatalf("the bot's old leaf: %v %v", ok, err)
	}
	reseat, err := ada.replaceMember(group, leaf, fresh.pkg)
	if err != nil {
		t.Fatal(err)
	}

	fake.deliver(pb.MailboxKind_MAILBOX_KIND_WELCOME, reseat)
	say("welcome back")
	events := poll()
	if got := texts(events); len(got) != 1 || got[0] != "welcome back" {
		t.Fatalf("after the reseat: %v", got)
	}
	if d.rejoins[gid] != nil {
		t.Fatal("the rejoin outlived the Welcome")
	}
	if on, _ := loadRejoins(d.dir); on[gid] != nil {
		t.Fatal("the rejoin is still on disk")
	}

	// And the bot's sends reach Ada again.
	if err := d.sealTo(ctx, gid, []byte("x"), true, "", nil); err != nil {
		t.Fatal(err)
	}
	last := fake.asks()[len(fake.asks())-1]
	g, kind, inner, err = ada.openEnvelope(last.Payload)
	if err != nil || kind != envelopeMessage {
		t.Fatalf("send: kind %d %v", kind, err)
	}
	if inc, err := ada.process(g, inner, false, 0); err != nil || string(inc.plaintext) != "x" {
		t.Fatalf("ada reads %q: %v", inc.plaintext, err)
	}
}

// A group already forgotten (by hand, before the daemon rejoined by itself)
// is asked for with the devices named, and asked again once the wait is over.
func TestRejoinOfAForgottenGroupAsksTheNamedDevicesAndRepeats(t *testing.T) {
	issuerSeed := make([]byte, 32)
	issuerSeed[0] = 9
	issuer, err := newTestIssuer(issuerSeed)
	if err != nil {
		t.Fatal(err)
	}
	defer issuer.close()
	trusted, _ := issuer.publishedKeys()
	seed := mustSeed(t)
	cred, err := issuer.issue("actor-bot", "device-bot", seed)
	if err != nil {
		t.Fatal(err)
	}
	bot, err := newMemoryMLS("actor-bot", cred, seed, trusted)
	if err != nil {
		t.Fatal(err)
	}
	defer bot.close()
	fake := &fakePeachy{}
	d := &Device{rpc: newRPC(fake.serve(t).URL), dir: t.TempDir(), state: &deviceState{DeviceID: "device-bot"}, mls: bot}
	ctx := context.Background()
	gid, _ := uuidV4()

	if err := d.Rejoin(ctx, gid, nil); err == nil || !strings.Contains(err.Error(), "no devices") {
		t.Fatalf("with nobody to ask: %v", err)
	}
	to := []Recipient{{User: "actor-ada", Device: "device-ada"}, {User: "actor-bo", Device: "device-bo"}}
	if err := d.Rejoin(ctx, gid, to); err != nil {
		t.Fatal(err)
	}
	if asks := fake.asks(); len(asks) != 1 || len(asks[0].Recipients) != 2 {
		t.Fatalf("asks %v", asks)
	}
	d.rejoins[gid].NextMS = time.Now().UnixMilli() - 1
	d.RetryRejoins(ctx)
	if asks := fake.asks(); len(asks) != 2 || len(asks[1].Recipients) != 2 {
		t.Fatalf("no second ask: %d", len(asks))
	}
	if r := d.rejoins[gid]; r.Asks != 2 || time.Until(time.UnixMilli(r.NextMS)) < 19*time.Minute {
		t.Fatalf("second wait %+v", r)
	}
}
