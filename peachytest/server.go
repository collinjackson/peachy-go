// Package peachytest is an in-memory fake Peachy server for integration
// tests: enough of ChatService, and the two plain HTTP paths beside it, for
// peachy-go's Devices (and programs built on them, such as the bridge) to
// sign in, link, publish key packages, found groups, send and receive
// sealed messages and files, with no Peachy account and no network.
//
// It is built only from peachy-protocol's published protos and docs, and
// cites the doc section for each rule it applies. It is not a Peachy
// server: it keeps everything in memory, meters nothing, and runs each
// account's "phone" itself (a server-run approver, as identity.md allows for
// a test server), which approves every new device at once with a version-1
// box. Where the docs leave a behavior open it does the simplest thing that
// agrees with them, and says so in a comment.
//
// It is pure Go (no cgo), and listens on 127.0.0.1, which peachy-go treats as
// a local test server: it trusts the fake's published credential keys and
// accepts its version-1 boxes.
//
//	srv := peachytest.Start(t)
//	srv.AddAccount("+15555550100", "Alice", "alice")
//	dev, _ := peachy.Open(srv.URL, dir, "test")
//	dev.StartLogin(ctx, "+15555550100")
//	dev.FinishLogin(ctx, "+15555550100", peachytest.Code)
//	for st, _ := dev.LinkStep(ctx); st.State != peachy.LinkApproved; ... {}
//	dev.Connect(ctx)
package peachytest

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/collinjackson/peachy-go/pb"
)

// Code is the verification code VerifyPhone takes for every number.
const Code = "123456"

// Server is one fake Peachy server. Its methods are safe for concurrent use.
type Server struct {
	// URL is the server's base address (http://127.0.0.1:port), what
	// peachy.Open takes.
	URL string

	hs *httptest.Server

	mu       sync.Mutex
	issuer   ed25519.PrivateKey
	now      func() time.Time
	accounts map[string]*account // by actor id
	byPhone  map[string]*account
	sessions map[string]*session      // by bearer token
	devices  map[string]*device       // by device id
	heads    map[string]*head         // by string(handle)
	payloads map[string]*payload      // by envelope id
	retries  map[string]string        // client_message_id → envelope id
	objects  map[string][]byte        // object key → bytes
	uploads  map[string]upload        // upload token → what may go up
	held     map[string]chan struct{} // actor → closed when its held calls may go on
	streams  map[string]map[*subscriber]bool
	pageSize int            // heads per sweep page
	commits  map[string]int // commits taken, by committing device

	hideBotRows bool
}

type account struct {
	id, phone, name, handle string
	created                 time.Time
	accountKey              []byte
	identity                ed25519.PrivateKey
	approver                *device
	approverSeed            []byte
	accessKeyHash           []byte
	store                   store
	bot                     bool // a bot's account: its devices get pdc3 credentials
}

type session struct {
	token, id string
	actor     string
}

type device struct {
	id, actor, installID, platform string
	mls                            bool
	signingKey                     []byte
	created                        time.Time
	approval                       string // approved, pending
	certified                      bool
	accountKey, accountSig         []byte
	revoked                        *time.Time
	sessions                       map[string]bool // session ids linked to the row
	exchanges                      map[string]*pb.DeviceLinkExchange
	box                            []byte
	approvedBy                     string
	serverRun                      bool

	mailboxOpen bool
	mailbox     []*entry
	lost        bool
	packages    []*pb.MlsKeyPackage
	lastResort  *pb.MlsKeyPackage
}

type entry struct {
	env       *pb.MailboxEnvelope
	payloadID string
}

type payload struct {
	refs     int
	retryKey string
}

type head struct {
	epoch    uint64
	verifier []byte
	stampSet [][]byte // the admins' stamp keys, once a founding enrolled them
}

type upload struct {
	key    string
	length int64
}

type subscriber struct {
	mu      sync.Mutex
	domains map[pb.StateDomain]bool
	wake    chan struct{}
}

// Start starts a server that closes when the test ends.
func Start(tb testing.TB) *Server {
	s := New()
	tb.Cleanup(s.Close)
	return s
}

// New starts a server; Close stops it.
func New() *Server {
	s := &Server{
		issuer:   ed25519.NewKeyFromSeed(randomBytes(32)),
		now:      time.Now,
		accounts: map[string]*account{},
		byPhone:  map[string]*account{},
		sessions: map[string]*session{},
		devices:  map[string]*device{},
		heads:    map[string]*head{},
		payloads: map[string]*payload{},
		retries:  map[string]string{},
		objects:  map[string][]byte{},
		uploads:  map[string]upload{},
		streams:  map[string]map[*subscriber]bool{},
		pageSize: 5000,
		commits:  map[string]int{},
	}
	s.hs = httptest.NewServer(s.handler())
	s.URL = s.hs.URL
	return s
}

// Close stops the server.
func (s *Server) Close() {
	s.hs.CloseClientConnections()
	s.hs.Close()
}

// AddAccount creates an account for phone (E.164), with a display name and
// handle (without the @; "" for none), and returns its actor id. Its
// server-run approver founds the account: it mints the account key, pins
// the identity key and writes the account store's first manifest, which
// holds an access key (account-store.md "A device without the key", step 4).
//
// The account key is minted in the two-key form (64 bytes: store key, then
// identity root), as a first device does from peachy-protocol 0.3.0 on
// (account-store.md "The held account key"); AddAccountOneKey mints the
// 32-byte form an older account holds.
func (s *Server) AddAccount(phone, name, handle string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.addAccount(phone, name, handle).id
}

// AddAccountOneKey is AddAccount with a 32-byte (one-key) account key.
func (s *Server) AddAccountOneKey(phone, name, handle string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.addAccountKey(phone, name, handle, randomBytes(32)).id
}

// AddBot is AddAccount for a bot: its devices are issued pdc3 credentials
// once certified, and GetUsers names it USER_KIND_BOT. A real bot signs in
// with a connect code, not a phone (bots.md "Bot accounts"); the fake lets
// a test Device sign in as one by phone, a shortcut no real server takes.
func (s *Server) AddBot(phone, name, handle string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	a := s.addAccount(phone, name, handle)
	a.bot = true
	return a.id
}

func (s *Server) addAccount(phone, name, handle string) *account {
	return s.addAccountKey(phone, name, handle, randomBytes(64))
}

func (s *Server) addAccountKey(phone, name, handle string, accountKey []byte) *account {
	now := s.now()
	a := &account{id: newUUID(), phone: phone, name: name, handle: handle, created: now,
		accountKey: accountKey, approverSeed: randomBytes(32)}
	a.identity = accountIdentity(a.accountKey)
	pub := ed25519.NewKeyFromSeed(a.approverSeed).Public().(ed25519.PublicKey)
	a.approver = &device{id: newUUID(), actor: a.id, installID: "server-run-" + newUUID(), platform: "ios", mls: true,
		signingKey: pub, created: now, approval: "approved", certified: true, serverRun: true,
		accountKey: a.identity.Public().(ed25519.PublicKey), accountSig: certifyDevice(a.identity, pub),
		sessions: map[string]bool{}}
	s.devices[a.approver.id] = a.approver
	s.accounts[a.id] = a
	s.byPhone[phone] = a
	a.store.init(a.accountKey, now)
	return a
}

// AccountKey is the account key of actor, which the server-run approver
// holds (as Peachy's service holds it only for its store-review login).
func (s *Server) AccountKey(actor string) []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	if a := s.accounts[actor]; a != nil {
		return append([]byte(nil), a.accountKey...)
	}
	return nil
}

// Devices is actor's live device ids, other than its server-run approver.
func (s *Server) Devices(actor string) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []string
	for _, d := range s.devices {
		if d.actor == actor && !d.serverRun && d.revoked == nil {
			out = append(out, d.id)
		}
	}
	sort.Strings(out)
	return out
}

// LoseMailbox drops every entry waiting for device, as if they expired
// uncollected; its next FetchMailbox says lost (delivery.md "FetchMailbox
// and AckMailbox").
func (s *Server) LoseMailbox(deviceID string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	d := s.devices[deviceID]
	if d == nil {
		return 0
	}
	n := len(d.mailbox)
	for _, e := range d.mailbox {
		s.release(e.payloadID)
	}
	d.mailbox = nil
	d.lost = true
	return n
}

// Waiting is how many entries wait in device's mailbox.
func (s *Server) Waiting(deviceID string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	if d := s.devices[deviceID]; d != nil {
		return len(d.mailbox)
	}
	return 0
}

// SetHeadPageSize sets how many heads one sweep page holds (5000 by
// default), so a test can make the sweep page.
func (s *Server) SetHeadPageSize(n int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pageSize = max(n, 1)
}

// Commits is how many commits the server took from device.
func (s *Server) Commits(device string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.commits[device]
}

// HideBotRows makes GetUsers leave out bots' rows, as Peachy's server does
// for a client it doesn't serve bots to (bots.md, Conventions).
func (s *Server) HideBotRows() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.hideBotRows = true
}

// StampSet is how many stamp keys the handle's set holds (0: none).
func (s *Server) StampSet(handle []byte) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	if h := s.heads[string(handle)]; h != nil {
		return len(h.stampSet)
	}
	return 0
}

// Head is a conversation head's epoch and verifier, and whether the server
// holds one for handle.
func (s *Server) Head(handle []byte) (uint64, []byte, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	h := s.heads[string(handle)]
	if h == nil {
		return 0, nil, false
	}
	return h.epoch, append([]byte(nil), h.verifier...), true
}

// caller is who a request comes from: a session, or none.
type caller struct {
	token   string
	session *session
}

func errorf(code connect.Code, msg string) error { return connect.NewError(code, errors.New(msg)) }

var errUnauthenticated = errorf(connect.CodeUnauthenticated, "sign in first")

// needSession is the caller's session, or unauthenticated (identity.md
// "Signing in": a missing, unknown or ended session).
func (c *caller) needSession() (*session, error) {
	if c.session == nil {
		return nil, errUnauthenticated
	}
	return c.session, nil
}

func unary[Req, Resp any](s *Server, mux *http.ServeMux, method string, f func(c *caller, req *Req) (*Resp, error)) {
	path := "/peachy.v1.ChatService/" + method
	mux.Handle(path, connect.NewUnaryHandler(path, func(ctx context.Context, r *connect.Request[Req]) (*connect.Response[Resp], error) {
		if method == "SendSealed" {
			s.mu.Lock()
			var wait chan struct{}
			if c := s.caller(r.Header()); c.session != nil {
				wait = s.held[c.session.actor]
			}
			s.mu.Unlock()
			if wait != nil {
				select {
				case <-wait:
				case <-ctx.Done():
					return nil, connect.NewError(connect.CodeCanceled, ctx.Err())
				}
			}
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		resp, err := f(s.caller(r.Header()), r.Msg)
		if err != nil {
			return nil, err
		}
		return connect.NewResponse(resp), nil
	}))
}

func (s *Server) caller(h http.Header) *caller {
	token, ok := strings.CutPrefix(h.Get("Authorization"), "Bearer ")
	if !ok || token == "" {
		return &caller{}
	}
	return &caller{token: token, session: s.sessions[token]}
}

func (s *Server) handler() http.Handler {
	mux := http.NewServeMux()
	unary(s, mux, "StartPhoneVerification", s.startPhoneVerification)
	unary(s, mux, "VerifyPhone", s.verifyPhone)
	unary(s, mux, "RegisterDevice", s.registerDevice)
	unary(s, mux, "ListDevices", s.listDevices)
	unary(s, mux, "StepDeviceLink", s.stepDeviceLink)
	unary(s, mux, "FetchAccountKey", s.fetchAccountKey)
	unary(s, mux, "GetMe", s.getMe)
	unary(s, mux, "GetUsers", s.getUsers)
	unary(s, mux, "SetAccessKey", s.setAccessKey)
	unary(s, mux, "ReadStore", s.readStore)
	unary(s, mux, "WriteStore", s.writeStore)
	unary(s, mux, "PublishKeyPackages", s.publishKeyPackages)
	unary(s, mux, "FetchKeyPackages", s.fetchKeyPackages)
	unary(s, mux, "FetchKeyPackagesAnonymous", s.fetchKeyPackagesAnonymous)
	unary(s, mux, "CreateHandle", s.createHandle)
	unary(s, mux, "SubmitCommit", s.submitCommit)
	unary(s, mux, "FetchConversationHead", s.fetchConversationHead)
	unary(s, mux, "SendSealed", s.sendSealed)
	unary(s, mux, "FetchMailbox", s.fetchMailbox)
	unary(s, mux, "AckMailbox", s.ackMailbox)
	unary(s, mux, "CreateUpload", s.createUpload)
	streamPath := "/peachy.v1.ChatService/StreamEvents"
	mux.Handle(streamPath, connect.NewServerStreamHandler(streamPath, s.streamEvents))
	mux.HandleFunc("GET /healthz/device-credential-keys", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(PublishedKeys(s.issuer.Public().(ed25519.PublicKey))))
	})
	mux.HandleFunc("PUT /upload/{token}", s.putObject)
	mux.HandleFunc("GET /media/{key...}", s.getObject)
	return mux
}

func ts(t time.Time) *timestamppb.Timestamp { return timestamppb.New(t.Truncate(time.Second)) }

// poke tells actor's open streams that domain moved (delivery.md
// "Realtime: StreamEvents"). Called with s.mu held.
func (s *Server) poke(actor string, domain pb.StateDomain) {
	for sub := range s.streams[actor] {
		sub.mu.Lock()
		sub.domains[domain] = true
		sub.mu.Unlock()
		select {
		case sub.wake <- struct{}{}:
		default:
		}
	}
}

// streamEvents opens with state_versions, then sends a state_changed for
// each poke. It never carries the mailbox (StreamEventsRequest
// .mailbox_device_id is ignored, which delivery.md "The mailbox on the
// stream" allows) and relays no ephemeral frames.
func (s *Server) streamEvents(ctx context.Context, r *connect.Request[pb.StreamEventsRequest], out *connect.ServerStream[pb.StreamEventsResponse]) error {
	s.mu.Lock()
	sess := s.caller(r.Header()).session
	if sess == nil {
		s.mu.Unlock()
		return errUnauthenticated
	}
	sub := &subscriber{domains: map[pb.StateDomain]bool{}, wake: make(chan struct{}, 1)}
	if s.streams[sess.actor] == nil {
		s.streams[sess.actor] = map[*subscriber]bool{}
	}
	s.streams[sess.actor][sub] = true
	version := s.accounts[sess.actor].store.version
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		delete(s.streams[sess.actor], sub)
		s.mu.Unlock()
	}()
	first := &pb.StreamEventsResponse{StateVersions: &pb.StateVersions{Domains: []*pb.StateDomainVersion{
		{Domain: pb.StateDomain_STATE_DOMAIN_ACCOUNT_STORE, Version: version}}}}
	if err := out.Send(first); err != nil {
		return err
	}
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-sub.wake:
		}
		sub.mu.Lock()
		var domains []pb.StateDomain
		for d := range sub.domains {
			domains = append(domains, d)
		}
		sub.domains = map[pb.StateDomain]bool{}
		sub.mu.Unlock()
		sort.Slice(domains, func(i, j int) bool { return domains[i] < domains[j] })
		if err := out.Send(&pb.StreamEventsResponse{StateChanged: &pb.StateChangedEvent{Domains: domains}}); err != nil {
			return err
		}
	}
}

// storeAccountRecord is the account record AddAccount writes.
func accountRecord(accessKey []byte, at time.Time) []byte {
	b, _ := json.Marshal(struct {
		Kind  string         `json:"kind"`
		Key   string         `json:"key"`
		At    int64          `json:"at"`
		Value map[string]any `json:"value"`
	}{"account", "", at.UnixMilli(), map[string]any{"accessKey": base64.StdEncoding.EncodeToString(accessKey)}})
	return b
}

// HasAccessKey is whether actor's device registered an access key
// (SetAccessKey).
// HoldSends makes the account's SendSealed calls hang, as a connection that
// dropped without a reset does, until the returned release is called or the
// caller gives up.
func (s *Server) HoldSends(actor string) (release func()) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.held == nil {
		s.held = map[string]chan struct{}{}
	}
	ch := make(chan struct{})
	s.held[actor] = ch
	var once sync.Once
	return func() {
		once.Do(func() {
			s.mu.Lock()
			if s.held[actor] == ch {
				delete(s.held, actor)
			}
			s.mu.Unlock()
			close(ch)
		})
	}
}

func (s *Server) HasAccessKey(actor string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	a := s.accounts[actor]
	return a != nil && a.accessKeyHash != nil
}
