// Package peachy is a Peachy client: one linked device, what the bridge
// drives. It talks to Peachy's API itself and leaves the cryptography to
// Peachy's MLS engine (mls.go), the same split as mautrix-signal over
// libsignal.
//
// The steps, each a call the bridge makes when it's ready:
//
//  1. Open loads the saved device, or mints a seed for a new one.
//  2. StartLogin and FinishLogin: phone and code.
//  3. LinkStep, repeated: registers, then reports the number to pick on the
//     phone, until an approver has sealed the account key to us.
//  4. Connect: certifies, opens the MLS store, publishes key packages once.
//  5. Poll drains the mailbox into Events; SendText and SendMedia send, and
//     Download fetches and opens a message's attachment.
package peachy

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog"

	"github.com/collinjackson/peachy-go/pb"
)

const (
	keyPackages  = 20
	noteIDBytes  = 16
	frameByte    = 0xff
	frameVersion = 5
)

// Device is one linked Peachy device. Safe for concurrent use: calls that
// touch the MLS state or the saved device run one at a time; downloads and
// uploads run alongside them.
type Device struct {
	rpc  *rpc
	dir  string
	name string

	mu        sync.Mutex
	state     *deviceState
	seed      []byte
	publicKey []byte
	mls       *mlsClient

	mediaMu   sync.Mutex
	mediaBase string

	// Receipts sent to their authors only, per conversation, since the last
	// one that went to everyone (see Receipt).
	narrowMarks map[string]int

	// The account store as last read (ReadStore).
	store *Store

	// The linking attempt under way (link.go), nil when none.
	link *pairing
	// The account's access key once the server holds it (accesskey.go),
	// handed to members in every message and hello.
	accessKey []byte
	// Whether a box no person vouched for may open: only for a server on
	// this machine (localServer), which approves devices itself.
	serverApproval bool

	// The last sweep of conversation heads (recovery.go), reused briefly.
	sweep *headSweep
	// When every group was last checked against its head.
	allChecked time.Time
	ownSent    map[string]time.Time // nonces of envelopes sent, until they come back

	// Groups forgotten and waiting for a seat (rejoin.go), as in rejoins.json.
	rejoins map[string]*rejoin
}

// GroupError is an envelope of one of our groups that its MLS state refused.
type GroupError struct {
	Group string
	Err   error
}

func (e *GroupError) Error() string { return e.Err.Error() }
func (e *GroupError) Unwrap() error { return e.Err }

// Open opens (or creates) the device kept in dataDir. name is what Peachy's
// Devices list calls it when it links; a device already linked keeps the
// name it linked with.
func Open(server, dataDir, name string) (*Device, error) {
	state, err := loadState(dataDir)
	if err != nil {
		return nil, err
	}
	if state == nil {
		seed, err := generateSeed()
		if err != nil {
			return nil, err
		}
		install := make([]byte, 16)
		if _, err := rand.Read(install); err != nil {
			return nil, err
		}
		state = &deviceState{SeedHex: hex.EncodeToString(seed), InstallID: hex.EncodeToString(install)}
		if err := state.save(dataDir); err != nil {
			return nil, err
		}
	}
	seed, err := state.seed()
	if err != nil {
		return nil, err
	}
	pub, err := signingPublicKey(seed)
	if err != nil {
		return nil, err
	}
	r := newRPC(server)
	r.token = state.SessionToken
	return &Device{rpc: r, dir: dataDir, name: name, state: state, seed: seed, publicKey: pub,
		serverApproval: localServer(server)}, nil
}

// keepPrivate makes the device's folder and MLS store readable by its owner
// only. The engine creates the store with the default mode, and SQLite gives
// its -wal and -shm files the store's.
func keepPrivate(dir, store string) error {
	if err := os.Chmod(dir, 0o700); err != nil {
		return err
	}
	for _, f := range []string{store, store + "-wal", store + "-shm"} {
		if err := os.Chmod(f, 0o600); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return nil
}

// Close frees the MLS client. The device must not be used afterwards.
func (d *Device) Close() {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.mls != nil {
		d.mls.close()
		d.mls = nil
	}
}

type Status struct {
	SignedIn bool
	Linked   bool
}

func (d *Device) Status() Status {
	d.mu.Lock()
	defer d.mu.Unlock()
	return Status{SignedIn: d.state.SessionToken != "", Linked: d.state.AccountKeyHex != ""}
}

func (d *Device) StartLogin(ctx context.Context, phone string) error {
	_, err := call[pb.StartPhoneVerificationRequest, pb.StartPhoneVerificationResponse](ctx, d.rpc, "StartPhoneVerification",
		&pb.StartPhoneVerificationRequest{Phone: phone})
	return err
}

// FinishLogin returns the person's Peachy display name.
func (d *Device) FinishLogin(ctx context.Context, phone, code string) (string, error) {
	verified, err := call[pb.VerifyPhoneRequest, pb.VerifyPhoneResponse](ctx, d.rpc, "VerifyPhone",
		&pb.VerifyPhoneRequest{Phone: phone, Code: code})
	if err != nil {
		return "", err
	}
	if verified.RegistrationLock != nil {
		// Answering the lock means restoring the account key from Peachy's
		// PIN vault, which this bridge doesn't do yet.
		return "", errors.New("Registration lock is on for this Peachy account. Turn it off in Peachy (Settings → PIN), connect the bridge, then turn it back on: the bridge keeps working")
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.state.SessionToken = verified.SessionToken
	if err := d.state.save(d.dir); err != nil {
		return "", err
	}
	d.rpc.token = verified.SessionToken
	return verified.GetUser().GetDisplayName(), nil
}

// register as platform "web": the server lets only native platforms start a
// browser-only account over, and a bridge must never do that. Called with
// d.mu held.
func (d *Device) register(ctx context.Context, certified bool) (*pb.RegisterDeviceResponse, error) {
	req := &pb.RegisterDeviceRequest{
		InstallId:  d.state.InstallID,
		Platform:   "web",
		SigningKey: d.publicKey,
		Mls:        true,
		// Copy detection judges native platforms only; a client still says it
		// starts over when the server finds it a copy (docs/identity.md).
		StartsOverIfCopied: true,
	}
	// Proves this login holds the row's key, so a login new to the row (the
	// same install signing in again) is not refused (docs/identity.md,
	// "Taking over a row"). Sent on every registration.
	req.KeyProof = keyProof(d.seed, d.state.InstallID, d.publicKey, d.rpc.token)
	if key, err := d.state.accountKey(); err != nil {
		return nil, err
	} else if key != nil && certified {
		if req.AccountIdentityKey, err = accountIdentityPublicKey(key); err != nil {
			return nil, err
		}
		if req.AccountSignature, err = signAccountDevice(key, d.publicKey); err != nil {
			return nil, err
		}
	}
	return call[pb.RegisterDeviceRequest, pb.RegisterDeviceResponse](ctx, d.rpc, "RegisterDevice", req)
}

// Connect certifies, opens the MLS store and publishes key packages, then
// registers the account's access key. After linking, and on every start.
func (d *Device) Connect(ctx context.Context) error {
	if err := d.connect(ctx); err != nil {
		return err
	}
	d.setUpAccessKey(ctx)
	d.nameSelf(ctx)
	return nil
}

func (d *Device) connect(ctx context.Context) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.state.AccountKeyHex == "" {
		return errors.New("not linked yet")
	}
	certified, err := d.register(ctx, true)
	if err != nil {
		return err
	}
	if len(certified.GetCredential()) == 0 {
		return errors.New("RegisterDevice returned no credential")
	}
	if id := certified.GetDevice().GetId(); id != "" && id != d.state.DeviceID {
		d.state.DeviceID = id
		if err := d.state.save(d.dir); err != nil {
			return err
		}
	}
	trusted, err := d.trustedKeys(ctx)
	if err != nil {
		return err
	}
	if d.mls != nil {
		d.mls.close()
	}
	store := filepath.Join(d.dir, "mls.sqlite")
	key, err := storeKey(d.dir)
	if err != nil {
		return err
	}
	if err := prepareStore(store, key, d.state.PublishedKeyPackages); err != nil {
		return err
	}
	accountKey, err := d.state.accountKey()
	if err != nil {
		return err
	}
	d.mls, err = openMLS(certified.GetCredential(), d.seed, trusted, store, key, accountKey)
	if err != nil {
		return err
	}
	if err := keepPrivate(d.dir, store); err != nil {
		return err
	}
	// The encrypted store opened under its key: any copy in the clear an
	// older build's migration left can go.
	if n, err := removeClearCopies(store); err != nil {
		zerolog.Ctx(ctx).Warn().Err(err).Msg("Peachy: couldn't remove a clear copy of the MLS store; delete mls.sqlite.plain-* by hand")
	} else if n > 0 {
		zerolog.Ctx(ctx).Info().Int("files", n).Msg("Peachy: removed the MLS store's clear copies")
	}
	if !d.state.PublishedKeyPackages {
		var packages []*pb.MlsKeyPackage
		for i := 0; i <= keyPackages; i++ {
			lastResort := i == keyPackages
			kp, err := d.mls.keyPackage(lastResort)
			if err != nil {
				return err
			}
			packages = append(packages, &pb.MlsKeyPackage{
				Ciphersuite:   uint32(kp.ciphersuite),
				KeyPackage:    kp.pkg,
				KeyPackageRef: kp.ref,
				LastResort:    lastResort,
			})
		}
		_, err = call[pb.PublishKeyPackagesRequest, pb.PublishKeyPackagesResponse](ctx, d.rpc, "PublishKeyPackages",
			&pb.PublishKeyPackagesRequest{DeviceId: d.state.DeviceID, KeyPackages: packages})
		if err != nil {
			return err
		}
		d.state.PublishedKeyPackages = true
		if err := d.state.save(d.dir); err != nil {
			return err
		}
	}
	return nil
}

// productionServer is Peachy's production API, whose credential keys the
// engine carries.
const productionServer = "api.pchy.app"

// trustedKeys is the server's published credential keys, narrowed to the
// ones this build of the engine carries, so a key the server adds vouches for
// nothing until a build carries it. A server other than production (a local
// test server, whose signing seed is public) gets its published list as it is.
// The set is chosen from the address the person gave, never from anything a
// server says. Called with d.mu held.
func (d *Device) trustedKeys(ctx context.Context) (string, error) {
	published, err := d.rpc.deviceCredentialKeys(ctx)
	if err != nil {
		return "", err
	}
	u, err := url.Parse(d.rpc.base)
	if err != nil {
		return "", err
	}
	if u.Hostname() != productionServer {
		zerolog.Ctx(ctx).Warn().Str("server", u.Host).Msg("Peachy: not the production server, so its credential keys aren't pinned")
		return published, nil
	}
	if report, err := serverKeyPinReport(published, "production"); err == nil && report != "" {
		zerolog.Ctx(ctx).Warn().Str("report", report).Msg("Peachy: the server publishes credential keys this build doesn't carry; trusting only the carried ones")
	}
	return serverKeysPinned(published, "production")
}

// Me is this account's actor id.
func (d *Device) Me() (string, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.mls == nil {
		return "", errors.New("not connected")
	}
	actor, _, err := d.mls.identity()
	return actor, err
}

const (
	EventJoined   = "joined"
	EventMessage  = "message"
	EventChanged  = "changed"
	EventSelfNote = "self_note"
	EventLost     = "lost"
	EventReaction = "reaction"
	EventDelete   = "delete"
	EventEdit     = "edit"
	EventReceipt  = "receipt"
)

// Event is something the mailbox brought.
//
//   - EventJoined: this device was added to Conversation.
//   - EventMessage: a message. Sender is an actor id; it's ours when the
//     person wrote it on another device. Text may be empty when the message
//     is only attachments.
//   - EventChanged: the conversation's members or name changed.
//   - EventSelfNote: a note from one of the account's own devices (the
//     history hand-off), as JSON.
//   - EventLost: envelopes expired before we fetched them.
//   - EventReaction: Sender reacted to Target with Emoji, or took their
//     reaction back (Remove). One reaction per person per message.
//   - EventDelete: Sender withdrew Target. Only the author may: check it.
//   - EventEdit: Sender replaced Target's words with Text, as Revision
//     (1..10). Only the author may, within 48 hours, and only above the
//     revision already shown: check it.
//   - EventReceipt: Sender has Receipt (ReceiptRead or ReceiptDelivered)
//     every message up to Target.
type Event struct {
	Type         string
	Conversation string
	Sender       string
	ID           string
	Text         string
	Attachments  []Attachment
	// For a message: the id of the message it answers, or "".
	ReplyTo string
	// For a message: how long after it's seen it disappears (from sending,
	// for your own); 0 for never. Expiring it is up to the reader.
	Timer time.Duration
	// For a message: the people it names, and whether it names everyone
	// (@all in a group).
	Mentions []Mention
	Everyone bool
	// For a reaction, delete or edit: the message it names.
	Target   string
	Emoji    string
	Remove   bool
	Revision int
	Receipt  string
	// Server receive time, milliseconds since the epoch.
	AtMS int64
	JSON string
}

// Poll drains one page of the mailbox, then sends the hellos that are due.
// more is true when another page waits. The MLS engine saves after every
// message it processes, so envelopes are acknowledged only once what they did
// is on disk.
func (d *Device) Poll(ctx context.Context) (events []Event, more bool, err error) {
	events, more, err = d.poll(ctx)
	d.sendHellos(ctx, time.Now())
	return events, more, err
}

func (d *Device) poll(ctx context.Context) (events []Event, more bool, err error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.mls == nil {
		return nil, false, errors.New("not connected")
	}
	accountKey, err := d.state.accountKey()
	if err != nil {
		return nil, false, err
	}
	page, err := call[pb.FetchMailboxRequest, pb.FetchMailboxResponse](ctx, d.rpc, "FetchMailbox",
		&pb.FetchMailboxRequest{DeviceId: d.state.DeviceID})
	if err != nil {
		return nil, false, err
	}
	var done []string
	recover := map[string]int{} // group → the head read the engine owes it
	noGroup := false
	for _, env := range page.GetEnvelopes() {
		event, err := d.handle(ctx, accountKey, env)
		if err != nil {
			l := zerolog.Ctx(ctx).Warn().Err(err).Str("envelope", env.GetId())
			var ge *GroupError
			if errors.As(err, &ge) {
				l = l.Str("group", ge.Group)
			}
			if errors.Is(err, errNoGroup) {
				noGroup = true
			} else {
				l.Msg("Peachy: couldn't process an envelope")
			}
			if errors.As(err, &ge) {
				// A message of one of our groups that won't open: the engine
				// says when that owes a read of the group's head.
				sealedAhead := isMLSCode(err, mlsStaleCopy)
				if due, err := d.mls.recoveryReadDue([]byte(ge.Group), sealedAhead, time.Now()); err == nil && due {
					if sealedAhead {
						recover[ge.Group] = headReadSealedAhead
					} else if _, ok := recover[ge.Group]; !ok {
						recover[ge.Group] = headReadCheck
					}
				}
			}
		} else if event != nil {
			events = append(events, *event)
		}
		done = append(done, env.GetId())
	}
	if len(done) > 0 {
		_, err = call[pb.AckMailboxRequest, pb.AckMailboxResponse](ctx, d.rpc, "AckMailbox",
			&pb.AckMailboxRequest{DeviceId: d.state.DeviceID, Ids: done})
		if err != nil {
			return events, false, err
		}
	}
	for _, e := range events {
		if e.Type == EventJoined {
			d.rejoined(ctx, e.Conversation)
		}
	}
	// After the ack: the rest of the page is taken, and a forgotten group's
	// envelopes after it would open for no group.
	for g, kind := range recover {
		d.recoverGroup(ctx, g, kind)
	}
	if page.GetLost() || noGroup && time.Since(d.allChecked) >= noGroupCheckEvery {
		// After a lost mailbox, or an envelope that opened for no group (at
		// most every ten minutes), every group is checked against its head.
		d.allChecked = time.Now()
		d.checkAllGroups(ctx, headReadLost)
	}
	if page.GetLost() {
		events = append(events, Event{Type: EventLost})
	}
	return events, page.GetMore(), nil
}

func (d *Device) handle(ctx context.Context, accountKey []byte, env *pb.MailboxEnvelope) (*Event, error) {
	at := env.GetReceivedAt().AsTime().UnixMilli()
	switch env.GetKind() {
	case pb.MailboxKind_MAILBOX_KIND_WELCOME:
		group, err := d.mls.join(env.GetPayload())
		if isMLSCode(err, mlsAlreadyAMember) {
			return nil, nil // a second Welcome to a group we're in
		} else if err != nil {
			return nil, err
		}
		if err := d.oweHello(string(group), time.Now()); err != nil {
			return nil, err
		}
		return &Event{Type: EventJoined, Conversation: string(group)}, nil
	case pb.MailboxKind_MAILBOX_KIND_MLS, pb.MailboxKind_MAILBOX_KIND_COMMIT:
		if d.sentByUs(env.GetPayload()) {
			return nil, nil // our own send, back: acknowledged unopened
		}
		group, kind, inner, err := d.mls.openEnvelope(env.GetPayload())
		if err != nil {
			return nil, err
		}
		if group == nil {
			// For a group this device isn't in, or sealed at an epoch its copy
			// never reached: the only trace of a copy that fell behind.
			return nil, errNoGroup
		}
		if !doorFor(env.GetKind(), kind) {
			return nil, nil
		}
		var before []member
		if kind == envelopeCommit {
			if before, err = d.mls.roster(group); err != nil {
				return nil, err
			}
		}
		inc, err := d.mls.process(group, inner, kind == envelopeCommit, env.GetReceivedAt().AsTime().Unix())
		if isMLSCode(err, mlsWrongDoor) || isMLSCode(err, mlsNotFromAMember) || isMLSCode(err, mlsDuplicate) {
			return nil, nil
		} else if err != nil {
			return nil, &GroupError{Group: string(group), Err: err}
		}
		switch inc.kind {
		case incomingApplication:
			if f, ok := readFrame(inc.plaintext); ok {
				return &Event{Type: EventMessage, Conversation: string(group), Sender: inc.senderActor,
					ID: f.id, Text: f.text, Attachments: f.attachments, ReplyTo: f.replyTo, Timer: f.timer,
					Mentions: f.mentions, Everyone: f.everyone, AtMS: at}, nil
			}
			e := &Event{Conversation: string(group), Sender: inc.senderActor, AtMS: at}
			switch l := parseLane(inc.plaintext); l.kind {
			case laneReact:
				e.Type, e.Target, e.Emoji, e.Remove = EventReaction, l.target, l.emoji, l.remove
			case laneDel:
				e.Type, e.Target = EventDelete, l.target
			case laneEdit:
				e.Type, e.Target, e.Revision, e.Text = EventEdit, l.target, l.revision, l.text
			case laneMark:
				if l.laneMark {
					return nil, nil
				}
				e.Type, e.Target, e.Receipt = EventReceipt, l.target, l.receipt
			default:
				return nil, nil // resend asks, history shares: not bridged yet
			}
			return e, nil
		case incomingCommit:
			// A commit that brings in an account new to the tree owes it a hello.
			me, _, ierr := d.mls.identity()
			if after, rerr := d.mls.roster(group); ierr == nil && rerr == nil && accountsAdded(before, after, me) {
				if err := d.oweHello(string(group), time.Now()); err != nil {
					return nil, err
				}
			}
			return &Event{Type: EventChanged, Conversation: string(group)}, nil
		}
		return nil, nil // a proposal queued, or our own message echoed
	case pb.MailboxKind_MAILBOX_KIND_SELF_NOTE:
		p := env.GetPayload()
		if len(p) <= noteIDBytes || accountKey == nil {
			return nil, errors.New("self-note too short")
		}
		note, err := d.openSelfNote(ctx, accountKey, p[:noteIDBytes], p[noteIDBytes:])
		if err != nil {
			return nil, err
		}
		return &Event{Type: EventSelfNote, JSON: string(note)}, nil
	}
	return nil, fmt.Errorf("unknown mailbox kind %d", env.GetKind())
}

// doorFor says whether an envelope of kind goes to the engine from a mailbox
// entry of mailboxKind. A commit counts only from the commit mailbox, which the
// server fills only from SubmitCommit, after the group's head took it: one that
// came through SendSealed skipped the head, so another member may never apply
// it, and merging it would split this device off the group. The commit mailbox
// carries nothing else. Typing, seat asks, calls and previews aren't bridged.
func doorFor(mailboxKind pb.MailboxKind, kind uint8) bool {
	switch mailboxKind {
	case pb.MailboxKind_MAILBOX_KIND_COMMIT:
		return kind == envelopeCommit
	case pb.MailboxKind_MAILBOX_KIND_MLS:
		return kind == envelopeMessage
	}
	return false
}

// frame is a message as it travels: Peachy's frame 5, 0xFF then the version
// byte then JSON {i, t, a, r, …}.
type frame struct {
	id, text    string
	attachments []Attachment
	replyTo     string
	timer       time.Duration
	mentions    []Mention
	everyone    bool
}

// readFrame reads a message frame. Lane frames (reactions, deletes, edits,
// receipts) are bare JSON and not ok here. A pointer that doesn't parse is
// dropped, as Peachy's clients drop it; so is a reply naming no message, or
// itself.
func readFrame(plaintext []byte) (frame, bool) {
	if len(plaintext) < 3 || plaintext[0] != frameByte {
		return frame{}, false
	}
	var f struct {
		I string            `json:"i"`
		T string            `json:"t"`
		A []json.RawMessage `json:"a"`
		R string            `json:"r"`
		X json.RawMessage   `json:"x"`
		M []struct {
			U string `json:"u"`
			H string `json:"h"`
		} `json:"m"`
		MA bool `json:"ma"`
	}
	if json.Unmarshal(plaintext[2:], &f) != nil {
		return frame{}, false
	}
	out := frame{id: strings.ToLower(f.I), text: f.T, mentions: decodeMentions(f.M), everyone: f.MA}
	if f.X != nil {
		// A timer that isn't one is unreadable, never kept forever.
		t, ok := parseTimer(f.X)
		if !ok {
			return frame{}, false
		}
		out.timer = t
	}
	for _, raw := range f.A {
		var a Attachment
		if json.Unmarshal(raw, &a) == nil && a.ObjectKey != "" && a.Key != "" {
			out.attachments = append(out.attachments, a)
		}
	}
	if out.text == "" && len(out.attachments) == 0 {
		return frame{}, false
	}
	if r := strings.ToLower(f.R); isUUID(r) && r != out.id {
		out.replyTo = r
	}
	return out, true
}

// MaxTimer is the longest disappearing-message timer: four weeks.
const MaxTimer = 2419200 * time.Second

// parseTimer reads a disappearing timer, whole seconds from 1 to four weeks.
// Off is written by leaving it out, so 0 isn't one.
func parseTimer(raw json.RawMessage) (time.Duration, bool) {
	n, err := strconv.ParseInt(string(raw), 10, 64)
	if err != nil || n < 1 || time.Duration(n)*time.Second > MaxTimer {
		return 0, false
	}
	return time.Duration(n) * time.Second, true
}

func isUUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i, c := range s {
		switch {
		case i == 8 || i == 13 || i == 18 || i == 23:
			if c != '-' {
				return false
			}
		case !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f'):
			return false
		}
	}
	return true
}

// mentions resolves text's @handles against the chat's members, as the
// sender's device does for every message.
func (d *Device) mentions(ctx context.Context, conversation, text string) ([]Mention, bool, error) {
	var members []string
	group := true
	d.mu.Lock()
	if d.mls != nil {
		roster, err := d.mls.roster([]byte(conversation))
		if err != nil {
			d.mu.Unlock()
			return nil, false, err
		}
		seen := map[string]bool{}
		for _, m := range roster {
			if !seen[m.actorID] {
				seen[m.actorID] = true
				members = append(members, m.actorID)
			}
		}
		var conv Conversation
		d.readMeta([]byte(conversation), &conv)
		conv.Members = members
		group = !conv.DM()
	}
	d.mu.Unlock()
	if len(FindMentions(text)) == 0 || len(members) == 0 {
		return nil, false, nil
	}
	people, err := d.People(ctx, members)
	if err != nil {
		return nil, false, err
	}
	m, everyone := ResolveMentions(text, people, group)
	return m, everyone, nil
}

// Conversation is a conversation as the bridge shows it.
type Conversation struct {
	ID string
	// The group's own name; empty for a DM, which is named after the other
	// person.
	Name string
	// Members' actor ids, ourselves included, each once.
	Members []string
	// Advanced Chat Privacy is on for this chat.
	ACP bool
	// The chat's disappearing-message timer, which messages sent to it carry;
	// 0 for off.
	Timer time.Duration
	// The group's own photo, sealed like an attachment (Download opens it);
	// nil for none, and for a DM, which shows the other person's.
	Photo *Attachment
}

// DM is true for a conversation with no name of its own and one other
// person.
func (c Conversation) DM() bool { return c.Name == "" && len(c.Members) == 2 }

// ForgetGroup drops the conversation's MLS state from this device, so that
// a member removing and re-adding it seats it fresh. For a copy stuck on an
// old epoch ("Message epoch differs"): it can neither read nor be read by
// devices added since. Rejoin does this and asks to be seated too.
func (d *Device) ForgetGroup(id string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.mls == nil {
		return errors.New("not connected")
	}
	return d.mls.forget([]byte(id))
}

func (d *Device) Conversations() ([]Conversation, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.mls == nil {
		return nil, errors.New("not connected")
	}
	groups, err := d.mls.groupIDs()
	if err != nil {
		return nil, err
	}
	var out []Conversation
	for _, g := range groups {
		roster, err := d.mls.roster(g)
		if err != nil {
			return nil, err
		}
		seen := map[string]bool{}
		c := Conversation{ID: string(g)}
		for _, m := range roster {
			if !seen[m.actorID] {
				seen[m.actorID] = true
				c.Members = append(c.Members, m.actorID)
			}
		}
		sort.Strings(c.Members)
		d.readMeta(g, &c)
		out = append(out, c)
	}
	return out, nil
}

// readMeta fills in what the group's own sealed state says: name, photo,
// Advanced Chat Privacy and the disappearing timer.
func (d *Device) readMeta(group []byte, c *Conversation) {
	raw, err := d.mls.meta(group)
	if err != nil || raw == nil {
		return
	}
	var meta struct {
		N   string          `json:"n"`
		ACP bool            `json:"acp"`
		A   *Attachment     `json:"a"`
		Dis json.RawMessage `json:"dis"`
	}
	if json.Unmarshal(raw, &meta) != nil {
		return
	}
	c.Name, c.ACP = meta.N, meta.ACP
	if meta.A != nil && meta.A.ObjectKey != "" && meta.A.Key != "" {
		c.Photo = meta.A
	}
	if meta.Dis != nil {
		c.Timer, _ = parseTimer(meta.Dis)
	}
}

type Person struct {
	ID        string
	Name      string
	Handle    string // without the @; "" when they have none
	AvatarURL string
}

func (d *Device) People(ctx context.Context, ids []string) ([]Person, error) {
	resp, err := call[pb.GetUsersRequest, pb.GetUsersResponse](ctx, d.rpc, "GetUsers", &pb.GetUsersRequest{UserIds: ids})
	if err != nil {
		return nil, err
	}
	var out []Person
	for _, u := range resp.GetUsers() {
		out = append(out, Person{ID: u.GetId(), Name: u.GetDisplayName(), Handle: strings.TrimPrefix(u.GetHandle(), "@"), AvatarURL: u.GetAvatarUrl()})
	}
	return out, nil
}

// SendText sends words to a conversation, as a reply to the message
// replyTo names unless it's ""; returns the message id.
func (d *Device) SendText(ctx context.Context, conversation, text, replyTo string) (string, error) {
	id, err := NewMessageID()
	if err != nil {
		return "", err
	}
	return id, d.send(ctx, id, conversation, text, replyTo, nil)
}

// React sets this person's reaction to a message (one emoji: ValidEmoji), or
// with remove takes it back. A reaction replaces the person's earlier one.
func (d *Device) React(ctx context.Context, conversation, target, emoji string, remove bool) error {
	wire, err := encodeReaction(target, emoji, remove)
	if err != nil {
		return err
	}
	return d.sendLane(ctx, conversation, wire)
}

// Delete withdraws one of this person's own messages, for everyone.
func (d *Device) Delete(ctx context.Context, conversation, target string) error {
	wire, err := encodeDelete(target)
	if err != nil {
		return err
	}
	return d.sendLane(ctx, conversation, wire)
}

// wideMarkEvery is how many author-only receipts may go into a conversation
// before one goes to everyone. A member a receipt skips never sees that step
// of the sender's ratchet, and Peachy's engine refuses a message more than
// 1,000 steps past the last it saw from a sender, so a quiet reader who sent
// thousands of narrow receipts would become unreadable.
const wideMarkEvery = 100

// Receipt tells a conversation this person has read, or received, every
// message up to target. With authors, it goes only to their devices (as
// Peachy routes a receipt to the authors of the messages it covers), except
// the first from this process and every 100th after, which go to everyone;
// with none, to everyone.
func (d *Device) Receipt(ctx context.Context, conversation, kind, target string, authors []string) error {
	wire, err := encodeReceipt(kind, target)
	if err != nil {
		return err
	}
	d.mu.Lock()
	if d.narrowMarks == nil {
		d.narrowMarks = map[string]int{}
	}
	n, seen := d.narrowMarks[conversation]
	if len(authors) == 0 || !seen || n >= wideMarkEvery {
		authors = nil
		d.narrowMarks[conversation] = 0
	} else {
		d.narrowMarks[conversation] = n + 1
	}
	d.mu.Unlock()
	return d.sealTo(ctx, conversation, wire, false, "", authors)
}

// Edit replaces the words of one of this person's own messages. revision is
// 1 for the first edit, up to MaxEditRevision; Peachy offers edits for 24
// hours after sending.
func (d *Device) Edit(ctx context.Context, conversation, target string, revision int, text string) error {
	wire, err := encodeEdit(target, revision, text)
	if err != nil {
		return err
	}
	return d.sendLane(ctx, conversation, wire)
}

// Media is a file to send, with what the recipient's app shows about it.
// Width and Height are 0 when unknown.
type Media struct {
	Data     []byte
	Mime     string
	FileName string
	Width    int
	Height   int
	// For video and audio; 0 when unknown.
	DurationMS int64
	// The average color as #rrggbb, Peachy's placeholder while it loads; ""
	// when unknown.
	Color string
}

// MaxAttachments is how many files one Peachy message can carry.
const MaxAttachments = 32

// SendMedia seals and uploads each file, then sends them as one message (an
// album, when there are several) with an optional caption, under id from
// NewMessageID.
func (d *Device) SendMedia(ctx context.Context, id, conversation, caption, replyTo string, media []Media) error {
	if len(media) == 0 || len(media) > MaxAttachments {
		return fmt.Errorf("a message carries 1 to %d attachments, not %d", MaxAttachments, len(media))
	}
	var pointers []Attachment
	for _, m := range media {
		s, err := sealPadded(m.Data)
		if err != nil {
			return err
		}
		upload, err := d.rpc.createUpload(ctx, len(s.object))
		if err != nil {
			return err
		}
		if upload.GetResumable() != nil || upload.GetUploadUrl() == "" {
			return errors.New("the server offered no plain upload for this file")
		}
		if err := d.rpc.putObject(ctx, upload.GetUploadUrl(), s.object); err != nil {
			return err
		}
		pointers = append(pointers, pointerFor(s, upload.GetObjectKey(), len(m.Data), m))
	}
	return d.send(ctx, id, conversation, caption, replyTo, pointers)
}

// maxAvatarBytes bounds a profile photo download.
const maxAvatarBytes = 10 * 1024 * 1024

// Avatar fetches a profile photo from the URL Peachy gave for it
// (Person.AvatarURL). Profile photos are public images, not sealed. Only
// https, or http when the server itself is plain http (a local test server).
func (d *Device) Avatar(ctx context.Context, avatarURL string) ([]byte, error) {
	base, err := url.Parse(d.rpc.base)
	if err != nil {
		return nil, err
	}
	u, err := base.Parse(avatarURL)
	if err != nil {
		return nil, err
	}
	if u.Scheme != "https" && !(u.Scheme == "http" && base.Scheme == "http") {
		return nil, fmt.Errorf("profile photo URL with scheme %q", u.Scheme)
	}
	b, err := d.rpc.get(ctx, u.String())
	if err != nil {
		return nil, err
	}
	if len(b) > maxAvatarBytes {
		return nil, errors.New("profile photo too large")
	}
	return b, nil
}

// Download fetches and opens the file an incoming message's pointer names.
func (d *Device) Download(ctx context.Context, a Attachment) ([]byte, error) {
	if !objectKeyOK(a.ObjectKey) {
		return nil, errors.New("attachment has an unexpected object key")
	}
	base, err := d.media(ctx)
	if err != nil {
		return nil, err
	}
	object, err := d.rpc.get(ctx, base+"/"+a.ObjectKey)
	if err != nil {
		return nil, fmt.Errorf("download: %w", err)
	}
	return a.open(object)
}

// media is where sealed objects are read from (GetMe's media_base_url),
// asked for once.
func (d *Device) media(ctx context.Context) (string, error) {
	d.mediaMu.Lock()
	defer d.mediaMu.Unlock()
	if d.mediaBase == "" {
		me, err := call[pb.GetMeRequest, pb.GetMeResponse](ctx, d.rpc, "GetMe", &pb.GetMeRequest{})
		if err != nil {
			return "", err
		}
		base := me.GetMediaBaseUrl()
		if !strings.HasPrefix(base, "https://") && !strings.HasPrefix(base, "http://") {
			return "", errors.New("the server gave no media address")
		}
		d.mediaBase = strings.TrimRight(base, "/")
	}
	return d.mediaBase, nil
}

// objectKeyOK: object keys are server-minted (sealed/<uuid>.bin); refuse
// anything that could point the download somewhere else.
func objectKeyOK(key string) bool {
	if key == "" || strings.HasPrefix(key, "/") {
		return false
	}
	for _, part := range strings.Split(key, "/") {
		if part == "" || part == "." || part == ".." {
			return false
		}
	}
	for _, c := range key {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("/_.-", c)) {
			return false
		}
	}
	return true
}

func (d *Device) send(ctx context.Context, id, conversation, text, replyTo string, attachments []Attachment) error {
	if attachments == nil {
		attachments = []Attachment{}
	}
	msg := map[string]any{"i": id, "t": text, "a": attachments}
	// A message carries the chat's timer as it is when sent; every reader
	// expires it by that.
	d.mu.Lock()
	var conv Conversation
	if d.mls != nil {
		d.readMeta([]byte(conversation), &conv)
	}
	if d.accessKey != nil {
		// So members can reach this account without naming themselves.
		msg["ak"] = base64.StdEncoding.EncodeToString(d.accessKey)
	}
	d.mu.Unlock()
	if conv.Timer > 0 {
		msg["x"] = int64(conv.Timer / time.Second)
	}
	if strings.Contains(text, "@") {
		people, everyone, err := d.mentions(ctx, conversation, text)
		if err != nil {
			return err
		}
		if len(people) > 0 {
			m := make([]map[string]string, len(people))
			for i, p := range people {
				m[i] = map[string]string{"u": p.UserID, "h": p.Handle}
			}
			msg["m"] = m
		}
		if everyone {
			msg["ma"] = true
		}
	}
	if replyTo != "" {
		// "b": the reply also shows in the chat itself, not only under the
		// message it answers, as a reply from Matrix does.
		msg["r"], msg["b"] = replyTo, true
	}
	body, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	clientID, err := uuidV4()
	if err != nil {
		return err
	}
	return d.seal(ctx, conversation, append([]byte{frameByte, frameVersion}, body...), true, clientID)
}

// sendLane sends a lane frame: not urgent (it wakes and notifies nobody),
// and with no client message id, as Peachy's clients send them.
func (d *Device) sendLane(ctx context.Context, conversation string, wire []byte) error {
	return d.seal(ctx, conversation, wire, false, "")
}

// seal encrypts plaintext into the conversation and sends it to every other
// device in it.
func (d *Device) seal(ctx context.Context, conversation string, plaintext []byte, urgent bool, clientID string) error {
	return d.sealTo(ctx, conversation, plaintext, urgent, clientID, nil)
}

// sealTo is seal to the devices of only those accounts, or with none named,
// to every other device in the conversation.
func (d *Device) sealTo(ctx context.Context, conversation string, plaintext []byte, urgent bool, clientID string, only []string) error {
	return d.sealHinted(ctx, conversation, plaintext, urgent, clientID, only, -1)
}

// sealHinted is sealTo with a content hint (0 to 3), or none for -1.
func (d *Device) sealHinted(ctx context.Context, conversation string, plaintext []byte, urgent bool, clientID string, only []string, hint int) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.mls == nil {
		return errors.New("not connected")
	}
	group := []byte(conversation)
	roster, err := d.mls.roster(group)
	if err != nil {
		return err
	}
	var recipients []*pb.SealedRecipient
	for _, m := range roster {
		if m.deviceID != d.state.DeviceID && (only == nil || slices.Contains(only, m.actorID)) {
			recipients = append(recipients, &pb.SealedRecipient{UserId: m.actorID, DeviceId: m.deviceID})
		}
	}
	if len(recipients) == 0 {
		return nil // nobody to tell, and no step of the ratchet spent
	}
	var ciphertext []byte
	if hint >= 0 {
		ciphertext, err = d.mls.encryptWithHint(group, plaintext, uint8(hint))
	} else {
		ciphertext, err = d.mls.encrypt(group, plaintext)
	}
	if err != nil {
		return err
	}
	payload, err := d.mls.sealEnvelope(group, envelopeMessage, ciphertext)
	if err != nil {
		return err
	}
	d.rememberSent(payload, time.Now())
	sent, err := call[pb.SendSealedRequest, pb.SendSealedResponse](ctx, d.rpc, "SendSealed", &pb.SendSealedRequest{
		Payload:         payload,
		Urgent:          urgent,
		ClientMessageId: clientID,
		Recipients:      recipients,
	})
	if err != nil {
		return err
	}
	if n := len(sent.GetStaleDeviceIds()); n > 0 {
		zerolog.Ctx(ctx).Warn().Int("stale_devices", n).Str("conversation", conversation).
			Msg("Peachy: devices in this conversation are gone; their leaves need removing")
	}
	return nil
}

// NewMessageID mints the id a message is sent under (a v4 uuid), for
// callers that need it before the message goes out.
func NewMessageID() (string, error) { return uuidV4() }

func uuidV4() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	h := hex.EncodeToString(b)
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:], nil
}

// openSelfNote opens a note from one of the account's own devices, believing
// it only when the device it names is in the account's device list and
// signed it under the key that list gives it.
func (d *Device) openSelfNote(ctx context.Context, accountKey, id, value []byte) ([]byte, error) {
	sender, err := noteSender(accountKey, id, value)
	if err != nil {
		return nil, err
	}
	list, err := call[pb.ListDevicesRequest, pb.ListDevicesResponse](ctx, d.rpc, "ListDevices", &pb.ListDevicesRequest{})
	if err != nil {
		return nil, err
	}
	for _, dev := range list.GetDevices() {
		if dev.GetId() == sender {
			return noteOpenSigned(accountKey, id, value, sender, dev.GetSigningKey(), time.Now().UnixMilli())
		}
	}
	return nil, fmt.Errorf("self-note from device %s, which isn't in the account's device list", sender)
}
