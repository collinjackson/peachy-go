package peachytest

// Key packages, conversation heads, sends and the mailbox: peachy-protocol's
// docs/delivery.md. Nothing is metered.

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"sort"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/collinjackson/peachy-go/pb"
)

const ciphersuite = 0x004F

func sortDevices(ds []*device) { sort.Slice(ds, func(i, j int) bool { return ds[i].id < ds[j].id }) }

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// ownMLSDevice is the caller's own unrevoked MLS device, registered under
// its session (delivery.md "Publish", "FetchMailbox and AckMailbox").
func (s *Server) ownMLSDevice(sess *session, id string) (*device, error) {
	d := s.devices[id]
	if d == nil || d.actor != sess.actor {
		return nil, errorf(connect.CodeNotFound, "no such device")
	}
	if d.revoked != nil || !d.sessions[sess.id] {
		return nil, errorf(connect.CodePermissionDenied, "not this login's device")
	}
	return d, nil
}

// deliverable: an account's own unrevoked, approved device that has a
// mailbox (delivery.md "Sending", check 5).
func deliverable(d *device, actor string) bool {
	return d != nil && d.actor == actor && d.revoked == nil && d.approval == "approved" && d.mailboxOpen
}

func (s *Server) publishKeyPackages(c *caller, req *pb.PublishKeyPackagesRequest) (*pb.PublishKeyPackagesResponse, error) {
	sess, err := c.needSession()
	if err != nil {
		return nil, err
	}
	d, err := s.ownMLSDevice(sess, req.GetDeviceId())
	if err != nil {
		return nil, err
	}
	if d.approval != "approved" || !d.certified {
		return nil, errorf(connect.CodeFailedPrecondition, "this device is waiting to be let in")
	}
	kps := req.GetKeyPackages()
	if len(kps) < 1 || len(kps) > 100 {
		return nil, errorf(connect.CodeInvalidArgument, "1 to 100 key packages")
	}
	lastResorts := 0
	for _, kp := range kps {
		if kp.GetCiphersuite() != ciphersuite || len(kp.GetKeyPackage()) == 0 || len(kp.GetKeyPackage()) > 32<<10 ||
			len(kp.GetKeyPackageRef()) == 0 || len(kp.GetKeyPackageRef()) > 128 {
			return nil, errorf(connect.CodeInvalidArgument, "bad key package")
		}
		if kp.GetLastResort() {
			lastResorts++
		}
	}
	if lastResorts > 1 {
		return nil, errorf(connect.CodeInvalidArgument, "at most one last-resort package")
	}
	published := 0
	for _, kp := range kps {
		if kp.GetLastResort() {
			d.lastResort = kp
			published++
			continue
		}
		dup := false
		for _, have := range d.packages {
			dup = dup || bytes.Equal(have.GetKeyPackageRef(), kp.GetKeyPackageRef())
		}
		if !dup {
			d.packages = append(d.packages, kp)
			published++
		}
	}
	// Package liveness (a credential's exp more than 5 days away) is not
	// checked: the fake's credentials last 30 days.
	d.mailboxOpen = true
	s.poke(sess.actor, pb.StateDomain_STATE_DOMAIN_SESSIONS)
	return &pb.PublishKeyPackagesResponse{Published: uint32(published), Available: uint32(len(d.packages)),
		HasLastResort: d.lastResort != nil}, nil
}

// handOut consumes one package of each approved device of actor
// (delivery.md "Consume").
func (s *Server) handOut(actor string, skip, only []string) ([]*pb.FetchedKeyPackage, []string) {
	in := func(id string, list []string) bool {
		for _, x := range list {
			if x == id {
				return true
			}
		}
		return false
	}
	var kps []*pb.FetchedKeyPackage
	var without []string
	for _, d := range s.sortedDevices(actor) {
		if !d.mls || d.revoked != nil || d.approval != "approved" || !d.certified || in(d.id, skip) || len(only) > 0 && !in(d.id, only) {
			continue
		}
		var kp *pb.MlsKeyPackage
		last := false
		if len(d.packages) > 0 {
			kp, d.packages = d.packages[0], d.packages[1:]
		} else if d.lastResort != nil {
			kp, last = d.lastResort, true
		}
		if kp == nil {
			without = append(without, d.id)
			continue
		}
		kps = append(kps, &pb.FetchedKeyPackage{UserId: actor, DeviceId: d.id, Ciphersuite: kp.GetCiphersuite(),
			KeyPackage: kp.GetKeyPackage(), KeyPackageRef: kp.GetKeyPackageRef(), UsedLastResort: last})
	}
	return kps, without
}

func (s *Server) fetchKeyPackages(c *caller, req *pb.FetchKeyPackagesRequest) (*pb.FetchKeyPackagesResponse, error) {
	if _, err := c.needSession(); err != nil {
		return nil, err
	}
	if n := len(req.GetUserIds()); n < 1 || n > 128 || len(req.GetSkipDeviceIds()) > 16 || len(req.GetOnlyDeviceIds()) > 16 {
		return nil, errorf(connect.CodeInvalidArgument, "1 to 128 user ids, at most 16 device ids in each filter")
	}
	resp := &pb.FetchKeyPackagesResponse{}
	for _, u := range req.GetUserIds() {
		if s.accounts[u] == nil {
			return nil, errorf(connect.CodeNotFound, "no such account")
		}
	}
	for _, u := range req.GetUserIds() {
		kps, without := s.handOut(u, req.GetSkipDeviceIds(), req.GetOnlyDeviceIds())
		resp.KeyPackages = append(resp.KeyPackages, kps...)
		resp.DevicesWithoutPackages = append(resp.DevicesWithoutPackages, without...)
	}
	return resp, nil
}

func (s *Server) accessKeyOK(actor string, key []byte) bool {
	a := s.accounts[actor]
	if a == nil || a.accessKeyHash == nil {
		return false
	}
	sum := sha256.Sum256(key)
	return subtle.ConstantTimeCompare(sum[:], a.accessKeyHash) == 1
}

func (s *Server) fetchKeyPackagesAnonymous(_ *caller, req *pb.FetchKeyPackagesAnonymousRequest) (*pb.FetchKeyPackagesAnonymousResponse, error) {
	if !s.accessKeyOK(req.GetUserId(), req.GetAccessKey()) {
		return nil, errorf(connect.CodePermissionDenied, "access denied")
	}
	kps, without := s.handOut(req.GetUserId(), nil, req.GetOnlyDeviceIds())
	return &pb.FetchKeyPackagesAnonymousResponse{KeyPackages: kps, DevicesWithoutPackages: without}, nil
}

// createHandle opens a head at epoch 0 (delivery.md "Founding a
// conversation", step 3).
func (s *Server) createHandle(_ *caller, req *pb.CreateHandleRequest) (*pb.CreateHandleResponse, error) {
	if len(req.GetHandle()) != 32 || len(req.GetVerifier()) != 32 {
		return nil, errorf(connect.CodeInvalidArgument, "handle and verifier are 32 bytes")
	}
	if h := s.heads[string(req.GetHandle())]; h != nil {
		if h.epoch == 0 && bytes.Equal(h.verifier, req.GetVerifier()) {
			return &pb.CreateHandleResponse{}, nil
		}
		return nil, errorf(connect.CodeAlreadyExists, "that handle is taken")
	}
	s.heads[string(req.GetHandle())] = &head{verifier: append([]byte(nil), req.GetVerifier()...)}
	return &pb.CreateHandleResponse{}, nil
}

// authorize is the access check of a send or commit naming accounts: a
// session, or the access key of every account (delivery.md "Access keys",
// "The check").
func (s *Server) authorize(c *caller, actors []string, keys []*pb.RecipientAccessKey) error {
	if c.session != nil {
		return nil
	}
	if c.token != "" {
		return errUnauthenticated
	}
	given := map[string][]byte{}
	for _, k := range keys {
		given[k.GetUserId()] = k.GetAccessKey()
	}
	ok := true
	for _, a := range actors {
		ok = s.accessKeyOK(a, given[a]) && ok
	}
	if !ok {
		return errorf(connect.CodePermissionDenied, "access denied")
	}
	return nil
}

func distinctActors(rs []*pb.SealedRecipient, ws []*pb.MlsWelcome) []string {
	seen := map[string]bool{}
	var out []string
	add := func(a string) {
		if !seen[a] {
			seen[a] = true
			out = append(out, a)
		}
	}
	for _, r := range rs {
		add(r.GetUserId())
	}
	for _, w := range ws {
		add(w.GetRecipientUserId())
	}
	return out
}

// envelopeVersionOK: only version 2 and 3 envelopes are taken
// (delivery.md "Retired builds").
func envelopeVersionOK(b []byte) error {
	if len(b) == 0 {
		return errorf(connect.CodeInvalidArgument, "empty envelope")
	}
	switch b[0] {
	case 2, 3:
		return nil
	case 1:
		return errorf(connect.CodeFailedPrecondition, "envelope-retired")
	}
	return errorf(connect.CodeInvalidArgument, "envelope-retired")
}

func (s *Server) submitCommit(c *caller, req *pb.SubmitCommitRequest) (*pb.SubmitCommitResponse, error) {
	if len(req.GetHandle()) != 32 || len(req.GetNextVerifier()) != 32 {
		return nil, errorf(connect.CodeInvalidArgument, "handle and next_verifier are 32 bytes")
	}
	if n := len(req.GetCommit()); n == 0 || n > 4<<20 {
		return nil, errorf(connect.CodeInvalidArgument, "commit size")
	}
	if err := envelopeVersionOK(req.GetCommit()); err != nil {
		return nil, err
	}
	if len(req.GetWelcomes()) > 512 {
		return nil, errorf(connect.CodeInvalidArgument, "too many Welcomes")
	}
	for _, w := range req.GetWelcomes() {
		if n := len(w.GetWelcome()); n == 0 || n > 4<<20 {
			return nil, errorf(connect.CodeInvalidArgument, "Welcome size")
		}
	}
	actors := distinctActors(req.GetRecipients(), req.GetWelcomes())
	if len(req.GetRecipients())+len(req.GetWelcomes()) > 1024 || len(actors) > 256 {
		return nil, errorf(connect.CodeInvalidArgument, "too many recipients")
	}
	if err := s.authorize(c, actors, req.GetAccessKeys()); err != nil {
		return nil, err
	}
	for _, w := range req.GetWelcomes() {
		d := s.devices[w.GetRecipientDeviceId()]
		if d == nil || d.actor != w.GetRecipientUserId() || d.revoked != nil {
			return nil, errorf(connect.CodeInvalidArgument, "a Welcome for no live device")
		}
		// delivery.md "A Welcome names a package its device published": the
		// server only counts a Welcome that names none, and still places it,
		// so the fake doesn't read the refs.
	}
	h := s.heads[string(req.GetHandle())]
	if h == nil {
		return nil, errorf(connect.CodeNotFound, "no such conversation")
	}
	if h.epoch != req.GetEpoch() {
		return nil, errorf(connect.CodeFailedPrecondition, "the head is at another epoch")
	}
	sum := sha256.Sum256(req.GetSendKey())
	if len(req.GetSendKey()) != 32 || !bytes.Equal(sum[:], h.verifier) {
		return nil, errorf(connect.CodePermissionDenied, "not allowed")
	}
	if err := s.checkStamp(c, h, req); err != nil {
		return nil, err
	}
	if len(req.GetStampSet()) > 0 {
		h.stampSet = req.GetStampSet()
	}
	h.epoch++
	h.verifier = append([]byte(nil), req.GetNextVerifier()...)
	if c.session != nil {
		for _, d := range s.devices {
			if d.sessions[c.session.id] && !d.serverRun {
				s.commits[d.id]++
			}
		}
	}

	welcomed := map[string]bool{}
	for _, w := range req.GetWelcomes() {
		welcomed[w.GetRecipientDeviceId()] = true
	}
	resp := &pb.SubmitCommitResponse{Seq: h.epoch, Epoch: h.epoch}
	var to []*device
	for _, r := range req.GetRecipients() {
		d := s.devices[r.GetDeviceId()]
		if d == nil || d.revoked != nil {
			resp.StaleDeviceIds = append(resp.StaleDeviceIds, r.GetDeviceId())
			continue
		}
		if deliverable(d, r.GetUserId()) && !welcomed[d.id] {
			to = append(to, d)
		}
	}
	if len(to) > 0 {
		s.place(to, pb.MailboxKind_MAILBOX_KIND_COMMIT, req.GetCommit(), "")
	}
	for _, w := range req.GetWelcomes() {
		s.place([]*device{s.devices[w.GetRecipientDeviceId()]}, pb.MailboxKind_MAILBOX_KIND_WELCOME, w.GetWelcome(), "")
	}
	if c.session != nil {
		s.poke(c.session.actor, pb.StateDomain_STATE_DOMAIN_MLS)
	}
	return resp, nil
}

// checkStamp applies delivery.md "Commit stamps" and "Own-scope commits":
// with no set a stamp is ignored and only the founding commit (epoch 0) may
// enroll one; with a set the commit is stamped by one of its keys, or marked
// own-scope and unstamped. The fake doesn't check who may enroll (the
// community roster), doesn't meter own-scope commits, doesn't rewind, and
// takes the core's word that an own-scope commit is one.
func (s *Server) checkStamp(c *caller, h *head, req *pb.SubmitCommitRequest) error {
	unstamped := func(msg string) error {
		err := connect.NewError(connect.CodePermissionDenied, errors.New(msg))
		err.Meta().Set("peachy-refusal", "unstamped")
		return err
	}
	if st := req.GetStamp(); len(st) != 0 && len(st) != 64 {
		return errorf(connect.CodeInvalidArgument, "stamp is 0 or 64 bytes")
	}
	newSet := req.GetStampSet()
	if len(newSet) > 0 && !validStampSet(newSet) {
		return errorf(connect.CodeInvalidArgument, "malformed stamp_set")
	}
	if req.GetRewind() {
		return unstamped("the fake takes no rewind")
	}
	own := req.GetScope() == pb.CommitScope_COMMIT_SCOPE_OWN
	if own {
		if len(req.GetStamp()) != 0 || len(newSet) != 0 || req.GetEnrollCommunityId() != "" || req.GetEnrollOrganizationId() != "" {
			return errorf(connect.CodeInvalidArgument, "an own-scope commit carries no stamp, set or enrollment")
		}
		if len(req.GetWelcomes()) > 0 {
			if c.session == nil {
				return errorf(connect.CodeInvalidArgument, "an own-scope commit with a Welcome goes signed in")
			}
			for _, w := range req.GetWelcomes() {
				if w.GetRecipientUserId() != c.session.actor {
					return errorf(connect.CodeInvalidArgument, "an own-scope commit's Welcomes name the caller's own account")
				}
			}
		}
	}
	switch {
	case len(h.stampSet) == 0 && len(newSet) == 0:
		return nil
	case len(h.stampSet) == 0:
		if h.epoch != 0 || own {
			return unstamped("a stamp set is enrolled only by a founding commit")
		}
		if !stampVerifies(newSet, req.GetStamp(), req.GetHandle(), req.GetEpoch(), req.GetCommit(), newSet) {
			return unstamped("the founding stamp doesn't verify under the new set")
		}
		return nil
	case own && len(newSet) == 0:
		return nil
	}
	if !stampVerifies(h.stampSet, req.GetStamp(), req.GetHandle(), req.GetEpoch(), req.GetCommit(), newSet) {
		return unstamped("no key of the handle's stamp set signed this commit")
	}
	return nil
}

// place stores one payload with an entry for each device and pokes their
// accounts. Returns the envelope id. Called with s.mu held.
func (s *Server) place(to []*device, kind pb.MailboxKind, data []byte, retryKey string) (string, *pb.MailboxEnvelope) {
	id := newUUID()
	at := ts(s.now())
	s.payloads[id] = &payload{refs: len(to), retryKey: retryKey}
	if retryKey != "" {
		s.retries[retryKey] = id
	}
	var env *pb.MailboxEnvelope
	poked := map[string]bool{}
	for _, d := range to {
		env = &pb.MailboxEnvelope{Id: id, Kind: kind, Payload: data, ReceivedAt: at}
		d.mailbox = append(d.mailbox, &entry{env: env, payloadID: id})
		if !poked[d.actor] {
			poked[d.actor] = true
			s.poke(d.actor, pb.StateDomain_STATE_DOMAIN_MAILBOX)
		}
	}
	return id, env
}

// release drops one entry's hold on its payload; the last one forgets the
// retry key, so a retry after that is a new send (delivery.md
// "Idempotency").
func (s *Server) release(id string) {
	p := s.payloads[id]
	if p == nil {
		return
	}
	if p.refs--; p.refs <= 0 {
		delete(s.payloads, id)
		if p.retryKey != "" {
			delete(s.retries, p.retryKey)
		}
	}
}

func (s *Server) fetchConversationHead(c *caller, req *pb.FetchConversationHeadRequest) (*pb.FetchConversationHeadResponse, error) {
	resp := &pb.FetchConversationHeadResponse{}
	if req.GetEvery() {
		// The sweep (delivery.md "FetchConversationHead").
		if _, err := c.needSession(); err != nil {
			return nil, err
		}
		if len(req.GetHandles()) > 0 || len(req.GetAfter()) != 0 && len(req.GetAfter()) != 32 {
			return nil, errorf(connect.CodeInvalidArgument, "a sweep names no handles, and after is 32 bytes")
		}
		for _, k := range sortedKeys(s.heads) {
			if k <= string(req.GetAfter()) {
				continue
			}
			if len(resp.Heads) == s.pageSize {
				resp.More = true
				break
			}
			h := s.heads[k]
			resp.Heads = append(resp.Heads, &pb.ConversationHead{Handle: []byte(k), Epoch: h.epoch, Verifier: h.verifier})
		}
		return resp, nil
	}
	if len(req.GetHandles()) > 500 {
		return nil, errorf(connect.CodeInvalidArgument, "at most 500 handles")
	}
	for _, k := range req.GetHandles() {
		if h := s.heads[string(k)]; h != nil && len(k) == 32 {
			resp.Heads = append(resp.Heads, &pb.ConversationHead{Handle: k, Epoch: h.epoch, Verifier: h.verifier})
		}
	}
	return resp, nil
}

func (s *Server) sendSealed(c *caller, req *pb.SendSealedRequest) (*pb.SendSealedResponse, error) {
	limit := 1 << 20
	if req.GetEphemeral() {
		limit = 4096
	}
	if n := len(req.GetPayload()); n == 0 || n > limit {
		return nil, errorf(connect.CodeInvalidArgument, "payload size")
	}
	if len(req.GetRecipients()) == 0 {
		return nil, errorf(connect.CodeInvalidArgument, "no recipients")
	}
	if id := req.GetClientMessageId(); id != "" && !isUUID(id) {
		return nil, errorf(connect.CodeInvalidArgument, "client_message_id is a UUID")
	}
	if err := envelopeVersionOK(req.GetPayload()); err != nil {
		return nil, err
	}
	actors := distinctActors(req.GetRecipients(), nil)
	if len(req.GetRecipients()) > 1024 || len(actors) > 256 {
		return nil, errorf(connect.CodeInvalidArgument, "too many recipients")
	}
	if err := s.authorize(c, actors, req.GetAccessKeys()); err != nil {
		return nil, err
	}
	if key := req.GetClientMessageId(); key != "" {
		if id, ok := s.retries[key]; ok {
			return &pb.SendSealedResponse{Id: id, ReceivedAt: s.receivedAt(id)}, nil
		}
	}
	resp := &pb.SendSealedResponse{}
	var to []*device
	seen := map[string]bool{}
	for _, r := range req.GetRecipients() {
		if !isUUID(r.GetUserId()) || !isUUID(r.GetDeviceId()) || seen[r.GetDeviceId()] {
			continue
		}
		seen[r.GetDeviceId()] = true
		d := s.devices[r.GetDeviceId()]
		if d == nil || d.revoked != nil {
			resp.StaleDeviceIds = append(resp.StaleDeviceIds, r.GetDeviceId())
			continue
		}
		if deliverable(d, r.GetUserId()) {
			to = append(to, d)
		}
	}
	if req.GetEphemeral() {
		// Relayed to open streams only, which the fake doesn't do: a typing
		// frame is dropped.
		return resp, nil
	}
	if len(to) == 0 {
		resp.Id, resp.ReceivedAt = newUUID(), ts(s.now())
		return resp, nil
	}
	id, env := s.place(to, pb.MailboxKind_MAILBOX_KIND_MLS, req.GetPayload(), req.GetClientMessageId())
	resp.Id, resp.ReceivedAt = id, env.GetReceivedAt()
	resp.Placement = &pb.Placement{}
	for _, d := range to {
		resp.Placement.DeviceIds = append(resp.Placement.DeviceIds, d.id)
	}
	return resp, nil
}

func (s *Server) receivedAt(id string) *timestamppb.Timestamp {
	for _, d := range s.devices {
		for _, e := range d.mailbox {
			if e.payloadID == id {
				return e.env.GetReceivedAt()
			}
		}
	}
	return ts(s.now())
}

func (s *Server) mailboxDevice(c *caller, id string) (*device, error) {
	sess, err := c.needSession()
	if err != nil {
		return nil, err
	}
	d := s.devices[id]
	if d == nil || d.actor != sess.actor {
		return nil, errorf(connect.CodeNotFound, "no such device")
	}
	if d.revoked != nil || !d.sessions[sess.id] {
		return nil, errorf(connect.CodePermissionDenied, "not this login's device")
	}
	return d, nil
}

func (s *Server) fetchMailbox(c *caller, req *pb.FetchMailboxRequest) (*pb.FetchMailboxResponse, error) {
	d, err := s.mailboxDevice(c, req.GetDeviceId())
	if err != nil {
		return nil, err
	}
	limit := int(req.GetLimit())
	if limit == 0 {
		limit = 200
	}
	limit = min(limit, 500)
	resp := &pb.FetchMailboxResponse{Lost: d.lost, ServerTime: ts(s.now())}
	d.lost = false
	for i, e := range d.mailbox {
		if i == limit {
			resp.More = true
			break
		}
		resp.Envelopes = append(resp.Envelopes, e.env)
	}
	return resp, nil
}

func (s *Server) ackMailbox(c *caller, req *pb.AckMailboxRequest) (*pb.AckMailboxResponse, error) {
	d, err := s.mailboxDevice(c, req.GetDeviceId())
	if err != nil {
		return nil, err
	}
	if len(req.GetIds()) > 1000 {
		return nil, errorf(connect.CodeInvalidArgument, "at most 1000 ids")
	}
	done := map[string]bool{}
	for _, id := range req.GetIds() {
		done[id] = true
	}
	kept := d.mailbox[:0]
	for _, e := range d.mailbox {
		if done[e.env.GetId()] {
			s.release(e.payloadID)
		} else {
			kept = append(kept, e)
		}
	}
	d.mailbox = kept
	return &pb.AckMailboxResponse{}, nil
}
