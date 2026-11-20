package peachytest

// Sign-in, devices and linking: peachy-protocol's docs/identity.md.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"regexp"
	"strings"

	"connectrpc.com/connect"

	"github.com/collinjackson/peachy-go/pb"
)

var e164 = regexp.MustCompile(`^\+[1-9][0-9]{6,14}$`)

// startPhoneVerification sends no SMS: every code is Code. The number is
// canonical when it is E.164 (identity.md "Signing in", step 1).
func (s *Server) startPhoneVerification(_ *caller, req *pb.StartPhoneVerificationRequest) (*pb.StartPhoneVerificationResponse, error) {
	phone := strings.TrimSpace(req.GetPhone())
	if !e164.MatchString(phone) {
		return nil, errorf(connect.CodeInvalidArgument, "not an E.164 number")
	}
	return &pb.StartPhoneVerificationResponse{Phone: phone}, nil
}

// verifyPhone mints a session for a known number; for an unknown one it asks
// for a display name, and with one creates the account (identity.md
// "Signing in", step 2). Registration lock is never on.
func (s *Server) verifyPhone(_ *caller, req *pb.VerifyPhoneRequest) (*pb.VerifyPhoneResponse, error) {
	if req.GetCode() != Code {
		return nil, errorf(connect.CodePermissionDenied, "wrong code")
	}
	a := s.byPhone[req.GetPhone()]
	if a == nil {
		if req.GetDisplayName() == "" {
			return &pb.VerifyPhoneResponse{NeedsDisplayName: true}, nil
		}
		a = s.addAccount(req.GetPhone(), req.GetDisplayName(), "")
	}
	sess := &session{token: "pst_" + newUUID(), id: newUUID(), actor: a.id}
	s.sessions[sess.token] = sess
	return &pb.VerifyPhoneResponse{SessionToken: sess.token, User: s.user(a)}, nil
}

func (s *Server) user(a *account) *pb.User {
	u := &pb.User{Id: a.id, DisplayName: a.name, CreatedAt: ts(a.created)}
	if a.handle != "" {
		u.Handle = "@" + a.handle
	}
	return u
}

var validPlatforms = map[string]bool{"ios": true, "mac": true, "android": true, "web": true}

// registerDevice follows identity.md "RegisterDevice", "Taking over a row"
// and "The account identity key". The copied-install rule, twins and PIN
// restores are not modelled.
func (s *Server) registerDevice(c *caller, req *pb.RegisterDeviceRequest) (*pb.RegisterDeviceResponse, error) {
	sess, err := c.needSession()
	if err != nil {
		return nil, err
	}
	a := s.accounts[sess.actor]
	install := strings.TrimSpace(req.GetInstallId())
	if install == "" || len(install) > 128 {
		return nil, errorf(connect.CodeInvalidArgument, "bad install_id")
	}
	if !validPlatforms[req.GetPlatform()] {
		return nil, errorf(connect.CodeInvalidArgument, "bad platform")
	}
	key := req.GetSigningKey()
	if len(key) != ed25519.PublicKeySize {
		return nil, errorf(connect.CodeInvalidArgument, "signing_key must be 32 bytes")
	}
	idKey, sig := req.GetAccountIdentityKey(), req.GetAccountSignature()
	if (len(idKey) == 0) != (len(sig) == 0) || len(idKey) != 0 && (len(idKey) != 32 || len(sig) != 64) {
		return nil, errorf(connect.CodeInvalidArgument, "account_identity_key and account_signature: 32 and 64 bytes, both or neither")
	}
	if p := req.GetKeyProof(); len(p) != 0 && len(p) != 64 {
		return nil, errorf(connect.CodeInvalidArgument, "key_proof must be 64 bytes")
	}
	proofOK := len(req.GetKeyProof()) == 64 &&
		ed25519.Verify(key, keyProofMessage(install, key, c.token), req.GetKeyProof())

	var row *device
	for _, d := range s.devices {
		if d.actor == a.id && d.installID == install && d.mls == req.GetMls() && !d.serverRun {
			row = d
		}
	}
	now := s.now()
	if row != nil && row.revoked != nil {
		// identity.md "A removed install": the server never brings a
		// revoked row back.
		return nil, errorf(connect.CodePermissionDenied, "this device was removed")
	}
	if row != nil && !row.sessions[sess.id] && !proofOK {
		// "Taking over a row": a login not linked to the row proves it
		// holds the row's key.
		return nil, errorf(connect.CodePermissionDenied, "prove the row's key")
	}
	if row == nil {
		row = &device{id: newUUID(), actor: a.id, installID: install, mls: req.GetMls(), created: now,
			sessions: map[string]bool{}, exchanges: map[string]*pb.DeviceLinkExchange{}}
		s.devices[row.id] = row
	}
	row.platform = req.GetPlatform()
	if !bytes.Equal(row.signingKey, key) {
		// A new key rotates the row in place and drops its certificate.
		row.signingKey = append([]byte(nil), key...)
		row.certified, row.accountKey, row.accountSig = false, nil, nil
		row.sessions = map[string]bool{}
	}
	if proofOK {
		row.sessions = map[string]bool{}
	}
	row.sessions[sess.id] = true

	pinned := a.identity.Public().(ed25519.PublicKey)
	if len(idKey) != 0 {
		if !ed25519.Verify(idKey, certificateMessage(key), sig) {
			return nil, errorf(connect.CodeInvalidArgument, "bad account signature")
		}
		if !bytes.Equal(idKey, pinned) {
			return nil, errorf(connect.CodeFailedPrecondition, "another account identity key is pinned")
		}
		// "Who may certify": a relaunch, or a row its approver let in. The
		// server-run approver is always live and certified, so "only device"
		// never applies.
		if row.certified || row.approvedBy != "" {
			row.certified, row.accountKey, row.accountSig = true, idKey, sig
			row.approval = "approved"
		}
	}
	if !row.certified && row.mls {
		row.approval = "pending"
		// The server-run approver lets every new MLS row in at once, with a
		// version-1 box (identity.md "Fetching and opening the account key").
		box, err := sealAccountKeyV1(a.approverSeed, row.signingKey, row.id, a.accountKey)
		if err != nil {
			return nil, errorf(connect.CodeInternal, err.Error())
		}
		row.box, row.approvedBy = box, a.approver.id
	}
	iat, exp := credentialLifetime(now)
	cred := MintCredential(s.issuer, a.id, row.id, row.signingKey, row.accountKey, row.accountSig, iat, exp)
	return &pb.RegisterDeviceResponse{Device: s.deviceRow(row, sess), Credential: cred, AccountIdentityKey: pinned}, nil
}

// deviceRow is d as sess sees it: install and session ids only for rows its
// own login registered (identity.md "One install, two rows").
func (s *Server) deviceRow(d *device, sess *session) *pb.Device {
	out := &pb.Device{Id: d.id, Platform: d.platform, SigningKey: d.signingKey, CreatedAt: ts(d.created),
		ApprovalState: d.approval, AccountCertified: d.certified, ApprovedByDeviceId: d.approvedBy}
	if d.revoked != nil {
		out.RevokedAt = ts(*d.revoked)
	}
	if d.approval == "pending" {
		out.ApprovalRequestedAt = ts(d.created)
	}
	if sess != nil && d.sessions[sess.id] {
		out.InstallId, out.SessionId, out.OnThisLogin = d.installID, sess.id, true
	}
	for _, ex := range d.exchanges {
		out.LinkExchanges = append(out.LinkExchanges, ex)
	}
	return out
}

func (s *Server) listDevices(c *caller, _ *pb.ListDevicesRequest) (*pb.ListDevicesResponse, error) {
	sess, err := c.needSession()
	if err != nil {
		return nil, err
	}
	resp := &pb.ListDevicesResponse{}
	for _, d := range s.sortedDevices(sess.actor) {
		resp.Devices = append(resp.Devices, s.deviceRow(d, sess))
	}
	return resp, nil
}

func (s *Server) sortedDevices(actor string) []*device {
	var out []*device
	for _, d := range s.devices {
		if d.actor == actor {
			out = append(out, d)
		}
	}
	sortDevices(out)
	return out
}

// stepDeviceLink relays the two-digit exchange (identity.md "StepDeviceLink").
// The server-run approver never starts one, so only a test that plays an
// approving device itself drives it.
func (s *Server) stepDeviceLink(c *caller, req *pb.StepDeviceLinkRequest) (*pb.StepDeviceLinkResponse, error) {
	sess, err := c.needSession()
	if err != nil {
		return nil, err
	}
	row := s.devices[req.GetDeviceId()]
	approver := s.devices[req.GetApproverDeviceId()]
	if row == nil || approver == nil || row.actor != sess.actor || approver.actor != sess.actor {
		return nil, errorf(connect.CodeNotFound, "no such device")
	}
	ex := row.exchanges[approver.id]
	switch step := req.GetStep().(type) {
	case *pb.StepDeviceLinkRequest_ApproverCommitment:
		ex = &pb.DeviceLinkExchange{ApproverDeviceId: approver.id, ApproverCommitment: step.ApproverCommitment,
			ApproverSignature: req.GetApproverCommitmentSignature()}
		row.exchanges[approver.id] = ex
	case *pb.StepDeviceLinkRequest_DeviceNonce:
		if ex == nil {
			return nil, errorf(connect.CodeFailedPrecondition, "no exchange with that approver")
		}
		ex.DeviceNonce, ex.DeviceLinkKey, ex.DeviceLinkKeySignature = step.DeviceNonce, req.GetDeviceLinkKey(), req.GetDeviceLinkKeySignature()
	case *pb.StepDeviceLinkRequest_ApproverNonce:
		if ex == nil {
			return nil, errorf(connect.CodeFailedPrecondition, "no exchange with that approver")
		}
		ex.ApproverNonce = step.ApproverNonce
	default:
		return nil, errorf(connect.CodeInvalidArgument, "no step")
	}
	return &pb.StepDeviceLinkResponse{}, nil
}

func (s *Server) fetchAccountKey(c *caller, req *pb.FetchAccountKeyRequest) (*pb.FetchAccountKeyResponse, error) {
	sess, err := c.needSession()
	if err != nil {
		return nil, err
	}
	if len(req.GetDeviceId()) != 36 {
		return nil, errorf(connect.CodeInvalidArgument, "device_id must be a UUID")
	}
	d := s.devices[req.GetDeviceId()]
	if d == nil || d.actor != sess.actor || d.revoked != nil || !d.sessions[sess.id] || d.box == nil {
		return &pb.FetchAccountKeyResponse{}, nil
	}
	return &pb.FetchAccountKeyResponse{Box: d.box, ApproverDeviceId: d.approvedBy}, nil
}

func (s *Server) getMe(c *caller, _ *pb.GetMeRequest) (*pb.GetMeResponse, error) {
	sess, err := c.needSession()
	if err != nil {
		return nil, err
	}
	return &pb.GetMeResponse{User: s.user(s.accounts[sess.actor]), MediaBaseUrl: s.URL + "/media"}, nil
}

// getUsers answers public rows only; sealed profiles are not modelled.
func (s *Server) getUsers(c *caller, req *pb.GetUsersRequest) (*pb.GetUsersResponse, error) {
	if _, err := c.needSession(); err != nil {
		return nil, err
	}
	resp := &pb.GetUsersResponse{}
	for _, id := range req.GetUserIds() {
		if a := s.accounts[id]; a != nil {
			resp.Users = append(resp.Users, s.user(a))
		}
	}
	return resp, nil
}

// setAccessKey keeps SHA-256 of the key (delivery.md "Access keys").
func (s *Server) setAccessKey(c *caller, req *pb.SetAccessKeyRequest) (*pb.SetAccessKeyResponse, error) {
	sess, err := c.needSession()
	if err != nil {
		return nil, err
	}
	if len(req.GetAccessKey()) != 16 {
		return nil, errorf(connect.CodeInvalidArgument, "an access key is 16 bytes")
	}
	sum := sha256.Sum256(req.GetAccessKey())
	s.accounts[sess.actor].accessKeyHash = sum[:]
	return &pb.SetAccessKeyResponse{}, nil
}

// certifiedSession: the session registered a live, certified device of its
// account (account-store.md "ReadStore and WriteStore").
func (s *Server) certifiedSession(c *caller) (*session, error) {
	sess, err := c.needSession()
	if err != nil {
		return nil, err
	}
	for _, d := range s.devices {
		if d.actor == sess.actor && d.sessions[sess.id] && d.revoked == nil && d.certified {
			return sess, nil
		}
	}
	return nil, errorf(connect.CodePermissionDenied, "no certified device on this login")
}
