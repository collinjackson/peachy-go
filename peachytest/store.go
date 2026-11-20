package peachytest

// The account store: opaque sealed blobs under a compare-and-swap version
// (peachy-protocol's docs/account-store.md "ReadStore and WriteStore").

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"time"

	"connectrpc.com/connect"

	"github.com/collinjackson/peachy-go/pb"
)

type store struct {
	version  int64
	manifest []byte
	records  map[string][]byte // by string(id)
}

var zeroID = make([]byte, 16)

// init writes the first manifest, holding one account record with a fresh
// access key, as the account's first device would.
func (st *store) init(accountKey []byte, now time.Time) {
	id := randomBytes(16)
	st.records = map[string][]byte{string(id): storeSeal(accountKey, id, accountRecord(randomBytes(16), now))}
	manifest, _ := json.Marshal(map[string]any{"version": 1, "ids": []string{hex.EncodeToString(id)}})
	st.manifest = storeSeal(accountKey, zeroID, manifest)
	st.version = 1
}

func validRecordID(id []byte) bool { return len(id) == 16 && !bytes.Equal(id, zeroID) }

func validSealedLength(n int) bool { return n >= 285 && (n-29)%256 == 0 }

func (s *Server) readStore(c *caller, req *pb.ReadStoreRequest) (*pb.ReadStoreResponse, error) {
	sess, err := s.certifiedSession(c)
	if err != nil {
		return nil, err
	}
	for _, id := range req.GetIds() {
		if !validRecordID(id) {
			return nil, errorf(connect.CodeInvalidArgument, "a record id is 16 bytes, not all zero")
		}
	}
	st := &s.accounts[sess.actor].store
	if st.version == 0 || st.version == req.GetSinceVersion() {
		return &pb.ReadStoreResponse{Version: st.version}, nil
	}
	resp := &pb.ReadStoreResponse{Version: st.version, Manifest: st.manifest}
	if len(req.GetIds()) == 0 {
		for _, id := range sortedKeys(st.records) {
			resp.Records = append(resp.Records, &pb.StoreRecord{Id: []byte(id), Value: st.records[id]})
		}
	} else {
		for _, id := range req.GetIds() {
			if v, ok := st.records[string(id)]; ok {
				resp.Records = append(resp.Records, &pb.StoreRecord{Id: id, Value: v})
			}
		}
	}
	return resp, nil
}

// writeStore checks shapes and sizes from the doc's table; the store-wide
// record count and byte limits are not enforced.
func (s *Server) writeStore(c *caller, req *pb.WriteStoreRequest) (*pb.WriteStoreResponse, error) {
	sess, err := s.certifiedSession(c)
	if err != nil {
		return nil, err
	}
	if req.GetExpectedVersion() < 0 {
		return nil, errorf(connect.CodeInvalidArgument, "negative expected_version")
	}
	if !validSealedLength(len(req.GetManifest())) {
		return nil, errorf(connect.CodeInvalidArgument, "bad manifest length")
	}
	if len(req.GetManifest()) > 524288 {
		return nil, errorf(connect.CodeResourceExhausted, "manifest too large")
	}
	if len(req.GetUpserts()) > 500 {
		return nil, errorf(connect.CodeResourceExhausted, "too many upserts")
	}
	seen := map[string]bool{}
	for _, r := range req.GetUpserts() {
		if !validRecordID(r.GetId()) || seen[string(r.GetId())] || !validSealedLength(len(r.GetValue())) {
			return nil, errorf(connect.CodeInvalidArgument, "bad record")
		}
		if len(r.GetValue()) > 8192 {
			return nil, errorf(connect.CodeResourceExhausted, "record too large")
		}
		seen[string(r.GetId())] = true
	}
	for _, id := range req.GetDeletes() {
		if !validRecordID(id) {
			return nil, errorf(connect.CodeInvalidArgument, "bad record id")
		}
	}
	st := &s.accounts[sess.actor].store
	if st.version != req.GetExpectedVersion() {
		return &pb.WriteStoreResponse{Conflict: true, Version: st.version}, nil
	}
	if req.GetReset_() || st.records == nil {
		st.records = map[string][]byte{}
	}
	for _, id := range req.GetDeletes() {
		delete(st.records, string(id))
	}
	for _, r := range req.GetUpserts() {
		st.records[string(r.GetId())] = r.GetValue()
	}
	st.manifest = req.GetManifest()
	st.version++
	s.poke(sess.actor, pb.StateDomain_STATE_DOMAIN_ACCOUNT_STORE)
	return &pb.WriteStoreResponse{Version: st.version}, nil
}
