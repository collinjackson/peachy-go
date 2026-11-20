package peachytest

// Sealed media: CreateUpload, the presigned PUT and the public GET
// (peachy-protocol's docs/delivery.md "Sealed media"). Resumable uploads,
// group photos' sessionless door and deletes are not modelled; objects
// never expire.

import (
	"io"
	"net/http"
	"strconv"

	"connectrpc.com/connect"

	"github.com/collinjackson/peachy-go/pb"
)

const (
	maxAttachment = 100_000_000
	maxMeta       = 8_000_000
)

func (s *Server) createUpload(c *caller, req *pb.CreateUploadRequest) (*pb.CreateUploadResponse, error) {
	if _, err := c.needSession(); err != nil {
		return nil, err
	}
	if req.GetKind() != pb.UploadKind_UPLOAD_KIND_FILE {
		return nil, errorf(connect.CodeInvalidArgument, "a sealed upload is UPLOAD_KIND_FILE")
	}
	if req.GetContentType() != "application/octet-stream" {
		return nil, errorf(connect.CodeInvalidArgument, "content_type must be application/octet-stream")
	}
	var prefix string
	var limit int64
	switch req.GetSealedClass() {
	case pb.SealedClass_SEALED_CLASS_ATTACHMENT:
		prefix, limit = "sealed/", maxAttachment
	case pb.SealedClass_SEALED_CLASS_META:
		prefix, limit = "sealed-meta/", maxMeta
	default:
		return nil, errorf(connect.CodeInvalidArgument, "no sealed class")
	}
	if n := req.GetContentLength(); n <= 0 || n > limit {
		return nil, errorf(connect.CodeInvalidArgument, "content_length")
	}
	key := prefix + newUUID() + ".bin"
	token := newUUID()
	s.uploads[token] = upload{key: key, length: req.GetContentLength()}
	resp := &pb.CreateUploadResponse{UploadUrl: s.URL + "/upload/" + token, ObjectKey: key, PublicUrl: s.URL + "/media/" + key}
	if prefix == "sealed-meta/" {
		resp.DeleteToken = newUUID()
	}
	// resumable is never offered, which the doc allows ("the server offers
	// parts at all (an operator switch)").
	return resp, nil
}

// putObject takes the body with exactly the headers the presigned URL
// covers.
func (s *Server) putObject(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	up, ok := s.uploads[r.PathValue("token")]
	s.mu.Unlock()
	if !ok {
		http.Error(w, "no such upload", http.StatusForbidden)
		return
	}
	if r.Header.Get("Content-Type") != "application/octet-stream" || r.Header.Get("Content-Disposition") != "attachment" ||
		r.ContentLength != up.length {
		http.Error(w, "the signature doesn't cover these headers", http.StatusForbidden)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, up.length+1))
	if err != nil || int64(len(body)) != up.length {
		http.Error(w, "short body", http.StatusBadRequest)
		return
	}
	s.mu.Lock()
	s.objects[up.key] = body
	delete(s.uploads, r.PathValue("token"))
	s.mu.Unlock()
	w.WriteHeader(http.StatusOK)
}

func (s *Server) getObject(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	b, ok := s.objects[r.PathValue("key")]
	s.mu.Unlock()
	if !ok {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", strconv.Itoa(len(b)))
	_, _ = w.Write(b)
}
