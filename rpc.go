package peachy

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"connectrpc.com/connect"

	"github.com/collinjackson/peachy-go/pb"
)

const octetStream = "application/octet-stream"

// rpc makes Connect calls to Peachy's ChatService (protobuf over HTTP), and
// the plain HTTP the sealed media path uses.
type rpc struct {
	base  string
	http  *http.Client
	token string
}

func newRPC(base string) *rpc {
	return &rpc{
		base: strings.TrimRight(base, "/"),
		// Generous: a 90 MiB attachment on a slow line. Unary calls are
		// bounded by their contexts.
		http: &http.Client{Timeout: 10 * time.Minute},
	}
}

// unaryTimeout bounds each call, so a connection that drops without a reset
// fails in seconds rather than at the client's ten-minute limit (which stays
// for media). A variable for tests.
var unaryTimeout = 30 * time.Second

func call[Req, Resp any](ctx context.Context, r *rpc, method string, req *Req) (*Resp, error) {
	ctx, cancel := context.WithTimeout(ctx, unaryTimeout)
	defer cancel()
	client := connect.NewClient[Req, Resp](r.http, r.base+"/peachy.v1.ChatService/"+method)
	creq := connect.NewRequest(req)
	if r.token != "" {
		creq.Header().Set("Authorization", "Bearer "+r.token)
	}
	resp, err := client.CallUnary(ctx, creq)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", method, err)
	}
	return resp.Msg, nil
}

// deviceCredentialKeys is the JSON of the server keys that sign device
// credentials, as the MLS engine reads it.
func (r *rpc) deviceCredentialKeys(ctx context.Context) (string, error) {
	b, err := r.get(ctx, r.base+"/healthz/device-credential-keys")
	return string(b), err
}

// get fetches a URL: the credential keys, or a sealed object (public by
// key; only the key in the message opens it).
func (r *rpc) get(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := r.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET: %s", resp.Status)
	}
	return io.ReadAll(resp.Body)
}

// putObject PUTs a sealed object to the URL CreateUpload handed out.
func (r *rpc) putObject(ctx context.Context, url string, object []byte) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, url, bytes.NewReader(object))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", octetStream)
	req.Header.Set("Content-Disposition", "attachment")
	resp, err := r.http.Do(req)
	if err != nil {
		return fmt.Errorf("upload: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("upload: %s", resp.Status)
	}
	return nil
}

func (r *rpc) createUpload(ctx context.Context, length int) (*pb.CreateUploadResponse, error) {
	return call[pb.CreateUploadRequest, pb.CreateUploadResponse](ctx, r, "CreateUpload", &pb.CreateUploadRequest{
		Kind:          pb.UploadKind_UPLOAD_KIND_FILE,
		ContentType:   octetStream,
		ContentLength: int64(length),
		SealedClass:   pb.SealedClass_SEALED_CLASS_ATTACHMENT,
	})
}
