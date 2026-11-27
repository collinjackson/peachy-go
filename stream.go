package peachy

// Peachy's live event stream (StreamEvents), as its apps use it instead of
// polling: the server says "something is in your mailbox", "your settings
// changed" or "someone changed their profile", never what. The device then
// fetches as usual.
//
// Holding a stream doesn't silence your other devices: the server counts a
// device as having a person at it only when it says so (SetAttention), which
// this library never does.

import (
	"context"
	"errors"
	"net/http"
	"time"

	"connectrpc.com/connect"
	"github.com/rs/zerolog"

	"github.com/collinjackson/peachy-go/pb"
)

// Change is what the stream said moved.
type Change struct {
	// Something arrived: Poll.
	Mailbox bool
	// The account store changed: ReadStore.
	Settings bool
	// Someone this account knows changed their name, photo or handle.
	People bool
}

const maxStreamBackoff = time.Minute

// Listen holds the stream open until ctx ends, reconnecting when it drops
// (after the delay the server names, or with backoff), and sends each
// Change. Every connection opens with everything set, so what moved while
// the stream was down is fetched then. The channel closes when ctx ends.
func (d *Device) Listen(ctx context.Context) <-chan Change {
	out := make(chan Change, 16)
	go func() {
		defer close(out)
		backoff := time.Second
		for ctx.Err() == nil {
			wait, err := d.stream(ctx, out)
			if ctx.Err() != nil {
				return
			}
			if err == nil {
				backoff = time.Second // a clean end: the server closed it
			} else {
				zerolog.Ctx(ctx).Warn().Err(err).Msg("Peachy: live stream dropped; reconnecting")
			}
			if wait == 0 {
				wait = backoff
				backoff = min(backoff*2, maxStreamBackoff)
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(wait):
			}
		}
	}()
	return out
}

// stream runs one connection. It returns the delay the server asked for
// before reconnecting, if it named one.
func (d *Device) stream(ctx context.Context, out chan<- Change) (time.Duration, error) {
	// No overall timeout: the stream lives as long as the connection.
	client := connect.NewClient[pb.StreamEventsRequest, pb.StreamEventsResponse](
		&http.Client{Transport: d.rpc.http.Transport}, d.rpc.base+"/peachy.v1.ChatService/StreamEvents")
	req := connect.NewRequest(&pb.StreamEventsRequest{})
	if d.rpc.token == "" {
		return 0, errors.New("not signed in")
	}
	req.Header().Set("Authorization", "Bearer "+d.rpc.token)
	s, err := client.CallServerStream(ctx, req)
	if err != nil {
		return 0, err
	}
	defer s.Close()
	first := true
	for s.Receive() {
		msg := s.Msg()
		if first {
			// The stream is live: catch up on whatever moved before it was.
			first = false
			send(ctx, out, Change{Mailbox: true, Settings: true, People: true})
		}
		if r := msg.GetReconnect(); r != nil {
			return time.Duration(r.GetAfterMs()) * time.Millisecond, nil
		}
		if sc := msg.GetStateChanged(); sc != nil {
			var c Change
			for _, dom := range sc.GetDomains() {
				switch dom {
				case pb.StateDomain_STATE_DOMAIN_MAILBOX:
					c.Mailbox = true
				case pb.StateDomain_STATE_DOMAIN_ACCOUNT_STORE:
					c.Settings = true
				case pb.StateDomain_STATE_DOMAIN_PEOPLE:
					c.People = true
				case pb.StateDomain_STATE_DOMAIN_MLS:
					// The pool fell low: check it at the next quiet poll,
					// and drain (delivery.md §Realtime).
					d.keyPackagesDue()
					c.Mailbox = true
				}
			}
			if c != (Change{}) {
				send(ctx, out, c)
			}
		}
	}
	return 0, s.Err()
}

func send(ctx context.Context, out chan<- Change, c Change) {
	select {
	case out <- c:
	case <-ctx.Done():
	}
}
