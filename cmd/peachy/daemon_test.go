//go:build testissuer

package main

// peachy daemon's signal-cli REST API against the fake server
// (peachytest): a person on one account writes to a bot on another, the bot
// reads it through GET /v1/receive and over the WebSocket, and answers,
// replies and reacts through the API.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/collinjackson/peachy-go"
	"github.com/collinjackson/peachy-go/peachytest"
)

const botNumber = "+15555550199"

func signIn(t *testing.T, srv *peachytest.Server, dir, phone, name string) (*peachy.Device, string) {
	t.Helper()
	actor := srv.AddAccount(phone, name, strings.ToLower(name))
	ctx := context.Background()
	dev, err := peachy.Open(srv.URL, dir, name+"'s device")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(dev.Close)
	if err := dev.StartLogin(ctx, phone); err != nil {
		t.Fatal(err)
	}
	if _, err := dev.FinishLogin(ctx, phone, peachytest.Code); err != nil {
		t.Fatal(err)
	}
	for i := 0; ; i++ {
		st, err := dev.LinkStep(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if st.State == peachy.LinkApproved {
			break
		}
		if i == 3 {
			t.Fatalf("still %s", st.State)
		}
	}
	if err := dev.Connect(ctx); err != nil {
		t.Fatal(err)
	}
	return dev, actor
}

type signalEnvelope struct {
	Envelope struct {
		SourceUUID  string `json:"sourceUuid"`
		SourceName  string `json:"sourceName"`
		DataMessage struct {
			Timestamp int64   `json:"timestamp"`
			Message   *string `json:"message"`
			GroupInfo *struct {
				GroupID string `json:"groupId"`
			} `json:"groupInfo"`
			Reaction *struct {
				Emoji string `json:"emoji"`
			} `json:"reaction"`
		} `json:"dataMessage"`
	} `json:"envelope"`
}

func TestDaemonAgainstFakeServer(t *testing.T) {
	srv := peachytest.Start(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	alice, aliceID := signIn(t, srv, t.TempDir(), "+15555550100", "Alice")
	dir := t.TempDir()
	bot, _ := signIn(t, srv, dir, botNumber, "Bot")
	c := &cli{dev: bot, dir: dir, names: map[string]string{}}
	if err := c.connect(ctx); err != nil {
		t.Fatal(err)
	}
	dm, err := alice.FoundGroupForTest(ctx, "", true, []string{c.me})
	if err != nil {
		t.Fatal(err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	served := make(chan error, 1)
	go func() { served <- c.serveDaemon(ctx, ln, "secret", "normal") }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-served:
		case <-time.After(10 * time.Second):
			t.Error("the daemon didn't stop")
		}
	})
	base := "http://" + ln.Addr().String()
	do := func(method, path string, body any) (int, []byte) {
		t.Helper()
		var r io.Reader
		if body != nil {
			b, _ := json.Marshal(body)
			r = bytes.NewReader(b)
		}
		req, _ := http.NewRequestWithContext(ctx, method, base+path, r)
		req.Header.Set("Authorization", "Bearer secret")
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, b
	}
	receive := func() []signalEnvelope {
		t.Helper()
		code, b := do("GET", "/v1/receive/"+botNumber, nil)
		if code != http.StatusOK {
			t.Fatalf("receive: %d %s", code, b)
		}
		var out []signalEnvelope
		if err := json.Unmarshal(b, &out); err != nil {
			t.Fatalf("receive: %v in %s", err, b)
		}
		return out
	}
	alicePoll := func() []peachy.Event {
		t.Helper()
		events, _, err := alice.Poll(ctx)
		if err != nil {
			t.Fatal(err)
		}
		var msgs []peachy.Event
		for _, e := range events {
			if e.Type == peachy.EventMessage || e.Type == peachy.EventReaction {
				msgs = append(msgs, e)
			}
		}
		return msgs
	}

	if code, _ := (func() (int, []byte) {
		req, _ := http.NewRequestWithContext(ctx, "GET", base+"/v1/about", nil)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode, nil
	})(); code != http.StatusUnauthorized {
		t.Fatalf("no token: %d", code)
	}

	// Alice writes; the bot reads it from GET /v1/receive.
	hello, err := alice.SendText(ctx, dm, "hello bot", "")
	if err != nil {
		t.Fatal(err)
	}
	got := receive()
	if len(got) != 1 || got[0].Envelope.SourceUUID != aliceID || got[0].Envelope.DataMessage.Message == nil ||
		*got[0].Envelope.DataMessage.Message != "hello bot" || got[0].Envelope.DataMessage.GroupInfo != nil {
		t.Fatalf("received %+v", got)
	}
	ts := got[0].Envelope.DataMessage.Timestamp

	// The bot answers as a reply, by the timestamp it was handed.
	code, b := do("POST", "/v2/send", map[string]any{"message": "hi alice", "recipients": []string{aliceID}, "quote_timestamp": ts})
	if code != http.StatusCreated {
		t.Fatalf("send: %d %s", code, b)
	}
	msgs := alicePoll()
	if len(msgs) != 1 || msgs[0].Text != "hi alice" || msgs[0].ReplyTo != hello {
		t.Fatalf("alice got %+v", msgs)
	}

	// A reaction through the API.
	code, b = do("POST", "/v1/reactions/"+botNumber, map[string]any{"reaction": "🎉", "recipient": aliceID, "target_author": aliceID, "timestamp": ts})
	if code != http.StatusNoContent {
		t.Fatalf("react: %d %s", code, b)
	}
	if msgs = alicePoll(); len(msgs) != 1 || msgs[0].Type != peachy.EventReaction || msgs[0].Target != hello || msgs[0].Emoji != "🎉" {
		t.Fatalf("alice got %+v", msgs)
	}

	// Over the WebSocket, the stream's poke brings the next message in.
	wctx, wcancel := context.WithTimeout(ctx, 20*time.Second)
	defer wcancel()
	ws, _, err := websocket.Dial(wctx, "ws"+strings.TrimPrefix(base, "http")+"/v1/receive/"+botNumber,
		&websocket.DialOptions{HTTPHeader: http.Header{"Authorization": {"Bearer secret"}}})
	if err != nil {
		t.Fatal(err)
	}
	defer ws.CloseNow()
	if _, err := alice.SendText(ctx, dm, "over the socket", ""); err != nil {
		t.Fatal(err)
	}
	_, frame, err := ws.Read(wctx)
	if err != nil {
		t.Fatalf("socket: %v", err)
	}
	var rpc struct {
		Method string         `json:"method"`
		Params signalEnvelope `json:"params"`
	}
	if err := json.Unmarshal(frame, &rpc); err != nil || rpc.Method != "receive" || rpc.Params.Envelope.DataMessage.Message == nil ||
		*rpc.Params.Envelope.DataMessage.Message != "over the socket" {
		t.Fatalf("socket frame %s: %v", frame, err)
	}

	// The bot's groups list holds no DM; a group shows up once Alice founds one.
	g, err := alice.FoundGroupForTest(ctx, "Bots", false, []string{c.me})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := alice.SendText(ctx, g, "in the group", ""); err != nil {
		t.Fatal(err)
	}
	_, frame, err = ws.Read(wctx)
	if err != nil {
		t.Fatalf("socket: %v", err)
	}
	if err := json.Unmarshal(frame, &rpc); err != nil || rpc.Params.Envelope.DataMessage.GroupInfo == nil ||
		rpc.Params.Envelope.DataMessage.GroupInfo.GroupID != g {
		t.Fatalf("group frame %s: %v", frame, err)
	}
	code, b = do("GET", "/v1/groups/"+botNumber, nil)
	if code != http.StatusOK || !strings.Contains(string(b), `"name":"Bots"`) || strings.Count(string(b), `"internal_id"`) != 1 {
		t.Fatalf("groups: %d %s", code, b)
	}
	code, b = do("POST", "/v2/send", map[string]any{"message": "to the group", "recipients": []string{fmt.Sprintf("group.%s", g)}})
	if code != http.StatusCreated {
		t.Fatalf("group send: %d %s", code, b)
	}
	if msgs = alicePoll(); len(msgs) != 1 || msgs[0].Conversation != g || msgs[0].Text != "to the group" {
		t.Fatalf("alice got %+v", msgs)
	}
}
