package main

// peachy daemon: the part of signal-cli's REST API (bbernhard's
// signal-cli-rest-api, in its "normal" mode) that chat bots use, answered
// for Peachy. A bot written for that API, Com Tower for one, runs on Peachy
// by pointing its bridge URL here.
//
//	GET  /v1/about
//	GET  /v1/receive/{number}     what arrived since the last call; as a
//	                              WebSocket, each message as it arrives
//	POST /v2/send                 words, photos, replies; to a group or a DM
//	POST /v1/reactions/{number}   react; DELETE takes it back
//	GET  /v1/groups/{number}      the bot's group chats
//
// The {number} in a path is whatever the bot calls itself; this device is
// one account, so it isn't checked.
//
// Signal names a message by its author and sent timestamp, Peachy by an id,
// so the daemon gives each message a timestamp (unique on this device) and
// keeps the pairs in daemon-ids.jsonl. A group's id is its conversation id
// (groupInfo.groupId), and "group." + base64 of that sends to it, as with
// signal-cli. A person is their Peachy actor id, in sourceUuid; Peachy shows
// no one's phone number, so sourceNumber is always empty.
//
// Nothing comes from people the account has blocked. A DM from someone new
// is accepted: a bot answers whoever writes.
//
// With -mode json-rpc, receiving is only a WebSocket, as in
// signal-cli-rest-api's json-rpc mode: a plain GET is told so (400), and
// bots that know the mode, Com Tower for one, switch to the socket and hear
// each message the moment Peachy delivers it. Each socket message is
// {"jsonrpc":"2.0","method":"receive","params":{envelope, account}}. In the
// normal mode the socket works too.

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"mime"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf16"

	"github.com/coder/websocket"

	"github.com/collinjackson/peachy-go"
)

const (
	idsFile = "daemon-ids.jsonl"
	// Envelopes waiting for a bot to collect them; the oldest go first.
	maxQueued = 2000
)

type daemon struct {
	c *cli

	jsonRPC bool

	mu    sync.Mutex // the device, names and maps below
	queue []map[string]any
	// Closed, and replaced, when something joins the queue.
	queued chan struct{}
	byTS   map[int64]msgRef
	byID   map[string]int64
	lastTS int64
}

// msgRef is one message as both sides name it.
type msgRef struct {
	TS           int64  `json:"ts"`
	Conversation string `json:"conversation"`
	ID           string `json:"id"`
	Author       string `json:"author"`
}

func (c *cli) daemon(ctx context.Context, listen, token, mode string) error {
	if mode != "normal" && mode != "json-rpc" {
		return fmt.Errorf("-mode is normal or json-rpc, not %q", mode)
	}
	if host, _, err := net.SplitHostPort(listen); err != nil {
		return err
	} else if ip := net.ParseIP(host); host != "localhost" && (ip == nil || !ip.IsLoopback()) && token == "" {
		return errors.New("listening beyond this machine needs -token: anyone who reaches the daemon can read and send as this account")
	}
	ln, err := net.Listen("tcp", listen)
	if err != nil {
		return err
	}
	return c.serveDaemon(ctx, ln, token, mode)
}

// serveDaemon answers on ln until ctx ends.
func (c *cli) serveDaemon(ctx context.Context, ln net.Listener, token, mode string) error {
	if mode != "normal" && mode != "json-rpc" {
		ln.Close()
		return fmt.Errorf("-mode is normal or json-rpc, not %q", mode)
	}
	d := &daemon{c: c, jsonRPC: mode == "json-rpc", byTS: map[int64]msgRef{}, byID: map[string]int64{},
		queued: make(chan struct{})}
	if err := d.load(); err != nil {
		ln.Close()
		return err
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/about", d.about)
	mux.HandleFunc("GET /v1/receive/{number}", d.receive)
	mux.HandleFunc("POST /v2/send", d.send)
	mux.HandleFunc("POST /v1/reactions/{number}", d.react)
	mux.HandleFunc("DELETE /v1/reactions/{number}", d.react)
	mux.HandleFunc("GET /v1/groups/{number}", d.groups)
	srv := &http.Server{Handler: guard(token, mux), ReadHeaderTimeout: 10 * time.Second}

	go d.pollLoop(ctx)
	go func() {
		<-ctx.Done()
		shut, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shut)
	}()
	fmt.Fprintf(os.Stderr, "peachy daemon on http://%s (signal-cli REST API, %s mode). Ctrl-C stops.\n", ln.Addr(), mode)
	if err := srv.Serve(ln); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// guard asks for the token, when there is one, as a bearer token.
func guard(token string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if token != "" && r.Header.Get("Authorization") != "Bearer "+token {
			fail(w, http.StatusUnauthorized, "missing or wrong token")
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 100<<20)
		next.ServeHTTP(w, r)
	})
}

func (d *daemon) pollLoop(ctx context.Context) {
	wait := d.c.waitForMail(ctx, &d.mu)
	for {
		d.poll(ctx)
		// At least once a minute (the fallback poll): asks again in groups waiting for a seat.
		d.c.dev.RetryRejoins(ctx)
		if !wait() {
			return
		}
	}
}

// poll drains the mailbox into the queue.
func (d *daemon) poll(ctx context.Context) {
	d.mu.Lock()
	defer d.mu.Unlock()
	for {
		events, more, err := d.c.dev.Poll(ctx)
		if err != nil {
			if ctx.Err() == nil {
				log.Printf("peachy daemon: mailbox fetch failed: %v", err)
			}
			return
		}
		for _, e := range events {
			if env := d.envelope(ctx, e); env != nil {
				d.queue = append(d.queue, env)
			}
		}
		if len(d.queue) > 0 {
			close(d.queued)
			d.queued = make(chan struct{})
		}
		if over := len(d.queue) - maxQueued; over > 0 {
			log.Printf("peachy daemon: no bot collected %d messages; dropped the oldest", over)
			d.queue = d.queue[over:]
		}
		if !more {
			return
		}
	}
}

// envelope is e as signal-cli would hand it over, or nil for what a bot
// isn't shown.
func (d *daemon) envelope(ctx context.Context, e peachy.Event) map[string]any {
	if e.Type != peachy.EventMessage && e.Type != peachy.EventReaction {
		return nil
	}
	conv, ok := d.conversation(e.Conversation)
	if !ok || d.c.settings(ctx).Blocked(e.Sender) || e.Sender == d.c.me {
		return nil
	}
	d.c.learnNames(ctx, []string{e.Sender})
	if e.Type == peachy.EventMessage && conv.DM() && !d.c.settings(ctx).Contacts[e.Sender].Accepted {
		// A bot answers whoever writes: let them in, as answering a message
		// request does, so the chat isn't a request on the bot's account.
		if err := d.c.dev.Accept(ctx, e.Sender); err != nil {
			log.Printf("peachy daemon: couldn't accept the message request from %s: %v", e.Sender, err)
		} else {
			d.c.store = nil // a write pokes the other devices, not this one
		}
	}
	var dm map[string]any
	if e.Type == peachy.EventMessage {
		ts := d.remember(e.Conversation, e.ID, e.Sender, e.AtMS)
		text := e.Text
		var files []map[string]any
		for _, a := range e.Attachments {
			files = append(files, map[string]any{"contentType": a.Mime, "filename": a.FileName, "size": a.Size})
		}
		// expiresInSeconds is the message's disappearing timer, as in
		// Signal: a bot that keeps messages should drop them after it.
		dm = map[string]any{"timestamp": ts, "message": text, "expiresInSeconds": int64(e.Timer / time.Second), "viewOnce": false}
		if len(files) > 0 {
			dm["attachments"] = files
		}
		if m := signalMentions(text, e.Mentions); len(m) > 0 {
			dm["mentions"] = m
		}
		if e.ReplyTo != "" {
			if q, ok := d.byID[e.ReplyTo]; ok {
				ref := d.byTS[q]
				dm["quote"] = map[string]any{"id": q, "author": ref.Author, "authorUuid": ref.Author, "authorNumber": nil}
			}
		}
	} else {
		target, ok := d.byID[e.Target]
		if !ok {
			return nil // a reaction to something the bot never saw
		}
		ref := d.byTS[target]
		r := map[string]any{"emoji": e.Emoji, "targetAuthor": ref.Author, "targetAuthorUuid": ref.Author,
			"targetSentTimestamp": target, "isRemove": e.Remove}
		if ref.Author == d.c.me {
			// Bots spot reactions to their own posts by their number.
			r["targetAuthorNumber"] = d.c.number
		}
		dm = map[string]any{"timestamp": e.AtMS, "message": nil, "reaction": r}
	}
	if !conv.DM() {
		dm["groupInfo"] = map[string]any{"groupId": conv.ID, "groupName": conv.Name, "type": "DELIVER"}
	}
	return map[string]any{
		"envelope": map[string]any{
			"source": e.Sender, "sourceUuid": e.Sender, "sourceNumber": nil, "sourceName": d.c.names[e.Sender],
			"sourceDevice": 1, "timestamp": dm["timestamp"], "dataMessage": dm,
		},
		"account": d.c.number,
	}
}

func (d *daemon) conversation(id string) (peachy.Conversation, bool) {
	convs, err := d.c.dev.Conversations()
	if err != nil {
		return peachy.Conversation{}, false
	}
	for _, conv := range convs {
		if conv.ID == id {
			return conv, true
		}
	}
	return peachy.Conversation{}, false
}

// remember gives a message its timestamp: about when it arrived, and never
// one another message has.
func (d *daemon) remember(conversation, id, author string, atMS int64) int64 {
	if ts, ok := d.byID[id]; ok {
		return ts
	}
	ts := max(atMS, d.lastTS+1)
	ref := msgRef{TS: ts, Conversation: conversation, ID: id, Author: author}
	d.byTS[ts], d.byID[id], d.lastTS = ref, ts, ts
	if f, err := os.OpenFile(filepath.Join(d.c.dir, idsFile), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600); err == nil {
		_ = json.NewEncoder(f).Encode(ref)
		f.Close()
	}
	return ts
}

func (d *daemon) load() error {
	f, err := os.Open(filepath.Join(d.c.dir, idsFile))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	}
	defer f.Close()
	scan := bufio.NewScanner(f)
	for scan.Scan() {
		var ref msgRef
		if json.Unmarshal(scan.Bytes(), &ref) == nil && ref.ID != "" {
			d.byTS[ref.TS], d.byID[ref.ID] = ref, ref.TS
			d.lastTS = max(d.lastTS, ref.TS)
		}
	}
	return scan.Err()
}

func (d *daemon) about(w http.ResponseWriter, _ *http.Request) {
	mode := "normal"
	if d.jsonRPC {
		mode = "json-rpc"
	}
	reply(w, http.StatusOK, map[string]any{"versions": []string{"v1", "v2"}, "build": 2, "mode": mode,
		"version": "peachy", "capabilities": map[string]any{}})
}

func (d *daemon) receive(w http.ResponseWriter, r *http.Request) {
	d.mu.Lock()
	d.c.number = r.PathValue("number")
	d.mu.Unlock()
	if strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
		d.socket(w, r)
		return
	}
	if d.jsonRPC {
		fail(w, http.StatusBadRequest, "this daemon is in json-rpc mode: receive over a websocket")
		return
	}
	d.poll(r.Context())
	d.mu.Lock()
	out := d.queue
	d.queue = nil
	d.mu.Unlock()
	if out == nil {
		out = []map[string]any{}
	}
	reply(w, http.StatusOK, out)
}

// socket hands each queued envelope to a WebSocket as it arrives, until the
// bot hangs up. What it couldn't send goes back on the queue.
func (d *daemon) socket(w http.ResponseWriter, r *http.Request) {
	ws, err := websocket.Accept(w, r, nil)
	if err != nil {
		return // Accept has answered
	}
	defer ws.CloseNow()
	// Nothing is read from the bot, but reading answers its pings and
	// notices it leaving.
	ctx := ws.CloseRead(r.Context())
	for {
		d.mu.Lock()
		out, queued := d.queue, d.queued
		d.queue = nil
		d.mu.Unlock()
		for i, env := range out {
			b, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "method": "receive", "params": env})
			if err == nil {
				err = ws.Write(ctx, websocket.MessageText, b)
			}
			if err != nil {
				d.mu.Lock()
				d.queue = append(out[i:len(out):len(out)], d.queue...)
				d.mu.Unlock()
				return
			}
		}
		select {
		case <-queued:
		case <-ctx.Done():
			return
		case <-time.After(30 * time.Second):
			// Keep idle proxies from dropping the socket.
			if err := ws.Ping(ctx); err != nil {
				return
			}
		}
	}
}

func (d *daemon) groups(w http.ResponseWriter, r *http.Request) {
	d.mu.Lock()
	defer d.mu.Unlock()
	convs, err := d.c.dev.Conversations()
	if err != nil {
		fail(w, http.StatusInternalServerError, err.Error())
		return
	}
	out := []map[string]any{}
	for _, conv := range convs {
		if conv.DM() {
			continue
		}
		out = append(out, map[string]any{
			"name": conv.Name, "id": "group." + base64.StdEncoding.EncodeToString([]byte(conv.ID)),
			"internal_id": conv.ID, "members": conv.Members, "blocked": false,
			"pending_invites": []string{}, "pending_requests": []string{}, "invite_link": "", "admins": []string{},
		})
	}
	reply(w, http.StatusOK, out)
}

// resolve is the conversation a signal-cli recipient names: "group." and
// base64 of a conversation id (or the id itself), or a person's actor id,
// for the DM with them.
func (d *daemon) resolve(recipient string) (peachy.Conversation, error) {
	convs, err := d.c.dev.Conversations()
	if err != nil {
		return peachy.Conversation{}, err
	}
	if g, ok := strings.CutPrefix(recipient, "group."); ok {
		if raw, err := base64.StdEncoding.DecodeString(g); err == nil {
			g = string(raw)
		}
		for _, conv := range convs {
			if conv.ID == g {
				return conv, nil
			}
		}
		return peachy.Conversation{}, fmt.Errorf("no group %q", recipient)
	}
	person := strings.TrimPrefix(recipient, "+")
	for _, conv := range convs {
		if conv.DM() && (conv.Members[0] == person || conv.Members[1] == person) {
			return conv, nil
		}
	}
	if strings.HasPrefix(recipient, "+") && !strings.Contains(recipient, "-") {
		return peachy.Conversation{}, errors.New("Peachy doesn't share phone numbers: name a person by their id (sourceUuid)")
	}
	return peachy.Conversation{}, fmt.Errorf("no chat with %q yet: they need to message the bot first", recipient)
}

type sendRequest struct {
	Message           string   `json:"message"`
	Recipients        []string `json:"recipients"`
	Base64Attachments []string `json:"base64_attachments"`
	QuoteTimestamp    int64    `json:"quote_timestamp"`
	Mentions          []struct {
		Author string `json:"author"`
		Start  int    `json:"start"`
		Length int    `json:"length"`
	} `json:"mentions"`
}

func (d *daemon) send(w http.ResponseWriter, r *http.Request) {
	var req sendRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		fail(w, http.StatusBadRequest, "couldn't read the request: "+err.Error())
		return
	}
	if len(req.Recipients) == 0 {
		fail(w, http.StatusBadRequest, "no recipients")
		return
	}
	var media []peachy.Media
	for _, a := range req.Base64Attachments {
		m, err := decodeAttachment(a)
		if err != nil {
			fail(w, http.StatusBadRequest, err.Error())
			return
		}
		media = append(media, m)
	}
	ctx := r.Context()
	d.mu.Lock()
	defer d.mu.Unlock()
	text := d.mentionText(ctx, req)
	var ts int64
	for _, recipient := range req.Recipients {
		conv, err := d.resolve(recipient)
		if err != nil {
			fail(w, http.StatusBadRequest, err.Error())
			return
		}
		replyTo := ""
		if ref, ok := d.byTS[req.QuoteTimestamp]; ok && ref.Conversation == conv.ID {
			replyTo = ref.ID
		}
		id, err := peachy.NewMessageID()
		if err != nil {
			fail(w, http.StatusInternalServerError, err.Error())
			return
		}
		if len(media) > 0 {
			err = d.c.dev.SendMedia(ctx, id, conv.ID, text, replyTo, media)
		} else {
			id, err = d.c.dev.SendText(ctx, conv.ID, text, replyTo)
		}
		if err != nil {
			fail(w, http.StatusBadGateway, err.Error())
			return
		}
		ts = d.remember(conv.ID, id, d.c.me, time.Now().UnixMilli())
	}
	reply(w, http.StatusCreated, map[string]any{"timestamp": strconv.FormatInt(ts, 10)})
}

// signalMentions says where each person a message names is in its words, as
// signal-cli does. The words keep the @handle (signal-cli would put a
// placeholder there); start and length count UTF-16 units and cover it.
func signalMentions(text string, mentions []peachy.Mention) []map[string]any {
	var out []map[string]any
	lower := strings.ToLower(text)
	from := 0
	for _, m := range mentions {
		at := strings.Index(lower[from:], "@"+m.Handle)
		if m.Handle == "" || at < 0 {
			continue
		}
		at += from
		end := at + 1 + len(m.Handle)
		out = append(out, map[string]any{"uuid": m.UserID, "number": nil, "name": m.Handle,
			"start": len(utf16Of(text[:at])), "length": len(utf16Of(text[at:end]))})
		from = end
	}
	return out
}

// mentionText writes Signal's mentions into the words: signal-cli puts a
// placeholder where each goes, and Peachy's words carry an @handle, which
// the library turns into a real mention (or a name, for someone without a
// handle, which stays words).
func (d *daemon) mentionText(ctx context.Context, req sendRequest) string {
	if len(req.Mentions) == 0 {
		return req.Message
	}
	var ids []string
	for _, m := range req.Mentions {
		ids = append(ids, m.Author)
	}
	handles := map[string]string{}
	if people, err := d.c.dev.People(ctx, ids); err == nil {
		for _, p := range people {
			if p.Handle != "" {
				handles[p.ID] = "@" + p.Handle
			} else {
				handles[p.ID] = "@" + p.Name
			}
		}
	}
	// Mentions count UTF-16 units, as in Signal; rewrite from the end so
	// earlier offsets hold.
	units := utf16Of(req.Message)
	for i := len(req.Mentions) - 1; i >= 0; i-- {
		m := req.Mentions[i]
		at := handles[m.Author]
		if at == "" || m.Start < 0 || m.Length < 0 || m.Start+m.Length > len(units) {
			continue
		}
		units = append(units[:m.Start], append(utf16Of(at), units[m.Start+m.Length:]...)...)
	}
	return fromUTF16(units)
}

func (d *daemon) react(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Reaction     string `json:"reaction"`
		Recipient    string `json:"recipient"`
		TargetAuthor string `json:"target_author"`
		Timestamp    int64  `json:"timestamp"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		fail(w, http.StatusBadRequest, "couldn't read the request: "+err.Error())
		return
	}
	remove := r.Method == http.MethodDelete
	if !remove && !peachy.ValidEmoji(req.Reaction) {
		fail(w, http.StatusBadRequest, "Peachy reactions are a single emoji")
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	ref, ok := d.byTS[req.Timestamp]
	if !ok {
		fail(w, http.StatusBadRequest, "no message with that timestamp")
		return
	}
	if err := d.c.dev.React(r.Context(), ref.Conversation, ref.ID, req.Reaction, remove); err != nil {
		fail(w, http.StatusBadGateway, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// decodeAttachment reads signal-cli's base64_attachments item: plain base64,
// or data:<mime>;filename=<name>;base64,<data>.
func decodeAttachment(s string) (peachy.Media, error) {
	m := peachy.Media{FileName: "file"}
	data := s
	if rest, ok := strings.CutPrefix(s, "data:"); ok {
		head, body, ok := strings.Cut(rest, ",")
		if !ok || !strings.HasSuffix(head, ";base64") {
			return m, errors.New("an attachment's data: URL must be base64")
		}
		data = body
		for i, part := range strings.Split(strings.TrimSuffix(head, ";base64"), ";") {
			if i == 0 {
				m.Mime = part
			} else if name, ok := strings.CutPrefix(part, "filename="); ok {
				m.FileName = filepath.Base(name)
			}
		}
	}
	raw, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return m, errors.New("an attachment isn't base64")
	}
	m.Data = raw
	if m.Mime == "" {
		m.Mime = http.DetectContentType(raw)
	}
	if m.FileName == "file" {
		if exts, _ := mime.ExtensionsByType(m.Mime); len(exts) > 0 {
			m.FileName += exts[0]
		}
	}
	return m, nil
}

func reply(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func fail(w http.ResponseWriter, status int, msg string) {
	reply(w, status, map[string]string{"error": msg})
}

func utf16Of(s string) []uint16   { return utf16.Encode([]rune(s)) }
func fromUTF16(u []uint16) string { return string(utf16.Decode(u)) }
