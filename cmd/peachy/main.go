// Command peachy is Peachy in a terminal: its own linked device, separate
// from the bridge's, on this library.
//
//	peachy login PHONE        sign in and link this device
//	peachy chats              list conversations
//	peachy read CHAT [-n N]   show messages received since linking
//	peachy send CHAT TEXT...  send words (or stdin); -f FILE attaches files,
//	                          -r MSG replies
//	peachy react CHAT MSG EMOJI, unreact CHAT MSG
//	peachy edit CHAT MSG TEXT..., delete CHAT MSG   your own messages
//	peachy follow [CHAT]      print messages as they arrive
//	peachy daemon             answer signal-cli's REST API, for bots
//	peachy status
//
// CHAT is a conversation's id (or the start of it), its name, or the name of
// someone in it. MSG is the start of a message's id, as read shows it in
// brackets, or "last" for the newest one. Peachy doesn't hand new devices old
// messages, so read shows only what arrived after linking, kept in the data
// folder.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"github.com/rs/zerolog"
	"io"
	"mime"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/collinjackson/peachy-go"
)

const (
	// Peachy's live stream says when to fetch; this is the backstop.
	fallbackInterval = time.Minute
	linkPoll         = 2 * time.Second
	logFile          = "messages.jsonl"
)

func usage() {
	fmt.Fprint(os.Stderr, `usage: peachy [-d DIR] [-server URL] COMMAND

  login PHONE        sign in and link this device (-name sets its name)
  chats              list conversations
  read CHAT [-n N]   show messages received since linking
  send CHAT TEXT...  send words, or stdin when there are none; -f FILE attaches,
                     -r MSG replies to a message
  react CHAT MSG EMOJI   react to a message; unreact CHAT MSG takes it back
  edit CHAT MSG TEXT...  change the words of one of your messages
  delete CHAT MSG        delete one of your messages for everyone
  follow [CHAT]      print messages as they arrive, until Ctrl-C
  daemon             answer signal-cli's REST API, so bots written for it run
                     on Peachy; -listen ADDR (default 127.0.0.1:8080), -token,
                     -mode json-rpc to receive over a WebSocket
  forget-group CHAT  drop this device's copy of a group stuck on an old epoch;
                     then have a member remove and re-add it
  rejoin CHAT        forget a stuck group and ask its members for a seat (the
                     daemon does this itself, and asks again until seated); for
                     a group already forgotten, -to USER:DEVICE,... names whom
  roster CHAT        list the group's devices as USER:DEVICE, reading nothing
                     from the mailbox
  status             show whether this device is signed in and linked

`)
	flag.PrintDefaults()
}

func main() {
	configDir, _ := os.UserConfigDir()
	dir := flag.String("d", envOr("PEACHY_DIR", filepath.Join(configDir, "peachy-cli")), "where this device's keys live (keep it private)")
	server := flag.String("server", envOr("PEACHY_SERVER", "https://api.pchy.app"), "the Peachy API")
	flag.Usage = usage
	flag.Parse()
	if flag.NArg() == 0 {
		usage()
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	// The library reports what it skips (an envelope it couldn't process, a stale device) through
	// the context's logger: without one those warnings vanish. Info and up (a rejoin's progress,
	// warnings), to stderr.
	logger := zerolog.New(zerolog.ConsoleWriter{Out: os.Stderr, NoColor: true, TimeFormat: time.RFC3339}).
		Level(zerolog.InfoLevel).With().Timestamp().Logger()
	ctx = logger.WithContext(ctx)
	if err := run(ctx, *server, *dir, flag.Arg(0), flag.Args()[1:]); err != nil && !errors.Is(err, context.Canceled) {
		fmt.Fprintln(os.Stderr, "peachy:", err)
		os.Exit(1)
	}
}

// parseRecipients reads -to: USER:DEVICE pairs, comma-separated.
func parseRecipients(s string) ([]peachy.Recipient, error) {
	var out []peachy.Recipient
	for _, pair := range strings.Split(s, ",") {
		if pair = strings.TrimSpace(pair); pair == "" {
			continue
		}
		user, device, ok := strings.Cut(pair, ":")
		if !ok || user == "" || device == "" {
			return nil, fmt.Errorf("-to wants USER:DEVICE, not %q", pair)
		}
		out = append(out, peachy.Recipient{User: user, Device: device})
	}
	return out, nil
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

type cli struct {
	dev   *peachy.Device
	dir   string
	me    string
	names map[string]string // actor id → display name
	store *peachy.Store     // the person's Peachy settings; nil until read
	// What a bot calls this account (daemon): its phone number, by
	// signal-cli's habit.
	number string
}

// settings reads the person's Peachy settings (contact names, blocks) once.
// Without them the CLI goes on with Peachy names and nobody blocked.
func (c *cli) settings(ctx context.Context) *peachy.Store {
	if c.store == nil {
		if s, err := c.dev.ReadStore(ctx); err == nil {
			c.store = s
		} else {
			c.store = &peachy.Store{}
		}
	}
	return c.store
}

func run(ctx context.Context, server, dir, cmd string, args []string) error {
	fs := flag.NewFlagSet(cmd, flag.ExitOnError)
	name := fs.String("name", "Peachy CLI", "login: what Peachy's Devices list calls this device")
	n := fs.Int("n", 20, "read: how many messages")
	var files fileList
	fs.Var(&files, "f", "send: a file to attach (repeatable)")
	reply := fs.String("r", "", "send: the message to reply to")
	listen := fs.String("listen", "127.0.0.1:8080", "daemon: where to answer")
	token := fs.String("token", os.Getenv("PEACHY_DAEMON_TOKEN"), "daemon: a bearer token bots must send")
	mode := fs.String("mode", "normal", "daemon: normal, or json-rpc to receive only over a WebSocket")
	to := fs.String("to", "", "rejoin: USER:DEVICE,... to ask, for a group already forgotten")
	// Flags may come before or after CHAT and the words.
	var rest []string
	for {
		if err := fs.Parse(args); err != nil {
			return err
		}
		if args = fs.Args(); len(args) == 0 {
			break
		}
		rest, args = append(rest, args[0]), args[1:]
	}
	args = rest

	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	unlock, err := lock(dir)
	if err != nil {
		return err
	}
	defer unlock()
	dev, err := peachy.Open(server, dir, *name)
	if err != nil {
		return err
	}
	defer dev.Close()
	c := &cli{dev: dev, dir: dir, names: map[string]string{}}

	if cmd == "login" {
		if len(args) != 1 {
			return errors.New("usage: peachy login PHONE")
		}
		return c.login(ctx, args[0])
	}
	st := dev.Status()
	if cmd == "status" {
		fmt.Printf("signed in: %v\nlinked: %v\ndata: %s\n", st.SignedIn, st.Linked, dir)
		return nil
	}
	if !st.Linked {
		return errors.New("not linked yet: run peachy login PHONE")
	}
	if err := c.connect(ctx); err != nil {
		return err
	}
	if cmd != "follow" && cmd != "daemon" && cmd != "roster" && cmd != "rejoin" {
		if _, err := c.sync(ctx, nil); err != nil {
			return err
		}
		if err := c.forget(); err != nil {
			return err
		}
	}

	switch cmd {
	case "chats":
		return c.chats(ctx)
	case "read":
		if len(args) != 1 {
			return errors.New("usage: peachy read CHAT [-n N]")
		}
		return c.read(ctx, args[0], *n)
	case "send":
		if len(args) < 1 {
			return errors.New("usage: peachy send CHAT [-f FILE] [TEXT...]")
		}
		return c.send(ctx, args[0], strings.Join(args[1:], " "), files, *reply)
	case "react", "unreact", "edit", "delete":
		want := map[string]int{"react": 3, "unreact": 2, "edit": 3, "delete": 2}[cmd]
		if len(args) < want || (cmd != "edit" && len(args) != want) {
			return fmt.Errorf("usage: peachy %s CHAT MSG%s", cmd, map[string]string{"react": " EMOJI", "edit": " TEXT..."}[cmd])
		}
		return c.change(ctx, cmd, args[0], args[1], strings.Join(args[2:], " "))
	case "follow":
		chat := ""
		if len(args) > 0 {
			chat = args[0]
		}
		return c.follow(ctx, chat)
	case "daemon":
		return c.daemon(ctx, *listen, *token, *mode)
	case "forget-group":
		if len(args) != 1 {
			return errors.New("usage: peachy forget-group CHAT")
		}
		ch, err := c.find(ctx, args[0])
		if err != nil {
			return err
		}
		if err := c.dev.ForgetGroup(ch.ID); err != nil {
			return err
		}
		fmt.Printf("forgot %s (%s): have a member remove and re-add this device\n", ch.Name, ch.ID)
		return nil
	case "roster":
		if len(args) != 1 {
			return errors.New("usage: peachy roster CHAT")
		}
		ch, err := c.find(ctx, args[0])
		if err != nil {
			return err
		}
		devices, err := c.dev.Roster(ch.ID)
		if err != nil {
			return err
		}
		for _, r := range devices {
			fmt.Printf("%s:%s\n", r.User, r.Device)
		}
		return nil
	case "rejoin":
		if len(args) != 1 {
			return errors.New("usage: peachy rejoin CHAT [-to USER:DEVICE,...]")
		}
		recipients, err := parseRecipients(*to)
		if err != nil {
			return err
		}
		id := args[0]
		if ch, err := c.find(ctx, id); err == nil {
			id = ch.ID
		} else if len(recipients) == 0 {
			return err
		}
		if err := c.dev.Rejoin(ctx, id, recipients); err != nil {
			return err
		}
		fmt.Printf("asked for a seat in %s; the daemon asks again until a member seats this device\n", id)
		return nil
	}
	usage()
	os.Exit(2)
	return nil
}

// lock keeps two peachy commands from using one device at once: they would
// both advance the same MLS state.
func lock(dir string) (func(), error) {
	f, err := os.OpenFile(filepath.Join(dir, "lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		return nil, errors.New("another peachy command is using this device (is peachy follow running?)")
	}
	return func() { f.Close() }, nil
}

func (c *cli) login(ctx context.Context, phone string) error {
	st := c.dev.Status()
	if st.Linked {
		fmt.Println("Already linked.")
		return c.connect(ctx)
	}
	if !st.SignedIn {
		if err := c.dev.StartLogin(ctx, phone); err != nil {
			return err
		}
		fmt.Print("Code from the text message: ")
		code, err := bufio.NewReader(os.Stdin).ReadString('\n')
		if err != nil {
			return err
		}
		if _, err := c.dev.FinishLogin(ctx, phone, strings.TrimSpace(code)); err != nil {
			return err
		}
	}
	shown := "-"
	for {
		s, err := c.dev.LinkStep(ctx)
		if err != nil {
			return err
		}
		switch {
		case s.State == peachy.LinkApproved:
			if err := c.connect(ctx); err != nil {
				return err
			}
			fmt.Println("Linked. Try peachy chats.")
			return nil
		case s.State == peachy.LinkConfirmApprover:
			pick, err := askApproverNumber(s)
			if err != nil {
				return err
			}
			if err := c.dev.ConfirmApprover(pick); err != nil {
				return fmt.Errorf("%w. Remove this device on %s if it shows, then run login again", err, s.Approver)
			}
			continue
		case s.State == peachy.LinkPickNumber && s.Number != shown:
			fmt.Printf("On %s, pick %s.\n", s.Approver, s.Number)
			shown = s.Number
		case s.State != peachy.LinkPickNumber && shown != "":
			fmt.Println(`Open Peachy on your phone and tap "add another device". A number will show up here; pick the same one on your phone.`)
			shown = ""
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(linkPoll):
		}
	}
}

// askApproverNumber asks which number the phone shows now. Picking it is what
// vouches for the phone: a box from any other device won't open. Anything
// other than one of the choices counts as "none of these".
func askApproverNumber(s peachy.LinkStatus) (string, error) {
	fmt.Printf("%s now shows a number. Which one? %s, or 0 for none of these: ", s.Approver, strings.Join(s.Choices, ", "))
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil {
		return "", err
	}
	line = strings.TrimSpace(line)
	for _, c := range s.Choices {
		if line == c {
			return c, nil
		}
	}
	return "", nil
}

// connect certifies the device and opens its MLS state.
func (c *cli) connect(ctx context.Context) error {
	if err := c.dev.Connect(ctx); err != nil {
		return err
	}
	me, err := c.dev.Me()
	if err != nil {
		return err
	}
	c.me = me
	return nil
}

// sync drains the mailbox, keeping each message and change to one and
// handing it to show.
func (c *cli) sync(ctx context.Context, show func(peachy.Event)) (int, error) {
	got := 0
	for {
		events, more, err := c.dev.Poll(ctx)
		if err != nil {
			return got, err
		}
		for _, e := range events {
			switch e.Type {
			case peachy.EventMessage, peachy.EventReaction, peachy.EventEdit, peachy.EventDelete:
			case peachy.EventReceipt:
				if e.Sender == c.me && e.Receipt == peachy.ReceiptRead {
					if err := c.keepLine(keptFrom(e)); err != nil {
						return got, err
					}
				}
				continue
			default:
				continue
			}
			if c.settings(ctx).Blocked(e.Sender) {
				continue // as Peachy does: nothing from someone you blocked
			}
			got++
			if err := c.keepLine(keptFrom(e)); err != nil {
				return got, err
			}
			if show != nil {
				show(e)
			}
		}
		if !more {
			return got, nil
		}
	}
}

// kept is one line of the message log: a message, or a reaction, edit or
// delete naming one (Target). This device's own sends are kept too, since
// Peachy hands a device no copy of what it sent.
type kept struct {
	Type         string   `json:"type,omitempty"` // "" for a message
	Conversation string   `json:"conversation"`
	ID           string   `json:"id,omitempty"`
	Sender       string   `json:"sender"`
	Text         string   `json:"text,omitempty"`
	Files        []string `json:"files,omitempty"`
	ReplyTo      string   `json:"reply_to,omitempty"`
	Target       string   `json:"target,omitempty"`
	Emoji        string   `json:"emoji,omitempty"`
	Remove       bool     `json:"remove,omitempty"`
	Revision     int      `json:"revision,omitempty"`
	// A message's disappearing timer, in seconds; 0 for none.
	Timer int64 `json:"timer,omitempty"`
	AtMS  int64 `json:"at_ms"`
}

// Log lines that start a disappearing message's countdown: this device
// showed it (seen, naming it), or another of your devices read up to it
// (read, naming the newest message it covers).
const (
	keptSeen = "seen"
	keptRead = "read"
)

func keptFrom(e peachy.Event) kept {
	k := kept{Conversation: e.Conversation, ID: e.ID, Sender: e.Sender, Text: e.Text, ReplyTo: e.ReplyTo,
		Target: e.Target, Emoji: e.Emoji, Remove: e.Remove, Revision: e.Revision,
		Timer: int64(e.Timer / time.Second), AtMS: e.AtMS}
	switch e.Type {
	case peachy.EventMessage:
	case peachy.EventReceipt:
		k.Type = keptRead
		// A note stamped in the future starts the countdown now.
		k.AtMS = min(e.AtMS, time.Now().UnixMilli())
	default:
		k.Type = e.Type
	}
	for _, a := range e.Attachments {
		k.Files = append(k.Files, fileLabel(a))
	}
	return k
}

// keepLine appends to the log.
func (c *cli) keepLine(k kept) error {
	f, err := os.OpenFile(filepath.Join(c.dir, logFile), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	return json.NewEncoder(f).Encode(k)
}

// shown is a message as read shows it, with what has happened to it since.
type shown struct {
	kept
	edits     int // revision applied
	deleted   bool
	reactions map[string]string // sender → emoji
	seen      bool              // its disappearing countdown has started
}

// transcript folds a chat's log into its messages, oldest first, applying
// Peachy's rules: reactions one per person, latest wins; only the author
// edits (above the shown revision) or deletes.
func (c *cli) transcript(conversation string) ([]*shown, error) {
	f, err := os.Open(filepath.Join(c.dir, logFile))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	defer f.Close()
	var order []*shown
	byID := map[string]*shown{}
	scan := bufio.NewScanner(f)
	scan.Buffer(nil, 1<<20)
	for scan.Scan() {
		var k kept
		if json.Unmarshal(scan.Bytes(), &k) != nil || k.Conversation != conversation {
			continue
		}
		if k.Type == "" {
			if byID[k.ID] == nil {
				m := &shown{kept: k, reactions: map[string]string{}, seen: k.Sender == c.me}
				byID[k.ID] = m
				order = append(order, m)
			}
			continue
		}
		if k.Type == keptRead && byID[k.Target] != nil {
			for _, m := range order {
				m.seen = true
				if m.ID == k.Target {
					break
				}
			}
		}
		m := byID[k.Target]
		if m == nil {
			continue
		}
		switch k.Type {
		case peachy.EventReaction:
			if k.Remove {
				delete(m.reactions, k.Sender)
			} else {
				m.reactions[k.Sender] = k.Emoji
			}
		case peachy.EventEdit:
			if k.Sender == m.Sender && k.Revision > m.edits && !m.deleted {
				m.Text, m.edits = k.Text, k.Revision
			}
		case peachy.EventDelete:
			if k.Sender == m.Sender {
				m.deleted = true
			}
		case keptSeen:
			m.seen = true
		}
	}
	return order, scan.Err()
}

// message resolves MSG in a chat: "last", or the start of an id.
func (c *cli) message(conversation, query string) (*shown, error) {
	msgs, err := c.transcript(conversation)
	if err != nil {
		return nil, err
	}
	var live []*shown
	for _, m := range msgs {
		if !m.deleted {
			live = append(live, m)
		}
	}
	if query == "last" {
		if len(live) == 0 {
			return nil, errors.New("no messages here yet")
		}
		return live[len(live)-1], nil
	}
	var matches []*shown
	for _, m := range live {
		if strings.HasPrefix(m.ID, strings.ToLower(query)) {
			matches = append(matches, m)
		}
	}
	switch {
	case len(query) < 4:
		return nil, errors.New(`name a message by at least 4 characters of its id, or "last"`)
	case len(matches) == 0:
		return nil, fmt.Errorf("no message %q here (see peachy read)", query)
	case len(matches) > 1:
		return nil, fmt.Errorf("%q matches %d messages", query, len(matches))
	}
	return matches[0], nil
}

func fileLabel(a peachy.Attachment) string {
	if a.FileName != "" {
		return a.FileName
	}
	return a.Mime
}

// chat is a conversation with the name it's shown under.
type chat struct {
	peachy.Conversation
	label string
}

func (c *cli) conversations(ctx context.Context) ([]chat, error) {
	convs, err := c.dev.Conversations()
	if err != nil {
		return nil, err
	}
	var ids []string
	for _, conv := range convs {
		ids = append(ids, conv.Members...)
	}
	c.learnNames(ctx, ids)
	var out []chat
	for _, conv := range convs {
		label := conv.Name
		if label == "" {
			var others []string
			for _, m := range conv.Members {
				if m != c.me {
					others = append(others, c.name(m))
				}
			}
			label = strings.Join(others, ", ")
		}
		if label == "" {
			label = "Note to self"
		}
		out = append(out, chat{conv, label})
	}
	sort.Slice(out, func(i, j int) bool { return strings.ToLower(out[i].label) < strings.ToLower(out[j].label) })
	return out, nil
}

func (c *cli) learnNames(ctx context.Context, ids []string) {
	var unknown []string
	seen := map[string]bool{}
	for _, id := range ids {
		if _, ok := c.names[id]; !ok && !seen[id] {
			seen[id] = true
			unknown = append(unknown, id)
		}
	}
	if len(unknown) == 0 {
		return
	}
	people, err := c.dev.People(ctx, unknown)
	if err != nil {
		return
	}
	for _, p := range people {
		c.names[p.ID] = c.settings(ctx).NameFor(p.ID, p.Name)
	}
}

func (c *cli) name(id string) string {
	if id == c.me {
		return "you"
	}
	if n := c.names[id]; n != "" {
		return n
	}
	return id[:min(8, len(id))]
}

// find resolves CHAT: an id or the start of one, else a name.
func (c *cli) find(ctx context.Context, query string) (chat, error) {
	chats, err := c.conversations(ctx)
	if err != nil {
		return chat{}, err
	}
	q := strings.ToLower(query)
	var matches []chat
	for _, ch := range chats {
		if ch.ID == query {
			return ch, nil
		}
		if (len(q) >= 4 && strings.HasPrefix(strings.ToLower(ch.ID), q)) || strings.Contains(strings.ToLower(ch.label), q) {
			matches = append(matches, ch)
		}
	}
	switch len(matches) {
	case 0:
		return chat{}, fmt.Errorf("no chat matches %q (see peachy chats)", query)
	case 1:
		return matches[0], nil
	}
	var names []string
	for _, m := range matches {
		names = append(names, fmt.Sprintf("%s (%s)", m.label, m.ID[:8]))
	}
	return chat{}, fmt.Errorf("%q matches %d chats: %s", query, len(matches), strings.Join(names, "; "))
}

func (c *cli) chats(ctx context.Context) error {
	chats, err := c.conversations(ctx)
	if err != nil {
		return err
	}
	if len(chats) == 0 {
		fmt.Println("No chats yet. Chats show up here once someone writes in them.")
	}
	for _, ch := range chats {
		fmt.Printf("%s  %s  (%d people)\n", ch.ID[:8], ch.label, len(ch.Members))
	}
	return nil
}

func (c *cli) read(ctx context.Context, query string, n int) error {
	ch, err := c.find(ctx, query)
	if err != nil {
		return err
	}
	all, err := c.transcript(ch.ID)
	if err != nil {
		return err
	}
	var msgs []*shown
	for _, m := range all {
		if !m.deleted {
			msgs = append(msgs, m)
		}
	}
	if len(msgs) == 0 {
		fmt.Println("Nothing yet: messages show up here once they arrive after linking.")
		return nil
	}
	msgs = msgs[max(0, len(msgs)-n):]
	var people []string
	for _, m := range msgs {
		people = append(people, m.Sender)
		for r := range m.reactions {
			people = append(people, r)
		}
	}
	c.learnNames(ctx, people)
	for _, m := range msgs {
		c.printShown(m)
		if err := c.noteSeen(m.kept, m.seen); err != nil {
			return err
		}
	}
	return nil
}

// noteSeen starts a shown message's disappearing countdown, once.
func (c *cli) noteSeen(m kept, seen bool) error {
	if m.Timer == 0 || seen || m.Sender == c.me {
		return nil
	}
	return c.keepLine(kept{Type: keptSeen, Conversation: m.Conversation, Sender: c.me, Target: m.ID, AtMS: time.Now().UnixMilli()})
}

// forget deletes from the log every message whose disappearing timer has
// run out, and every line naming it, as Peachy's apps delete them: your own
// count down from sending, anyone else's from when one of your devices
// first showed it.
func (c *cli) forget() error {
	path := filepath.Join(c.dir, logFile)
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	}
	lines := strings.SplitAfter(string(b), "\n")
	type msg struct {
		k       kept
		started int64 // 0: not yet
	}
	msgs := map[string]*msg{}
	order := map[string][]*msg{} // conversation → its messages, in log order
	parsed := make([]kept, len(lines))
	start := func(m *msg, at int64) {
		if m.started == 0 || at < m.started {
			m.started = at
		}
	}
	for i, line := range lines {
		if json.Unmarshal([]byte(line), &parsed[i]) != nil {
			continue
		}
		k := parsed[i]
		switch k.Type {
		case "":
			if msgs[k.ID] == nil && k.Timer > 0 {
				m := &msg{k: k}
				if k.Sender == c.me {
					m.started = k.AtMS
				}
				msgs[k.ID] = m
			}
			if m := msgs[k.ID]; m != nil {
				order[k.Conversation] = append(order[k.Conversation], m)
			}
		case keptSeen:
			if m := msgs[k.Target]; m != nil {
				start(m, k.AtMS)
			}
		case keptRead:
			if msgs[k.Target] == nil {
				break
			}
			for _, m := range order[k.Conversation] {
				start(m, k.AtMS)
				if m.k.ID == k.Target {
					break
				}
			}
		}
	}
	now := time.Now().UnixMilli()
	gone := map[string]bool{}
	for id, m := range msgs {
		if m.started != 0 && m.started+m.k.Timer*1000 <= now {
			gone[id] = true
		}
	}
	if len(gone) == 0 {
		return nil
	}
	var out strings.Builder
	for i, line := range lines {
		if k := parsed[i]; gone[k.ID] || gone[k.Target] {
			continue
		}
		out.WriteString(line)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(out.String()), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func (c *cli) printShown(m *shown) {
	at := time.UnixMilli(m.AtMS).Local().Format("Jan 2 15:04")
	line := fmt.Sprintf("%s  [%s] %s: %s", at, m.ID[:min(8, len(m.ID))], c.name(m.Sender), body(m.kept))
	if m.edits > 0 {
		line += "  (edited)"
	}
	if m.ReplyTo != "" {
		line += "  ↪ " + m.ReplyTo[:min(8, len(m.ReplyTo))]
	}
	fmt.Println(line)
	if len(m.reactions) > 0 {
		var rs []string
		for who, emoji := range m.reactions {
			rs = append(rs, emoji+" "+c.name(who))
		}
		sort.Strings(rs)
		fmt.Println("                   " + strings.Join(rs, "  "))
	}
}

func body(m kept) string {
	b := m.Text
	for _, f := range m.Files {
		if b != "" {
			b += " "
		}
		b += "[" + f + "]"
	}
	return b
}

// print is one line of follow.
func (c *cli) print(where string, m kept) {
	at := time.UnixMilli(m.AtMS).Local().Format("Jan 2 15:04")
	if where != "" {
		where = " in " + where
	}
	short := func(id string) string { return id[:min(8, len(id))] }
	switch m.Type {
	case peachy.EventReaction:
		if m.Remove {
			fmt.Printf("%s  %s%s took back a reaction to [%s]\n", at, c.name(m.Sender), where, short(m.Target))
		} else {
			fmt.Printf("%s  %s%s reacted %s to [%s]\n", at, c.name(m.Sender), where, m.Emoji, short(m.Target))
		}
	case peachy.EventEdit:
		fmt.Printf("%s  %s%s edited [%s]: %s\n", at, c.name(m.Sender), where, short(m.Target), m.Text)
	case peachy.EventDelete:
		fmt.Printf("%s  %s%s deleted [%s]\n", at, c.name(m.Sender), where, short(m.Target))
	default:
		reply := ""
		if m.ReplyTo != "" {
			reply = "  ↪ " + short(m.ReplyTo)
		}
		fmt.Printf("%s  [%s] %s%s: %s%s\n", at, short(m.ID), c.name(m.Sender), where, body(m), reply)
	}
}

func (c *cli) send(ctx context.Context, query, text string, files []string, replyQuery string) error {
	ch, err := c.find(ctx, query)
	if err != nil {
		return err
	}
	replyTo := ""
	if replyQuery != "" {
		m, err := c.message(ch.ID, replyQuery)
		if err != nil {
			return err
		}
		replyTo = m.ID
	}
	own := kept{Conversation: ch.ID, Sender: c.me, Text: text, ReplyTo: replyTo,
		Timer: int64(ch.Timer / time.Second), AtMS: time.Now().UnixMilli()}
	if text == "" && len(files) == 0 {
		in, err := io.ReadAll(os.Stdin)
		if err != nil {
			return err
		}
		text = strings.TrimRight(string(in), "\n")
	}
	if len(files) == 0 {
		if text == "" {
			return errors.New("nothing to send")
		}
		id, err := c.dev.SendText(ctx, ch.ID, text, replyTo)
		if err != nil {
			return err
		}
		own.ID, own.Text = id, text
		return c.keepLine(own)
	}
	if len(files) > peachy.MaxAttachments {
		return fmt.Errorf("a message can carry at most %d files", peachy.MaxAttachments)
	}
	var media []peachy.Media
	for _, path := range files {
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		m := mime.TypeByExtension(strings.ToLower(filepath.Ext(path)))
		if m == "" {
			m = http.DetectContentType(data)
		}
		m, _, _ = strings.Cut(m, ";")
		media = append(media, peachy.Media{Data: data, Mime: m, FileName: filepath.Base(path)})
		own.Files = append(own.Files, filepath.Base(path))
	}
	id, err := peachy.NewMessageID()
	if err != nil {
		return err
	}
	if err := c.dev.SendMedia(ctx, id, ch.ID, text, replyTo, media); err != nil {
		return err
	}
	own.ID = id
	return c.keepLine(own)
}

// change reacts to, edits or deletes a message, under Peachy's rules.
func (c *cli) change(ctx context.Context, cmd, query, msgQuery, arg string) error {
	ch, err := c.find(ctx, query)
	if err != nil {
		return err
	}
	m, err := c.message(ch.ID, msgQuery)
	if err != nil {
		return err
	}
	k := kept{Type: map[string]string{"react": peachy.EventReaction, "unreact": peachy.EventReaction,
		"edit": peachy.EventEdit, "delete": peachy.EventDelete}[cmd],
		Conversation: ch.ID, Sender: c.me, Target: m.ID, AtMS: time.Now().UnixMilli()}
	switch cmd {
	case "react":
		if !peachy.ValidEmoji(arg) {
			return errors.New("Peachy reactions are a single emoji")
		}
		err, k.Emoji = c.dev.React(ctx, ch.ID, m.ID, arg, false), arg
	case "unreact":
		err, k.Remove = c.dev.React(ctx, ch.ID, m.ID, "", true), true
	case "edit":
		switch {
		case m.Sender != c.me:
			return errors.New("you can only edit your own messages")
		case time.Since(time.UnixMilli(m.AtMS)) > 24*time.Hour:
			return errors.New("Peachy allows edits for 24 hours")
		case m.edits >= peachy.MaxEditRevision:
			return errors.New("Peachy allows ten edits per message")
		}
		k.Revision, k.Text = m.edits+1, arg
		err = c.dev.Edit(ctx, ch.ID, m.ID, k.Revision, arg)
	case "delete":
		if m.Sender != c.me {
			return errors.New("you can only delete your own messages")
		}
		err = c.dev.Delete(ctx, ch.ID, m.ID)
	}
	if err != nil {
		return err
	}
	return c.keepLine(k)
}

func (c *cli) follow(ctx context.Context, query string) error {
	only := ""
	if query != "" {
		ch, err := c.find(ctx, query)
		if err != nil {
			return err
		}
		only = ch.ID
		fmt.Fprintf(os.Stderr, "Following %s. Ctrl-C stops.\n", ch.label)
	} else {
		fmt.Fprintln(os.Stderr, "Following every chat. Ctrl-C stops.")
	}
	// Where each message was written, for groups; a DM's sender says it.
	labels := map[string]string{}
	refresh := func() {
		if chats, err := c.conversations(ctx); err == nil {
			for _, ch := range chats {
				labels[ch.ID] = ch.Name
			}
		}
	}
	refresh()
	wait := c.waitForMail(ctx, &sync.Mutex{})
	for {
		_, err := c.sync(ctx, func(e peachy.Event) {
			if only != "" && e.Conversation != only {
				return
			}
			if _, ok := labels[e.Conversation]; !ok {
				refresh()
			}
			c.learnNames(ctx, []string{e.Sender})
			where := ""
			if only == "" {
				where = labels[e.Conversation]
			}
			k := keptFrom(e)
			c.print(where, k)
			if e.Type == peachy.EventMessage {
				_ = c.noteSeen(k, false)
			}
		})
		if err != nil && ctx.Err() == nil {
			fmt.Fprintln(os.Stderr, "peachy: mailbox fetch failed:", err)
		}
		if err := c.forget(); err != nil {
			fmt.Fprintln(os.Stderr, "peachy: couldn't delete expired messages:", err)
		}
		if !wait() {
			return nil
		}
	}
}

// waitForMail returns a wait that blocks until Peachy's live stream says
// something is in the mailbox (or fallbackInterval passes), as Peachy's apps
// wait; it reports false once ctx ends. A settings change on the way drops
// the cached settings, so blocks and names are read afresh.
func (c *cli) waitForMail(ctx context.Context, mu sync.Locker) func() bool {
	changes := c.dev.Listen(ctx)
	return func() bool {
		t := time.NewTimer(fallbackInterval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return false
			case ch, ok := <-changes:
				if !ok {
					return false
				}
				if ch.Settings || ch.People {
					mu.Lock()
					c.store, c.names = nil, map[string]string{}
					mu.Unlock()
				}
				if ch.Mailbox {
					return true
				}
			case <-t.C:
				return true
			}
		}
	}
}

type fileList []string

func (f *fileList) String() string     { return strings.Join(*f, ",") }
func (f *fileList) Set(v string) error { *f = append(*f, v); return nil }
