//go:build testissuer

package peachy

// Two or three accounts, each one real Device, against the fake server
// (peachytest): sign-in and linking, a DM and a group, every kind of
// message, membership changes and a lost mailbox. A send has landed in the
// recipient's mailbox by the time it returns, so each Poll is deterministic.

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"testing"
	"time"

	"github.com/rs/zerolog"

	"github.com/collinjackson/peachy-go/peachytest"
)

type person struct {
	*Device
	actor string
}

func signIn(t *testing.T, srv *peachytest.Server, phone, name, handle string) person {
	t.Helper()
	return signInAs(t, srv, srv.AddAccount(phone, name, handle), phone, name)
}

// signInAs signs in to an account the test already made (AddAccountOneKey,
// AddBot).
func signInAs(t *testing.T, srv *peachytest.Server, actor, phone, name string) person {
	t.Helper()
	ctx := context.Background()
	dev, err := Open(srv.URL, t.TempDir(), name+"'s bot")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(dev.Close)
	if err := dev.StartLogin(ctx, phone); err != nil {
		t.Fatal(err)
	}
	if got, err := dev.FinishLogin(ctx, phone, peachytest.Code); err != nil || got != name {
		t.Fatalf("FinishLogin: %q %v", got, err)
	}
	// The fake's approver lets the device in at once: the first step
	// registers and finds the box, or the second does.
	for i := 0; ; i++ {
		st, err := dev.LinkStep(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if st.State == LinkApproved {
			break
		}
		if i == 3 {
			t.Fatalf("still %s", st.State)
		}
	}
	if err := dev.Connect(ctx); err != nil {
		t.Fatal(err)
	}
	if me, err := dev.Me(); err != nil || me != actor {
		t.Fatalf("Me: %q %v", me, err)
	}
	// Connect read the store the fake wrote and registered its access key.
	if !srv.HasAccessKey(actor) {
		t.Fatal("no access key registered")
	}
	return person{dev, actor}
}

func (p person) poll(t *testing.T) []Event {
	t.Helper()
	var all []Event
	// Every warning a poll logs fails the test: a device's mailbox, its own
	// sends coming back included, should read cleanly.
	var logged bytes.Buffer
	ctx := zerolog.New(&logged).Level(zerolog.WarnLevel).WithContext(context.Background())
	for {
		events, more, err := p.Poll(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if logged.Len() > 0 {
			t.Fatalf("the poll warned: %s", logged.String())
		}
		all = append(all, events...)
		if !more {
			return all
		}
	}
}

// only is the one event of type typ in events.
func only(t *testing.T, events []Event, typ string) Event {
	t.Helper()
	var got []Event
	for _, e := range events {
		if e.Type == typ {
			got = append(got, e)
		}
	}
	if len(got) != 1 {
		t.Fatalf("%d %s events in %+v", len(got), typ, events)
	}
	return got[0]
}

func none(t *testing.T, events []Event, typ string) {
	t.Helper()
	for _, e := range events {
		if e.Type == typ {
			t.Fatalf("unexpected %s: %+v", typ, e)
		}
	}
}

func TestFakeServerDM(t *testing.T) {
	srv := peachytest.Start(t)
	ctx := context.Background()
	alice := signIn(t, srv, "+15555550100", "Alice", "alice")
	bob := signIn(t, srv, "+15555550101", "Bob", "bob")

	dm, err := alice.FoundGroupForTest(ctx, "", true, []string{bob.actor})
	if err != nil {
		t.Fatal(err)
	}
	if e := only(t, bob.poll(t), EventJoined); e.Conversation != dm {
		t.Fatalf("joined %s, not %s", e.Conversation, dm)
	}
	none(t, alice.poll(t), EventMessage) // her own commits come back and are skipped
	convs, err := bob.Conversations()
	if err != nil || len(convs) != 1 || !convs[0].DM() || convs[0].ID != dm {
		t.Fatalf("bob's chats %+v %v", convs, err)
	}

	// Text, both ways, and a reply.
	hi, err := alice.SendText(ctx, dm, "hi bob", "")
	if err != nil {
		t.Fatal(err)
	}
	m := only(t, bob.poll(t), EventMessage)
	if m.Text != "hi bob" || m.Sender != alice.actor || m.ID != hi || m.Conversation != dm {
		t.Fatalf("bob got %+v", m)
	}
	re, err := bob.SendText(ctx, dm, "hi alice", hi)
	if err != nil {
		t.Fatal(err)
	}
	m = only(t, alice.poll(t), EventMessage)
	if m.Text != "hi alice" || m.Sender != bob.actor || m.ReplyTo != hi || m.ID != re {
		t.Fatalf("alice got %+v", m)
	}

	// A reaction, taken back; an edit; a delete.
	if err := bob.React(ctx, dm, hi, "👍", false); err != nil {
		t.Fatal(err)
	}
	if r := only(t, alice.poll(t), EventReaction); r.Target != hi || r.Emoji != "👍" || r.Remove || r.Sender != bob.actor {
		t.Fatalf("reaction %+v", r)
	}
	if err := bob.React(ctx, dm, hi, "👍", true); err != nil {
		t.Fatal(err)
	}
	if r := only(t, alice.poll(t), EventReaction); !r.Remove {
		t.Fatalf("unreaction %+v", r)
	}
	if err := alice.Edit(ctx, dm, hi, 1, "hi Bob"); err != nil {
		t.Fatal(err)
	}
	if e := only(t, bob.poll(t), EventEdit); e.Target != hi || e.Text != "hi Bob" || e.Revision != 1 {
		t.Fatalf("edit %+v", e)
	}
	if err := alice.Delete(ctx, dm, hi); err != nil {
		t.Fatal(err)
	}
	if e := only(t, bob.poll(t), EventDelete); e.Target != hi || e.Sender != alice.actor {
		t.Fatalf("delete %+v", e)
	}

	// An attachment, sealed, uploaded and fetched back.
	photo := bytes.Repeat([]byte("not really a png "), 2000)
	id, _ := NewMessageID()
	if err := alice.SendMedia(ctx, id, dm, "a photo", "", []Media{{Data: photo, Mime: "image/png", FileName: "p.png", Width: 3, Height: 2}}); err != nil {
		t.Fatal(err)
	}
	m = only(t, bob.poll(t), EventMessage)
	if m.Text != "a photo" || len(m.Attachments) != 1 {
		t.Fatalf("media message %+v", m)
	}
	got, err := bob.Download(ctx, m.Attachments[0])
	if err != nil || !bytes.Equal(got, photo) {
		t.Fatalf("download: %d bytes, %v", len(got), err)
	}

	// The names peachy-go shows come from GetUsers.
	people, err := bob.People(ctx, []string{alice.actor})
	if err != nil || len(people) != 1 || people[0].Name != "Alice" || people[0].Handle != "alice" {
		t.Fatalf("people %+v %v", people, err)
	}
}

func TestFakeServerGroupMembership(t *testing.T) {
	srv := peachytest.Start(t)
	ctx := context.Background()
	alice := signIn(t, srv, "+15555550100", "Alice", "alice")
	bob := signIn(t, srv, "+15555550101", "Bob", "bob")
	carol := signIn(t, srv, "+15555550102", "Carol", "carol")

	g, err := alice.FoundGroupForTest(ctx, "Climbers", false, []string{bob.actor})
	if err != nil {
		t.Fatal(err)
	}
	only(t, bob.poll(t), EventJoined)
	convs, _ := bob.Conversations()
	if len(convs) != 1 || convs[0].Name != "Climbers" || convs[0].DM() {
		t.Fatalf("bob's chats %+v", convs)
	}

	// Carol is added: Bob sees the change, Carol joins and reads what
	// follows, and Bob's send reaches both.
	if err := alice.AddMemberForTest(ctx, g, carol.actor); err != nil {
		t.Fatal(err)
	}
	only(t, bob.poll(t), EventChanged)
	only(t, carol.poll(t), EventJoined)
	alice.poll(t)
	if _, err := bob.SendText(ctx, g, "welcome carol", ""); err != nil {
		t.Fatal(err)
	}
	if m := only(t, carol.poll(t), EventMessage); m.Text != "welcome carol" || m.Sender != bob.actor {
		t.Fatalf("carol got %+v", m)
	}
	if m := only(t, alice.poll(t), EventMessage); m.Text != "welcome carol" {
		t.Fatalf("alice got %+v", m)
	}

	// Bob is removed: the others see the change, and nothing more reaches him.
	if err := alice.RemoveMemberForTest(ctx, g, bob.actor); err != nil {
		t.Fatal(err)
	}
	only(t, carol.poll(t), EventChanged)
	bob.poll(t)
	roster, err := carol.Roster(g)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range roster {
		if r.User == bob.actor {
			t.Fatalf("bob still in carol's roster %+v", roster)
		}
	}
	if _, err := alice.SendText(ctx, g, "just us", ""); err != nil {
		t.Fatal(err)
	}
	if m := only(t, carol.poll(t), EventMessage); m.Text != "just us" {
		t.Fatalf("carol got %+v", m)
	}
	none(t, bob.poll(t), EventMessage)
	if n := srv.Waiting(srv.Devices(bob.actor)[0]); n != 0 {
		t.Fatalf("%d envelopes still wait for bob", n)
	}
}

// A mailbox that lost envelopes reports it once, the device checks its
// groups against their heads (a sweep that pages), and later messages read.
func TestFakeServerLostMailbox(t *testing.T) {
	srv := peachytest.Start(t)
	srv.SetHeadPageSize(1)
	ctx := context.Background()
	alice := signIn(t, srv, "+15555550100", "Alice", "alice")
	bob := signIn(t, srv, "+15555550101", "Bob", "bob")
	dm, err := alice.FoundGroupForTest(ctx, "", true, []string{bob.actor})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := alice.FoundGroupForTest(ctx, "Second", false, []string{bob.actor}); err != nil {
		t.Fatal(err)
	}
	bob.poll(t)

	if _, err := alice.SendText(ctx, dm, "this one expires", ""); err != nil {
		t.Fatal(err)
	}
	if n := srv.LoseMailbox(srv.Devices(bob.actor)[0]); n != 1 {
		t.Fatalf("lost %d", n)
	}
	events := bob.poll(t)
	only(t, events, EventLost)
	none(t, events, EventMessage)
	if bob.sweep == nil || len(bob.sweep.heads) != 2 {
		t.Fatalf("no full sweep after the loss: %+v", bob.sweep)
	}
	if held, _ := bob.holds(dm); !held {
		t.Fatal("bob forgot a group whose head is in step")
	}
	if _, err := alice.SendText(ctx, dm, "after the gap", ""); err != nil {
		t.Fatal(err)
	}
	if m := only(t, bob.poll(t), EventMessage); m.Text != "after the gap" {
		t.Fatalf("bob got %+v", m)
	}
}

// The fake's credentials are byte for byte the engine's test issuer's.
func TestFakeServerCredentialMatchesTestIssuer(t *testing.T) {
	seed := bytes.Repeat([]byte{7}, 32)
	issuer, err := newTestIssuer(seed)
	if err != nil {
		t.Fatal(err)
	}
	defer issuer.close()
	device := bytes.Repeat([]byte{0x11}, 32)
	now := time.Now().Unix()
	want, err := issuer.issue("actor-ada", "device-ada", device)
	if err != nil {
		t.Fatal(err)
	}
	pub := ed25519.NewKeyFromSeed(device).Public().(ed25519.PublicKey)
	// The test issuer certifies under its test account key (testissuer.go).
	accountKey := sha256.Sum256([]byte("peachy-test-account\x00actor-ada"))
	idKey, sig := peachytest.AccountCertificate(accountKey[:], pub)
	got := peachytest.MintCredential(ed25519.NewKeyFromSeed(seed), "actor-ada", "device-ada", pub, idKey, sig, now-3600, now+29*86400)
	if !bytes.Equal(got, want) {
		t.Fatalf("fake %s\nengine %s", got, want)
	}
	keys, _ := issuer.publishedKeys()
	if fake := peachytest.PublishedKeys(ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)); fake != keys {
		t.Fatalf("published keys:\nfake   %s\nengine %s", fake, keys)
	}
}

// A send that hangs (a connection that dropped without a reset) holds up
// neither receiving nor, past unaryTimeout, the sender.
func TestHungSendDoesNotBlockReceiving(t *testing.T) {
	srv := peachytest.Start(t)
	ctx := context.Background()
	alice := signIn(t, srv, "+15555550100", "Alice", "alice")
	bob := signIn(t, srv, "+15555550101", "Bob", "bob")
	dm, err := alice.FoundGroupForTest(ctx, "", true, []string{bob.actor})
	if err != nil {
		t.Fatal(err)
	}
	only(t, bob.poll(t), EventJoined)
	alice.poll(t)

	before := unaryTimeout
	unaryTimeout = 2 * time.Second
	defer func() { unaryTimeout = before }()

	release := srv.HoldSends(alice.actor)
	defer release()
	sent := make(chan error, 1)
	go func() {
		_, err := alice.SendText(ctx, dm, "stuck", "")
		sent <- err
	}()
	// Wait until her send is out of the lock and on the wire.
	time.Sleep(200 * time.Millisecond)

	// Bob's message still reaches her while her own send hangs.
	if _, err := bob.SendText(ctx, dm, "are you there?", ""); err != nil {
		t.Fatal(err)
	}
	got := make(chan []Event, 1)
	go func() { got <- alice.poll(t) }()
	select {
	case events := <-got:
		if m := only(t, events, EventMessage); m.Text != "are you there?" {
			t.Fatalf("alice got %+v", m)
		}
	case <-time.After(time.Second):
		t.Fatal("alice's poll waited behind her hung send")
	}

	// Her send gives up at the timeout rather than at the client's ten minutes.
	select {
	case err := <-sent:
		if err == nil {
			t.Fatal("a held send succeeded")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the hung send didn't time out")
	}
}
