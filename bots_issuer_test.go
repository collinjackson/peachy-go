//go:build testissuer

package peachy

// peachy-protocol 0.3.0 against the fake server: the two account key forms,
// the leaf self-update, and a group that seats a bot.

import (
	"context"
	"encoding/hex"
	"slices"
	"testing"
	"time"

	"github.com/collinjackson/peachy-go/peachytest"
)

// Both forms of the held account key link, read the store and message.
func TestFakeServerAccountKeyForms(t *testing.T) {
	srv := peachytest.Start(t)
	ctx := context.Background()
	two := signIn(t, srv, "+15555550100", "Alice", "alice")
	one := signInAs(t, srv, srv.AddAccountOneKey("+15555550101", "Bob", "bob"), "+15555550101", "Bob")
	for _, c := range []struct {
		p    person
		want int
	}{{two, 64}, {one, 32}} {
		key, _ := hex.DecodeString(c.p.state.AccountKeyHex)
		if len(key) != c.want {
			t.Fatalf("held a %d-byte account key, not %d", len(key), c.want)
		}
		if _, err := c.p.ReadStore(ctx); err != nil {
			t.Fatalf("the %d-byte key's store: %v", c.want, err)
		}
		if floor := c.p.state.StoreFloors[floorID(key)]; floor < 1 {
			t.Fatalf("no store floor kept for the %d-byte key", c.want)
		}
	}
	dm, err := two.FoundGroupForTest(ctx, "", true, []string{one.actor})
	if err != nil {
		t.Fatal(err)
	}
	only(t, one.poll(t), EventJoined)
	if _, err := one.SendText(ctx, dm, "hi", ""); err != nil {
		t.Fatal(err)
	}
	if m := only(t, two.poll(t), EventMessage); m.Text != "hi" {
		t.Fatalf("got %+v", m)
	}
}

// A held key of another length is refused.
func TestAccountKeyLengths(t *testing.T) {
	for n, ok := range map[int]bool{32: true, 64: true, 0: false, 31: false, 48: false, 65: false, 96: false} {
		if n == 0 {
			continue
		}
		s := &deviceState{AccountKeyHex: hex.EncodeToString(make([]byte, n))}
		if _, err := s.accountKey(); (err == nil) != ok {
			t.Errorf("a %d-byte account key: %v", n, err)
		}
	}
}

// A device whose leaf lacks 0xF1AB sends one self-update in each group it
// joins, stamped as the core says, and no more; the group goes on.
func TestFakeServerLeafUpdateOncePerGroup(t *testing.T) {
	srv := peachytest.Start(t)
	ctx := context.Background()
	alice := signIn(t, srv, "+15555550100", "Alice", "alice")
	bob := signIn(t, srv, "+15555550101", "Bob", "bob")
	// This core's leaves list 0xF1AB; Bob's read as an older core's.
	leafStaleForTest = func(string) bool { return true }
	jitter = func(time.Duration) int64 { return 0 }
	t.Cleanup(func() {
		leafStaleForTest = nil
		jitter = defaultJitter
	})

	var groups []string
	for _, name := range []string{"one", "two"} {
		g, err := alice.FoundGroupForTest(ctx, name, false, []string{bob.actor})
		if err != nil {
			t.Fatal(err)
		}
		groups = append(groups, g)
	}
	before := srv.Commits(bob.state.DeviceID)
	bob.poll(t) // joins both; the updates are due at once
	bob.poll(t)
	bob.poll(t)
	if got := srv.Commits(bob.state.DeviceID) - before; got != len(groups) {
		t.Fatalf("bob sent %d leaf updates, not one per group (%d)", got, len(groups))
	}
	if len(bob.state.LeafUpdates) != 0 {
		t.Fatalf("still owed: %v", bob.state.LeafUpdates)
	}
	alice.poll(t) // takes his commits
	for _, g := range groups {
		if _, err := alice.SendText(ctx, g, "still here", ""); err != nil {
			t.Fatal(err)
		}
	}
	got := 0
	for _, e := range bob.poll(t) {
		if e.Type == EventMessage && e.Text == "still here" {
			got++
		}
	}
	if got != len(groups) {
		t.Fatalf("bob read %d of %d messages after his updates", got, len(groups))
	}
}

// A first launch of this build spreads the updates it owes over twelve
// hours; a later launch sends an overdue one within ten minutes.
func TestFakeServerLeafUpdateFirstLaunch(t *testing.T) {
	srv := peachytest.Start(t)
	ctx := context.Background()
	alice := signIn(t, srv, "+15555550100", "Alice", "alice")
	bob := signIn(t, srv, "+15555550101", "Bob", "bob")
	g, err := alice.FoundGroupForTest(ctx, "one", false, []string{bob.actor})
	if err != nil {
		t.Fatal(err)
	}
	bob.poll(t)
	leafStaleForTest = func(string) bool { return true }
	t.Cleanup(func() { leafStaleForTest = nil })

	bob.mu.Lock()
	bob.state.LeafSweptAt, bob.state.LeafUpdates = 0, nil // as a 0.2.0 build left it
	now := time.Now()
	if err := bob.sweepLeaves(now); err != nil {
		t.Fatal(err)
	}
	due, owed := bob.state.LeafUpdates[g]
	if !owed || bob.state.LeafSweptAt != now.Unix() {
		bob.mu.Unlock()
		t.Fatalf("first launch owes %v (swept %d)", bob.state.LeafUpdates, bob.state.LeafSweptAt)
	}
	want := leafUpdateDue(true, bob.state.DeviceID, g, now.Unix(), 0)
	if due < want || due > want+60 {
		bob.mu.Unlock()
		t.Fatalf("due %d, want %d to %d", due, want, want+60)
	}
	// Next launch, with the time passed.
	bob.state.LeafUpdates[g] = now.Unix() - 1
	if err := bob.sweepLeaves(now); err != nil {
		t.Fatal(err)
	}
	if late := bob.state.LeafUpdates[g]; late < now.Unix() || late > now.Unix()+600 {
		bob.mu.Unlock()
		t.Fatalf("an overdue update is due at %d", late)
	}
	bob.mu.Unlock()
}

// A group that seats a bot still bridges: the bot's leaf reads as a bot's,
// its messages arrive from it, and people's messages reach it without an
// access key.
func TestFakeServerGroupWithBot(t *testing.T) {
	srv := peachytest.Start(t)
	ctx := context.Background()
	alice := signIn(t, srv, "+15555550100", "Alice", "alice")
	bob := signIn(t, srv, "+15555550101", "Bob", "bob")
	bot := signInAs(t, srv, srv.AddBot("+15555550199", "Helper", "helper_bot"), "+15555550199", "Helper")

	g, err := alice.FoundGroupForTest(ctx, "with a bot", false, []string{bob.actor})
	if err != nil {
		t.Fatal(err)
	}
	only(t, bob.poll(t), EventJoined)
	if err := alice.AddBotForTest(ctx, g, bot.actor); err != nil {
		t.Fatal(err)
	}
	only(t, bot.poll(t), EventJoined)
	only(t, bob.poll(t), EventChanged)
	alice.poll(t)

	convs, err := bob.Conversations()
	if err != nil || len(convs) != 1 || !slices.Equal(convs[0].Bots, []string{bot.actor}) || !slices.Contains(convs[0].Members, bot.actor) {
		t.Fatalf("bob's chats %+v %v", convs, err)
	}
	people, err := bob.People(ctx, []string{bot.actor})
	if err != nil || len(people) != 1 || !people[0].Bot || people[0].Name != "Helper" {
		t.Fatalf("the bot's row %+v %v", people, err)
	}

	if _, err := bot.SendText(ctx, g, "beep", ""); err != nil {
		t.Fatal(err)
	}
	for _, p := range []person{alice, bob} {
		if m := only(t, p.poll(t), EventMessage); m.Sender != bot.actor || m.Text != "beep" {
			t.Fatalf("got %+v", m)
		}
	}
	if _, err := alice.SendText(ctx, g, "thanks", ""); err != nil {
		t.Fatal(err)
	}
	for _, p := range []person{bob, bot} {
		if m := only(t, p.poll(t), EventMessage); m.Sender != alice.actor || m.Text != "thanks" {
			t.Fatalf("got %+v", m)
		}
	}
	alice.mu.Lock()
	holds := alice.holdsBotLocked([]byte(g))
	alice.mu.Unlock()
	if !holds {
		t.Fatal("alice doesn't see the bot leaf")
	}
}

// In a governed group the founding enrolls the admins' stamp set, the
// admin's adds are stamped, and a member's leaf update goes own-scope,
// unstamped: the server takes each (delivery.md "Commit stamps").
func TestFakeServerGovernedGroupStamps(t *testing.T) {
	srv := peachytest.Start(t)
	ctx := context.Background()
	alice := signIn(t, srv, "+15555550100", "Alice", "alice")
	bob := signIn(t, srv, "+15555550101", "Bob", "bob")
	g, err := alice.FoundGovernedGroupForTest(ctx, "run by alice", []string{bob.actor})
	if err != nil {
		t.Fatal(err)
	}
	handle, err := groupHandle([]byte(g))
	if err != nil {
		t.Fatal(err)
	}
	if n := srv.StampSet(handle); n != 1 {
		t.Fatalf("the handle holds %d stamp keys, not alice's one", n)
	}
	leafStaleForTest = func(group string) bool { return group == g }
	jitter = func(time.Duration) int64 { return 0 }
	t.Cleanup(func() {
		leafStaleForTest = nil
		jitter = defaultJitter
	})
	before := srv.Commits(bob.state.DeviceID)
	bob.poll(t)
	bob.poll(t)
	if got := srv.Commits(bob.state.DeviceID) - before; got != 1 {
		t.Fatalf("bob's own-scope leaf update: %d commits taken", got)
	}
	alice.poll(t)
	if _, err := alice.SendText(ctx, g, "governed", ""); err != nil {
		t.Fatal(err)
	}
	if m := only(t, bob.poll(t), EventMessage); m.Text != "governed" {
		t.Fatalf("got %+v", m)
	}
}
