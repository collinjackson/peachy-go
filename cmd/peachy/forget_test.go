package main

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"
)

func TestForget(t *testing.T) {
	c := &cli{dir: t.TempDir(), me: "me"}
	now := time.Now().UnixMilli()
	min := int64(60 * 1000)
	lines := []kept{
		// Mine, a minute's timer, sent two minutes ago: gone.
		{Conversation: "a", ID: "mine-old", Sender: "me", Timer: 60, AtMS: now - 2*min},
		// Mine, sent just now: stays.
		{Conversation: "a", ID: "mine-new", Sender: "me", Timer: 60, AtMS: now},
		// Theirs, never shown: stays however old.
		{Conversation: "a", ID: "unseen", Sender: "bo", Timer: 60, AtMS: now - 60*min},
		// Theirs, shown two minutes ago: gone, with its reaction and seen line.
		{Conversation: "b", ID: "seen", Sender: "bo", Timer: 60, AtMS: now - 10*min},
		{Conversation: "b", Type: keptSeen, Sender: "me", Target: "seen", AtMS: now - 2*min},
		{Conversation: "b", Type: "reaction", Sender: "me", Target: "seen", Emoji: "👍", AtMS: now - 2*min},
		// Theirs, covered by another device's read note two minutes ago: gone,
		// and the one after the note stays.
		{Conversation: "c", ID: "noted", Sender: "bo", Timer: 60, AtMS: now - 10*min},
		{Conversation: "c", ID: "after", Sender: "bo", Timer: 60, AtMS: now - 9*min},
		{Conversation: "c", Type: keptRead, Sender: "me", Target: "noted", AtMS: now - 2*min},
		// No timer: stays.
		{Conversation: "c", ID: "plain", Sender: "bo", AtMS: now - 60*min},
	}
	for _, k := range lines {
		if err := c.keepLine(k); err != nil {
			t.Fatal(err)
		}
	}
	if err := c.forget(); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(filepath.Join(c.dir, logFile))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var left []string
	scan := bufio.NewScanner(f)
	for scan.Scan() {
		var k kept
		if err := json.Unmarshal(scan.Bytes(), &k); err != nil {
			t.Fatal(err)
		}
		left = append(left, k.Type+":"+k.ID+k.Target)
	}
	want := []string{":mine-new", ":unseen", ":after", ":plain"}
	if !slices.Equal(left, want) {
		t.Fatalf("left %v, want %v", left, want)
	}
}
