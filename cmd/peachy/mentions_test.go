package main

import (
	"testing"

	"github.com/collinjackson/peachy-go"
)

func TestSignalMentions(t *testing.T) {
	// UTF-16 offsets: the emoji is two units.
	got := signalMentions("🍑 hi @Ben and @cleo99", []peachy.Mention{{UserID: "b", Handle: "ben"}, {UserID: "c", Handle: "cleo99"}})
	want := [][2]int{{6, 4}, {15, 7}}
	if len(got) != len(want) {
		t.Fatalf("got %v", got)
	}
	for i, m := range got {
		if m["start"] != want[i][0] || m["length"] != want[i][1] {
			t.Fatalf("mention %d at %v+%v, want %v", i, m["start"], m["length"], want[i])
		}
	}
}
