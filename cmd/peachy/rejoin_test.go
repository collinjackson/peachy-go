package main

import "testing"

func TestParseRecipients(t *testing.T) {
	got, err := parseRecipients(" u1:d1, u2:d2 ,")
	if err != nil || len(got) != 2 || got[0].User != "u1" || got[1].Device != "d2" {
		t.Fatalf("got %+v %v", got, err)
	}
	for _, bad := range []string{"u1", "u1:", ":d1"} {
		if _, err := parseRecipients(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	if got, err := parseRecipients(""); err != nil || got != nil {
		t.Fatalf("empty: %+v %v", got, err)
	}
}
