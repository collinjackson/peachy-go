package peachy

import (
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"
)

func TestRejoinWaitDoublesFromTenMinutesToSixHours(t *testing.T) {
	want := []time.Duration{10 * time.Minute, 20 * time.Minute, 40 * time.Minute, 80 * time.Minute,
		160 * time.Minute, 320 * time.Minute, 6 * time.Hour, 6 * time.Hour}
	for i, w := range want {
		if got := rejoinWait(i + 1); got != w {
			t.Errorf("after ask %d: %v, want %v", i+1, got, w)
		}
	}
	if got := rejoinWait(1000); got != rejoinMaxWait {
		t.Errorf("after many asks: %v", got)
	}
}

func TestSeatAskIsDAP(t *testing.T) {
	proof := make([]byte, 89)
	proof[0] = 1
	b, err := seatAsk("dev", "actor", proof)
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]string
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	p, err := base64.StdEncoding.DecodeString(got["p"])
	if err != nil || len(got) != 3 || got["d"] != "dev" || got["a"] != "actor" || len(p) != 89 {
		t.Fatalf("ask %s", b)
	}
}

func TestRejoinsSurviveARestart(t *testing.T) {
	dir := t.TempDir()
	if m, err := loadRejoins(dir); err != nil || len(m) != 0 {
		t.Fatalf("empty dir: %v %v", m, err)
	}
	want := map[string]*rejoin{"g1": {Recipients: []Recipient{{User: "u", Device: "d"}}, SinceMS: 1, Asks: 2, NextMS: 3}}
	if err := saveRejoins(dir, want); err != nil {
		t.Fatal(err)
	}
	got, err := loadRejoins(dir)
	if err != nil || got["g1"] == nil || got["g1"].Asks != 2 || got["g1"].Recipients[0].Device != "d" {
		t.Fatalf("got %+v %v", got, err)
	}
}
