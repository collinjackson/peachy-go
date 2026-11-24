package peachy

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// The leaf self-update's cases in peachy-protocol's
// mls/fixtures/formats/bot-addressing.json: which triggers send one, and
// when it is due.
func TestLeafUpdateFixture(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(protocolDir(), "mls/fixtures/formats/bot-addressing.json"))
	if err != nil {
		t.Skip("no peachy-protocol checkout (build.sh clones one, or set PEACHY_PROTOCOL)")
	}
	var f struct {
		Spread int64 `json:"firstLaunchSpreadSeconds"`
		Jitter int64 `json:"leafUpdateJitterSeconds"`
		Late   int64 `json:"leafUpdateLateSeconds"`
		Cases  []struct {
			ID           string          `json:"id"`
			Call         string          `json:"call"`
			Trigger      string          `json:"trigger"`
			OwnLeafAware bool            `json:"ownLeafAware"`
			DeviceID     string          `json:"deviceId"`
			GroupID      string          `json:"groupId"`
			SweptAt      int64           `json:"sweptAt"`
			SeenAt       int64           `json:"seenAt"`
			Expect       json.RawMessage `json:"expect"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	if f.Spread != int64(firstLaunchSpread.Seconds()) || f.Jitter != int64(leafUpdateJitter.Seconds()) || f.Late != int64(leafUpdateLate.Seconds()) {
		t.Fatalf("the fixture's spread, jitter and late window are %d, %d, %d", f.Spread, f.Jitter, f.Late)
	}
	n := 0
	for _, c := range f.Cases {
		switch c.Call {
		case "leafUpdate":
			var want struct {
				SelfUpdate bool `json:"selfUpdate"`
			}
			if err := json.Unmarshal(c.Expect, &want); err != nil {
				t.Fatal(err)
			}
			// This device sends one on a join (handle, WELCOME) and on a
			// first launch (sweepLeaves), only for a leaf that lacks 0xF1AB;
			// nothing else schedules one. Bot-key writes it never defers, as
			// it writes none, so there is no re-check.
			got := !c.OwnLeafAware && (c.Trigger == "firstLaunch" || c.Trigger == "join")
			if got != want.SelfUpdate {
				t.Errorf("%s: selfUpdate %v", c.ID, got)
			}
			n++
		case "leafUpdateDue":
			var want int64
			if err := json.Unmarshal(c.Expect, &want); err != nil {
				t.Fatal(err)
			}
			if got := leafUpdateDue(c.Trigger == "firstLaunch", c.DeviceID, c.GroupID, c.SweptAt, c.SeenAt); got != want {
				t.Errorf("%s: due %d, want %d", c.ID, got, want)
			}
			n++
		}
	}
	if n == 0 {
		t.Fatal("no leafUpdate cases")
	}
}

// Recovery steps 3 and 4 are retired; 13 holds the copy, never forgets it.
func TestRecoveryActions(t *testing.T) {
	for step, want := range map[int]int{
		recoveryRejoinForked: actRejoin, recoveryRejoinStuck: actRejoin, recoveryRejoinLost: actRejoin,
		recoverySettleFirst: actWait, recoveryBackoff: actWait, recoveryHold: actHold,
		0: actNothing, 1: actNothing, 2: actNothing, 3: actNothing, 4: actNothing, 9: actNothing,
	} {
		if got := recoveryAction(step); got != want {
			t.Errorf("step %d: %d, want %d", step, got, want)
		}
	}
}

func TestParseStamp(t *testing.T) {
	s, err := parseStamp([]byte(`{"stamp":null,"set":null,"own":false}`))
	if err != nil || s.stamp != nil || s.set != nil || s.own {
		t.Fatalf("%+v %v", s, err)
	}
	if s, err = parseStamp([]byte(`{"stamp":null,"set":null,"own":true}`)); err != nil || !s.own {
		t.Fatalf("%+v %v", s, err)
	}
	if _, err = parseStamp([]byte(`{"stamp":"AAAA","set":null,"own":false}`)); err == nil {
		t.Fatal("took a short stamp")
	}
}
