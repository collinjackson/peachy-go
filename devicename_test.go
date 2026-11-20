package peachy

import (
	"encoding/json"
	"testing"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/collinjackson/peachy-go/pb"
)

func TestRenamedKeepsOthersAndDropsGoneRows(t *testing.T) {
	devices := []*pb.Device{
		{Id: "me"},
		{Id: "phone"},
		{Id: "phone-twin", TwinOf: "phone"},
		{Id: "old", RevokedAt: timestamppb.Now()},
	}
	mine, live := ownRows("me", devices)
	if len(mine) != 1 || mine[0] != "me" {
		t.Fatalf("mine %v", mine)
	}
	got := renamed(json.RawMessage(`{"phone":"Ada's phone","old":"Old laptop","me":"stale"}`), mine, live, "Beeper bridge")
	var m map[string]string
	if err := json.Unmarshal(got, &m); err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"phone": "Ada's phone", "me": "Beeper bridge"}
	if len(m) != len(want) || m["phone"] != want["phone"] || m["me"] != want["me"] {
		t.Fatalf("got %v", m)
	}
}

func TestOwnRowsFindsTwins(t *testing.T) {
	mine, _ := ownRows("mls", []*pb.Device{{Id: "mls", TwinOf: "plain"}, {Id: "plain"}})
	if len(mine) != 2 || mine[1] != "plain" {
		t.Fatalf("mine %v", mine)
	}
}
