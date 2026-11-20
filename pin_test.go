package peachy

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The production keys this build of the engine carries survive pinning, and
// a key the server adds is dropped.
func TestServerKeysPinned(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(protocolDir(), "mls/core/pinned-server-keys.json"))
	if err != nil {
		t.Skip("no peachy-protocol checkout (build.sh clones one, or set PEACHY_PROTOCOL)")
	}
	var file struct {
		Servers map[string][]struct {
			Kid       string `json:"kid"`
			PublicKey string `json:"publicKey"`
		} `json:"servers"`
	}
	if err := json.Unmarshal(raw, &file); err != nil {
		t.Fatal(err)
	}
	var keys []string
	for i, k := range file.Servers["production"] {
		keys = append(keys, fmt.Sprintf(`{"kid":%q,"publicKey":%q,"current":%v,"use":"device"}`, k.Kid, k.PublicKey, i == 0))
	}
	if len(keys) == 0 {
		t.Fatal("no production keys carried")
	}
	added := `{"kid":"deadbeef","publicKey":"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=","current":false,"use":"device"}`
	published := `{"enabled":true,"keys":[` + strings.Join(append(keys, added), ",") + `]}`
	pinned, err := serverKeysPinned(published, "production")
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range file.Servers["production"] {
		if !strings.Contains(pinned, k.Kid) {
			t.Errorf("carried key %s dropped: %s", k.Kid, pinned)
		}
	}
	if strings.Contains(pinned, "deadbeef") {
		t.Errorf("a key the server added survived: %s", pinned)
	}
	if report, _ := serverKeyPinReport(published, "production"); report == "" {
		t.Error("the added key should be reported")
	}
}
