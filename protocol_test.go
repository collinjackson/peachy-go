package peachy

import "os"

// protocolDir is the peachy-protocol checkout whose fixtures the tests
// replay: $PEACHY_PROTOCOL, or the one build.sh clones.
func protocolDir() string {
	if d := os.Getenv("PEACHY_PROTOCOL"); d != "" {
		return d
	}
	return "target/peachy-protocol"
}
