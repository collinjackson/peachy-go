#!/bin/sh
# Build Peachy's MLS engine and the peachy command. Needs Rust and Go.
#
# The engine comes from peachy-protocol
# (https://github.com/peachysocial/peachy-protocol, MIT), at the commit in
# peachy-protocol.commit: $PEACHY_PROTOCOL when set, else a clone this makes
# in target/peachy-protocol. The Go package links it as -lpeachy_mls_cabi, so
# anything else that builds against this package (go build, go test) needs
#
#   CGO_LDFLAGS=-L$PWD/target/lib
#
# which this script prints. PEACHY_FEATURES adds cargo features (the tests'
# peachy-mls-cabi/test-issuer). On macOS the linker warns that some Rust
# objects were built for a newer macOS than Go links for; that's harmless.
set -e
cd "$(dirname "$0")"
commit=$(cat peachy-protocol.commit)
protocol=${PEACHY_PROTOCOL:-target/peachy-protocol}

if [ ! -d "$protocol" ]; then
	git clone -q https://github.com/peachysocial/peachy-protocol.git "$protocol"
	git -C "$protocol" checkout -q "$commit"
fi
if [ "$(git -C "$protocol" rev-parse HEAD 2>/dev/null)" != "$commit" ]; then
	echo "build.sh: $protocol isn't at $commit (peachy-protocol.commit)" >&2
fi
if ! cmp -s include/peachy_mls.h "$protocol/mls/cabi/include/peachy_mls.h"; then
	echo "build.sh: include/peachy_mls.h differs from $protocol's; run ./generate.sh" >&2
	exit 1
fi

(cd "$protocol/mls" && cargo build --release -p peachy-mls-cabi ${PEACHY_FEATURES:+--features "$PEACHY_FEATURES"})
# Only the static library in the -L directory: -l would otherwise take the
# .dylib beside it, which doesn't export the SQLCipher the store key needs.
mkdir -p target/lib
ln -sf "$(cd "$protocol/mls/target/release" && pwd)/libpeachy_mls_cabi.a" target/lib/
lib="$(pwd)/target/lib"
CGO_LDFLAGS="-L$lib ${CGO_LDFLAGS:-}" go build -o peachy ./cmd/peachy
echo "built ./peachy; for go build and go test: CGO_LDFLAGS=-L$lib"
