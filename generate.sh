#!/bin/sh
# Regenerate what this package carries from peachy-protocol: pb/ from its
# protos and include/peachy_mls.h, its engine's C header. Run after changing
# peachy-protocol.commit. Needs protoc and protoc-gen-go
# (go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.36.12).
set -e
cd "$(dirname "$0")"
PATH="$PATH:$(go env GOPATH)/bin"
commit=$(cat peachy-protocol.commit)
protocol=${PEACHY_PROTOCOL:-target/peachy-protocol}
if [ ! -d "$protocol" ]; then
	git clone -q https://github.com/peachysocial/peachy-protocol.git "$protocol"
	git -C "$protocol" checkout -q "$commit"
elif [ "$(git -C "$protocol" rev-parse HEAD)" != "$commit" ]; then
	echo "generate.sh: $protocol isn't at $commit (peachy-protocol.commit)" >&2
	exit 1
fi

cp "$protocol/mls/cabi/include/peachy_mls.h" include/
cp "$protocol/LICENSE" include/LICENSE
rm -f pb/*.pb.go
protoc -I "$protocol/proto" \
  --go_out=. --go_opt=module=github.com/collinjackson/peachy-go \
  --go_opt=Mpeachy/v1/chat.proto=github.com/collinjackson/peachy-go/pb \
  --go_opt=Mpeachy/v1/state.proto=github.com/collinjackson/peachy-go/pb \
  peachy/v1/chat.proto peachy/v1/state.proto
cp "$protocol/LICENSE" pb/LICENSE
