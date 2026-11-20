# peachy-go

A Go client for [Peachy](https://pchy.app), with a command-line tool and a
daemon that runs chat bots.

- **The library** (package `peachy`, at the repository root): sign in, link
  as one of your devices, receive and send messages, photos, replies,
  reactions, edits and deletes, and read your Peachy settings. The
  encryption is Peachy's own MLS engine, called through its C interface.
- **`peachy`**, the command line: [Peachy in a terminal](docs/cli.md).
- **`peachy daemon`**: answers the same HTTP API as signal-cli-rest-api, so
  bots written for Signal that way, [Com
  Tower](https://github.com/collinjackson/com-tower) for one, run on Peachy.
  See [Bots on Peachy](docs/bots.md).

[mautrix-peachy](https://github.com/collinjackson/mautrix-peachy), the Peachy
bridge for Beeper and Matrix, is built on this library.

This is an independent open-source project, not part of the Peachy product.

## Build

You need Rust and Go 1.26.

```
./build.sh
```

builds Peachy's MLS engine and `./peachy`. The engine comes from
[peachy-protocol](https://github.com/peachysocial/peachy-protocol) (MIT) at
the commit in `peachy-protocol.commit`: `build.sh` clones it into
`target/peachy-protocol`, or uses `$PEACHY_PROTOCOL`. This package links the
engine as `-lpeachy_mls_cabi`, so other builds against it, and the tests, set
the `CGO_LDFLAGS` that `build.sh` prints:

```
CGO_LDFLAGS=-L$PWD/target/lib go test ./...
```

`pb/` (generated from peachy-protocol's protos) and `include/peachy_mls.h`
(the engine's C header) are peachy-protocol's, under its MIT license
(`pb/LICENSE`, `include/LICENSE`). `./generate.sh` remakes them after a change
to `peachy-protocol.commit`.

## Use the library

```go
dev, err := peachy.Open("https://api.pchy.app", dataDir, "My tool")
// First time: dev.StartLogin, dev.FinishLogin, then dev.LinkStep until
// approved on your phone. After that, on every start:
err = dev.Connect(ctx)
events, more, err := dev.Poll(ctx)
id, err := dev.SendText(ctx, conversationID, "hello", "")
```

`cmd/peachy` is a complete example.

## License

[MPL-2.0](LICENSE). You can use this library in any program, open or closed;
changes to its own files are shared under the same license.

`pb/` and `include/` are generated from peachy-protocol and stay under its
MIT license; the MLS engine itself isn't in this repository.
