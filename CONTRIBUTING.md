# Contributing

Issues and pull requests are welcome. Molebridge has one maintainer, so
reviews happen when there's time. For a suspected vulnerability, use the
private route in [SECURITY.md](SECURITY.md), not an issue.

## Ground rules

The project's rules are in [AGENTS.md](AGENTS.md); they apply to people as
much as to coding agents. Two matter most for a pull request. First, changes
to routing, the tunnel config, Compose networking or the exit need the
live checks in [verification](docs/verification.md), because CI can't tell
you that a real client fails closed. Second, update the docs your change
affects in the same pull request.

## Where things are

Molebridge is one Go module, `github.com/irashack/molebridge`, Go 1.27 (the
Dockerfile and CI build with Go 1.27.2). It uses the standard library
wherever it reaches, plus the short list in `vendor/modules.txt` (netlink,
WireGuard control, nftables), which is vendored and committed. A new module needs
a reason in the commit message and an update of `THIRD_PARTY.md` (see below).

- `cmd/molebridge/`: the one binary. The first argument is the role (`exit`,
  `panel`, `health`, `status`, `check-config`, `prepare-config`, `nordvpn-key`,
  `gluetun-auth`, `gluetun-post-rules`, `fix-blacklist`); each has a `role_*.go` file.
- `internal/exit/`: the exit container's process: the supervisor, the worker, the
  lease, the NetBird child, status publication and the stop sequence.
- `internal/contract/`: the routing contract: expected rules and routes, the diff and
  its ordered repair, the status judgments, the post-rules. `internal/rtnl/` speaks
  rtnetlink (a lossless rule decoder and the multicast groups), `internal/mutator/` is
  the single owner of every kernel change, `internal/watch/` the event loop,
  `internal/tunnel/` the native WireGuard bring-up and the cleanup, `internal/nft/`
  reads NetBird's nftables objects, and `internal/policy/` is the model of what the
  kernel's policy routing does with protected traffic, which the mutation owner asks
  before every deletion. `internal/proc/` starts and reaps child processes for PID 1.
- `internal/applier/`: the provider pipeline: the admission pipeline, the egress
  checks, the status record, and one provider per family (Mullvad, PIA, NordVPN,
  gluetun). `internal/attempt/` is the persisted attempt
  (`state/applier/attempt.json`), `internal/verdict/` judges a status record for every
  reader, `internal/providers/` is the provider registry and the catalog parsers,
  `internal/egress/` the tunnel-tier checks, `internal/countries/` country names to codes.
- `internal/nbprofile/` checks NetBird's settings and stored profile and holds the
  `fix-blacklist` repair; `internal/tunnelconf/` validates the tunnel config;
  `internal/gluetunauth/` is gluetun's role file and API key.
- `internal/panel/` is Switchyard, with `internal/panel/oidc/` for sign-in. Its
  front end is `panel/static/`, dependency-free; `panel/js-tests/` tests
  `panel/static/panel.js` with Node's own runner against the panel's answers for the
  fixtures in `panel/fixtures/`.
- `internal/tools/` holds the setup tools' code; `internal/state/`, `internal/validate/`,
  `internal/jsonfile/`, `internal/netx/` and `internal/bootclock/` are the shared
  strict I/O, validation, HTTP client and boot clock.
- `internal/drill/` and `internal/nstest/` are the namespace drills (below).
- `routing/gluetun-preflight` is the one runtime shell script: it runs inside gluetun's
  container. `tools/` holds the release and image scripts (`make-bundle.sh`,
  `check-bundle.sh`, `check-image.sh`, `check-compose.sh`, `release-notes.sh` and the
  acceptance tooling) and `tools/fixtures/` the data tests share.
- `compose.yaml`, `compose.gluetun.yaml` and `compose.sidecar.yaml`: the supported
  Compose forms, with `.env.example`, `.env.gluetun.example` and `.env.sidecar.example`.

Test files ported from the 0.7 Python suite usually name their Python file in a header
comment, and their test names stay close to the Python ones, so the two can be compared.
The supervisor, the lease, the mutation owner and the drills are new in Go and have no
Python counterpart. Tests reuse `tools/fixtures/` and `panel/fixtures/` by relative path.

## Checks

```sh
gofmt -l $(git ls-files '*.go' ':(exclude)vendor')    # prints nothing
go vet ./...
go run honnef.co/go/tools/cmd/staticcheck@v0.8.2 ./...
go run golang.org/x/vuln/cmd/govulncheck@v1.9.0 ./...
go test -count=1 ./...
node --test panel/js-tests/*.test.js

sh -n routing/gluetun-preflight && shellcheck -x -S warning routing/gluetun-preflight
sh tools/test-gluetun-preflight.sh
docker compose --env-file .env.example -f compose.yaml config --quiet
for provider in mullvad pia nordvpn; do
  PROVIDER=$provider EXIT_IF=$provider docker compose --env-file .env.example -f compose.yaml config --quiet
done
docker compose --env-file .env.gluetun.example -f compose.gluetun.yaml config --quiet
docker compose --env-file .env.sidecar.example -f compose.sidecar.yaml config --quiet
sh tools/check-compose.sh
sh tools/check-doc-links.sh
```

The panel script tests need Node 18 or later and nothing from npm. They run
`go test -run TestWritePayloads ./internal/panel` for the panel's own answers, so they need
the Go toolchain too.

The release tooling has its own scripts and tests, which CI runs: `tools/test-make-bundle.sh`,
`tools/test-check-bundle.sh`, `tools/test-gen-third-party.sh`, `tools/test-release-notes.sh`,
`tools/test-verify-acceptance.sh` and `tools/test-make-acceptance-predicate.sh`, plus
`sh tools/check-reproducible.sh` (two builds of the binary for amd64 and arm64 must hash equal;
the image is not claimed reproducible) and `sh tools/gen-third-party.sh --check`. After any
change to `vendor/`, run `sh tools/gen-third-party.sh` and commit `THIRD_PARTY.md`.

### The namespace drills

Anything that touches the routing, the tunnel, the mutation owner or the lease needs the
drills, which run the whole stack against a real kernel in disposable network namespaces.
They are Go tests behind the build tag `drill`:

```sh
sh internal/nstest/drill.sh                 # all of ./internal/..., in a privileged container
sh internal/nstest/drill.sh -count=1 ./internal/drill   # arguments are go test's
```

The script builds `molebridge-drill:local` (the Go toolchain image plus iproute2, nftables and
iputils) and runs `go test -tags drill` in it with `--privileged`. Namespaces are created inside
that container only. It needs Docker, and never touches your host's network. On a Linux machine
you can run the same tests directly as root with `go test -tags drill -count=1 ./internal/...`;
CI does that on the runner, which is a disposable VM. The drills cover every single-fault row of
the drift table with a 250 ms repair assertion, both address families, wrong-action and
extra-selector rules, event loss by flood, the PIA address transaction, a hung and a crashed
worker with the namespace held by another container, and the stop budget
([architecture](docs/architecture.md#drift-and-repair)).

Tests never touch the network beyond loopback: they use `httptest`, fakes and fixtures, and never
read anything under `~/.config`, `~/.ssh`, a keychain or a secret store. A test that adds a new side
effect (a file, a process, a socket) mocks it first.

### Running the panel by hand

The panel needs only a state directory. With the self-check off (it is for exactly this; never on
a deployed panel), a fake exit's records in `state/applier` and a scratch port:

```sh
MOLEBRIDGE_PANEL_ISOLATION_CHECK=off MOLEBRIDGE_PANEL_LISTEN=127.0.0.1:8099 \
  STATE_DIR=/tmp/panel-state PROVIDER=mullvad go run ./cmd/molebridge panel
```

`panel/fixtures/` has the records the tests use. Set `PANEL_THEME=light` or `PANEL_STYLE=dashboard`
to see the other looks.

## Building the image

The release image is built and signed by GitHub Actions on a tag; you don't need to build it to run
Molebridge. To build the same image from a checkout:

```sh
docker build --tag molebridge:dev --file Dockerfile .
sh tools/check-image.sh molebridge:dev linux/amd64    # what the image contains
```

It cross-compiles the binary with `CGO_ENABLED=0 GOFLAGS=-mod=vendor` (so the `vendor/` directory is
the dependency list) and adds the NetBird client from the release archive pinned in the `Dockerfile`,
checked against the SHA-256 committed there. To run your build through Compose, give it a local name in
a `compose.override.yaml` beside the Compose file, because the Compose files pin the release by digest
and an image can't be built under a digest:

```yaml
services:
  exit: {image: molebridge:dev}
  switchyard: {image: molebridge:dev}
```

List only services your Compose file has: `compose.gluetun.yaml` has no
`switchyard`, so leave that line out there, or Compose adds a stray service.
Then `docker compose build exit` and `docker compose up -d` run your build. Compose reads
`compose.override.yaml` by itself only when `COMPOSE_FILE` is unset; with a gluetun form, add it, as in
`COMPOSE_FILE=compose.gluetun.yaml:compose.override.yaml`. Updating NetBird means changing `NETBIRD_VERSION` and both `NETBIRD_SHA256_*` hashes together, from
`netbird_<version>_checksums.txt`, and reading the checks in `internal/nbprofile` against the new release's
source. The base images are pinned by tag and index digest; update them deliberately and run the
[verification](docs/verification.md) afterward.
