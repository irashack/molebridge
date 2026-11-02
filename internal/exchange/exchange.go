// Package exchange carries the file contract between an exit and its panel
// over HTTP, for an exit and a panel that share no filesystem
// (docs/network-exchange-design.md). Neither side's readers change: the
// client, inside the exit, copies the panel's request into the exit's own
// state/panel/desired.json and sends the exit's published files; the server,
// the `exchange` role on the panel's side, writes those files where the panel
// already reads them and hands out the panel's request.
//
// The exit only makes outbound requests. Each side treats the other's bytes
// as untrusted: bounded, strict JSON objects, and each side's existing reader
// validates them again.
//
// The package offers Server (the exchange's handler), Client (one exit's
// rounds), the published file names and limits, and the link-state file.
package exchange

import (
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"time"

	"github.com/irashack/molebridge/internal/providers"
)

// Schema is the protocol's version: the GET answer's and exchange.json's.
const Schema = 1

// The headers. SentAtHeader carries the exit's wall clock, so the exchange can
// measure the offset between the two clocks.
const (
	SentAtHeader = "X-Molebridge-Sent-At"
	SHA256Header = "X-Molebridge-Sha256"
)

// The published files the client sends, in the order it sends them.
const (
	FileResult     = "result.json"
	FileRelays     = "relays.json"
	FileRelayError = "relay-error.json"
)

// Files is the published files, in the order the client sends them.
var Files = []string{FileResult, FileRelayError, FileRelays}

// The limits every reader of these files applies (configuration.md, state
// files): the status record 16 KiB, the refresh error 4 KiB, the request
// 4 KiB, and the catalog its provider's.
const (
	ResultLimit     = 16384
	RelayErrorLimit = 4096
	DesiredLimit    = 4096
	// AnswerLimit bounds the GET answer: the request, three hashes and the
	// envelope.
	AnswerLimit = 8192
	// TokenLimit bounds a token file; a token is at least MinTokenBytes long.
	TokenLimit    = 1024
	MinTokenBytes = 32
)

// FileLimit is the size limit of a published file for the provider.
func FileLimit(name, provider string) (int64, bool) {
	switch name {
	case FileResult:
		return ResultLimit, true
	case FileRelayError:
		return RelayErrorLimit, true
	case FileRelays:
		return providers.SnapshotLimit(provider), true
	}
	return 0, false
}

// Every is how often the client runs a round. UnreachableAfter is how long
// without contact the panel shows the exit as unreachable, and SkewLimit the
// clock offset past which the panel stops judging the record's times.
const (
	Every            = 2 * time.Second
	UnreachableAfter = 15 * time.Second
	SkewLimit        = 10 * time.Second
)

var exitIDRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)

// ValidExitID is PANEL_EXITS's rule for an exit id.
func ValidExitID(id string) bool { return exitIDRE.MatchString(id) }

var hashRE = regexp.MustCompile(`^[0-9a-f]{64}$`)

// Hash is the lower-case hex SHA-256 of data.
func Hash(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
