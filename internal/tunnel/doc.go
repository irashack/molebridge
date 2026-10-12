// Package tunnel brings the native exit's WireGuard tunnel up and down
// without wg-quick, and removes the interfaces a stopping exit owns.
//
// Up does what `wg-quick up` did for the config tools/prepare-tunnel-config.py
// writes (Table = off, so no routing of its own): create a link of kind
// wireguard through rtnetlink, set the private key and (Mullvad) the peer
// through WireGuard's generic netlink, assign the addresses, set the MTU and
// bring the link up, then do what the PostUp hook did, the default route in
// the exit table, as route operations rather than a command. Nothing is
// executed and no shell is involved. It makes one attempt; the caller drives
// retries on the curve in Delay (2 seconds doubling to 60).
//
// Everything here runs as an operation of the mutation owner
// (internal/mutator), so the repairer never undoes a step in progress.
// The implementation is Linux only.
package tunnel
