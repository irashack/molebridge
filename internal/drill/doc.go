// Package drill holds the routing core's namespace drills: tests, behind the
// build tag drill, that run the whole stack (rtnetlink codec, mutation owner,
// event watcher, contract) against a real kernel in disposable network
// namespaces, inside a privileged container (internal/nstest/drill.sh). They
// port the native rows of tools/check-routing.sh and add the cases the Go
// design brings: a 250 ms repair assertion measured from the outside change,
// wrong-action and extra-selector rules, event loss by flood, and packet-level
// containment checked continuously while a repair runs.
package drill
