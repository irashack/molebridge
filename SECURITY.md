# Security policy

Molebridge is an experimental, single-maintainer project. There are no
releases yet; security fixes land on `main`.

## Reporting a vulnerability

Report privately through GitHub:
**[Report a vulnerability](https://github.com/irashack/molebridge/security/advisories/new)**
(the repository's **Security** tab, then **Report a vulnerability**).

Please do not open a public issue, discussion or pull request for a suspected
vulnerability. Include the revision, your host and container runtime, and the
smallest steps that reproduce the problem. Leave out real keys, account
numbers, hostnames, addresses and peer IDs; describe secrets by file and field
name only.

Reports are handled on a best-effort basis, with no guaranteed response time.

## In scope

Anything that breaks the properties in [the architecture](docs/architecture.md):

- forwarded client traffic leaving by any path other than the Mullvad tunnel
  (a fail-open), for either address family;
- the panel gaining privileges, running commands, or changing anything other
  than the desired server request;
- the applier acting on unvalidated relay-list, desired-state or form input;
- disclosure of the WireGuard key, the NetBird identity or other secrets.

The documented [boundaries](README.md#know-the-boundary) are not
vulnerabilities in themselves: the panel has no login of its own, the routing
guards are not a device-wide kill switch, and client DNS stays under client
and NetBird configuration.
