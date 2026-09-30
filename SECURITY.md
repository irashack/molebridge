# Security policy

Molebridge is an experimental, single-maintainer project. Security fixes land
on `main` and go into the next release; only the latest release is supported.

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

- forwarded client traffic leaving by any path other than the provider's
  tunnel (a fail-open), for either address family;
- the panel gaining privileges, running commands, or changing anything other
  than the desired server request;
- the applier acting on unvalidated server-list, provider API, desired-state
  or form input;
- disclosure of the WireGuard key, the NetBird identity, the PIA login or
  other secrets;
- with PIA port forwarding on, forwarded inbound connections reaching
  anything other than the configured overlay target.

The documented [boundaries](README.md#limits) are not vulnerabilities in
themselves: the panel has no login of its own unless you configure OpenID
Connect sign-in, the routing guards are not a device-wide kill switch, and
client DNS stays under client and NetBird configuration. Neither is a PIA port
you deliberately forward.
