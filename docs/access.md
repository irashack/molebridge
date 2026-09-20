# Authenticated panel access

The panel has no login. Anyone who can reach it can change the exit for all
users. Keep the Compose publish on `127.0.0.1`.

## Complete example: SSH forwarding

This option needs only an SSH account on the Docker host, with key-based login
already working. It requires no domain, certificate or reverse proxy.

1. Finish [setup](setup.md) on the Docker host and start the panel.
2. From your laptop, open an authenticated tunnel, substituting your own SSH
   user/host and the configured panel port:

   ```sh
   ssh -N -o ExitOnForwardFailure=yes -L 127.0.0.1:8095:127.0.0.1:8095 user@example.net
   ```

3. Leave that command running and open `http://127.0.0.1:8095` on the laptop.
   The panel accepts its own request host; `PANEL_PUBLIC_HOSTS` can be empty for
   this access method.
4. Close the SSH connection when finished. The Docker host's panel port remains
   available only through loopback. Do not change the publish to `0.0.0.0` to
   make the tunnel work.

The SSH server authenticates access; the panel's CSRF token protects switching
from cross-site form submissions. SSH forwarding is primarily a desktop access
path, not the phone home-screen installation path.

## Phones and dashboards

Use an existing HTTPS reverse proxy that authenticates every panel path,
including `/api/*`, `/select`, and static/manifest routes. An overlay access
policy is another option if it restricts access to exactly the people who may
switch. The host/container topology must allow the proxy to reach the loopback
publish; a proxy's own container loopback is not the Docker host's loopback.

Set `PANEL_PUBLIC_HOSTS` to the public hostname and optional port, and configure
`PANEL_FRAME_ANCESTORS` only for an authenticated dashboard. Keep the proxy's
session cookie valid for iframe and home-screen use; see [operations](operations.md).
Do not expose an unauthenticated panel through a public tunnel or port forward.
