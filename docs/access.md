# Panel access

The panel has no login. Anyone who can reach it can change the exit for
everyone who uses it. `compose.yaml` publishes it on the host's loopback
address only (`127.0.0.1:8095`). Keep it that way, and reach it in one of the
two ways below.

The panel also refuses any request whose `Host` header isn't loopback or a
name listed in `PANEL_PUBLIC_HOSTS`, answering 421. That stops a malicious web
page from reaching the loopback port through DNS rebinding. (`/healthz`
answers before this check, so a local health probe works under any name.)
Switching needs a CSRF token tied to a cookie, and, when the browser sends an
`Origin` header, that header must name a listed host too.

## SSH forwarding

This needs nothing but SSH access to the host: no domain, certificate or
proxy. It's the simplest option for a laptop. It doesn't suit phones.

1. Start the panel on the host (`docker compose up -d control-panel`).
2. On your laptop:

   ```sh
   ssh -N -o ExitOnForwardFailure=yes -L 127.0.0.1:8095:127.0.0.1:8095 user@example.net
   ```

3. Open <http://127.0.0.1:8095> while that runs. Loopback names are always
   accepted, so `PANEL_PUBLIC_HOSTS` can stay empty.

Don't change the publish to `0.0.0.0` to make this work; the forward
connects to the host's loopback.

## An authenticating reverse proxy

For phones, a dashboard or several people, put a reverse proxy in front that
authenticates every request before it reaches the panel. That includes
`/api/*`, `/select`, `/static/*` and the manifest. Identity-aware proxies
work (oauth2-proxy, Authelia, Authentik, Pomerium), and so does NetBird's own
reverse proxy restricted to the right access groups, which is what the tested
setup uses.

A minimal example with [Caddy](https://caddyserver.com) running on the same
host, using a password prompt:

```caddyfile
exit.example.net {
	basic_auth {
		alice <output of caddy hash-password>
	}
	reverse_proxy 127.0.0.1:8095
}
```

Replace the placeholder with the output of `caddy hash-password`, and set
`PANEL_PUBLIC_HOSTS=exit.example.net` in `.env`. Basic authentication works,
but phones and dashboard frames handle it poorly; a proxy with a proper sign-in
page is more comfortable. Whichever you use, prefer one that is reachable only
over NetBird, not from the whole Internet. (Caddy's automatic certificates
need either a public name or its DNS challenge; `tls internal` is an option
for a private-only name.)

Two details trip people up:

- **The proxy must reach the host's loopback.** The simplest arrangement is a
  proxy running on the host itself. A proxy in a container has its own
  loopback, and on Linux Docker it can't reach a port published only on the
  host's `127.0.0.1`. Rootless Podman's `host.containers.internal` does reach
  it on the tested host, and OrbStack's `host.docker.internal` did too. If
  your proxy sends that upstream name as the `Host`, add it (with the port)
  to `PANEL_PUBLIC_HOSTS`.
- **Cookies.** For the dashboard frame and a phone's home-screen app, the
  proxy's session cookie has to reach the panel's hostname. See
  [Switchyard](switchyard.md#embedding-in-a-dashboard).

Set `PANEL_FRAME_ANCESTORS` only if an authenticated dashboard embeds the
panel. Never expose the panel through a public tunnel or port forward without
authentication in front.
