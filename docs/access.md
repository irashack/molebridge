# Panel access

By default the panel has no login. Anyone who can reach it can change the exit
for everyone who uses it. `compose.yaml` publishes it on the host's loopback
address only (`127.0.0.1:8095`). Keep it that way, and reach it in one of the
three ways below. The third, [OpenID Connect sign-in](#sign-in-with-openid-connect),
is the only one that gives the panel a login of its own.

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
authentication in front, whether that is a proxy or sign-in.

## Sign-in with OpenID Connect

The panel can sign people in itself, through an OpenID Connect identity
provider you already run or use (Pocket ID, Keycloak, Authentik and similar),
and then show each person only the exits their groups allow. It is off unless
you set `PANEL_OIDC_ISSUER`. With that unset the panel behaves as described
above: no login.

This has unit and integration tests against a fake issuer. It has not yet been
tested against a real identity provider; see
[testing](testing.md#not-yet-tested).

You still need something in front of the panel that serves it over https.
The sign-in cookies are marked `Secure`, and the panel itself listens on plain
http on the loopback port. A reverse proxy, or NetBird's reverse proxy, as
described above will do; it doesn't need to authenticate.

### Set it up

1. **Pick the address people will open**, for example
   `https://exit.example.net`, and make your proxy serve it over https,
   passing requests to `127.0.0.1:8095`. This is `PANEL_PUBLIC_URL`: an origin
   only, with no path. The panel accepts its host as it does a
   `PANEL_PUBLIC_HOSTS` entry. If your proxy rewrites the upstream `Host`,
   list that name in `PANEL_PUBLIC_HOSTS` as before.
2. **Register a client at the identity provider.**
   - Type: public, using the authorization code flow with PKCE. The panel
     then holds no secret. If your provider only offers confidential clients,
     see `PANEL_OIDC_CLIENT_SECRET_FILE` in
     [configuration](configuration.md#panel-sign-in).
   - Redirect (callback) URL: `PANEL_PUBLIC_URL` plus `/auth/callback`, for
     example `https://exit.example.net/auth/callback`.
   - Scopes: `openid profile email groups`, so the provider includes the
     person's groups.
3. **Create the groups** you will grant access to, and add people to them.
   Group names can't contain spaces, commas or `=`.
4. **Set the panel's settings** in `.env`:

   ```sh
   PANEL_OIDC_ISSUER=https://id.example.net
   PANEL_OIDC_CLIENT_ID=switchyard
   PANEL_PUBLIC_URL=https://exit.example.net
   PANEL_ADMIN_GROUPS=exit-admins
   ```

   `PANEL_OIDC_ISSUER` must match the `issuer` in the provider's discovery
   document (`<issuer>/.well-known/openid-configuration`) character for
   character, including any trailing slash. The bundled `compose.yaml` passes
   these and `PANEL_SESSION_TTL` to the panel. `PANEL_ACCESS`, for per-exit
   groups, and a client secret file are for a separate Switchyard container;
   see [several exits](switchyard.md#per-person-exits). Every setting is listed
   in [configuration](configuration.md#panel-sign-in).
5. **Give the panel container a route to the identity provider.** The panel
   makes HTTPS requests to it; see [what the panel sends to the
   provider](architecture.md#sign-in). It uses the container's own CA store, so
   a provider with a private CA needs that CA in the image.
6. Recreate the panel (`docker compose up -d control-panel`) and open
   `PANEL_PUBLIC_URL`. It should send you to the provider, and back.

The panel stops at start if the settings are incomplete or unsafe, and says
which; see [troubleshooting](troubleshooting.md#sign-in).

### Who sees what

Groups come from the ID token's `groups` claim, or the claim named by
`PANEL_OIDC_GROUPS_CLAIM`. If the ID token has none, the panel asks the
provider's userinfo endpoint instead. With Pocket ID v2.16.0 the claim is in
both when the `groups` scope is granted (checked in its source, not against a
running instance), so the ID token is used there.

- Members of a `PANEL_ADMIN_GROUPS` group see every exit.
- Members of a group named in `PANEL_ACCESS` (`group=exit`) see those exits.
- Someone whose groups grant nothing gets a "Not allowed" page and no session.

An exit someone isn't granted looks the same as one that doesn't exist: the
page, the embed and the API answer 404 `unknown exit` (a switch answers 400
`unknown exit`), and the exit tabs list only the granted ones. The
`PANEL_HOME_URL` link is shown only to admin-group members.

### Before someone signs in

With sign-in on, these need no login:

- `/healthz`, `/static/*` and `/manifest.webmanifest`;
- `/readyz` without `?exit=`, which answers for all exits so a monitor can poll
  it. `/readyz?exit=<id>` needs a session that is granted that exit, and
  otherwise answers 404 `unknown exit`.

Everything else answers a signed-out request with a redirect to sign-in (`/`),
a small "Signed out" page (`/embed`), or 401 (`/api/*` and `POST /select`).
The [endpoint table](configuration.md#panel-endpoints) has the details. The
`Host` check above still applies first.

### Sessions and lockout

A session lasts `PANEL_SESSION_TTL` seconds from sign-in (3600 by default) and
is not extended by use. After that the browser goes back to the provider,
which usually signs the person in again without asking while their session
there lasts, and the panel reads their groups again. So removing someone from
a group takes effect within `PANEL_SESSION_TTL`. To cut someone off sooner,
restart the panel: sessions are kept in its memory only, so a restart signs
everyone out. Signing out of the panel does not sign out of the provider.

### In a dashboard frame

A frame can't sign in: identity providers refuse to be framed, and the panel's
session cookie is `SameSite=Lax`, so the browser doesn't send it inside a frame
from another site. The dashboard and the panel must be on the same site, as
for a proxy's cookie ([Switchyard](switchyard.md#embedding-in-a-dashboard)).

When there is no session, `/embed` shows a small "Signed out" page whose
**Sign in** link opens the provider in a new tab. After signing in there,
reload the dashboard. When a session ends while the frame is open, the frame
notices on its next status check and shows that page.
