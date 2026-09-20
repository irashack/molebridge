<p align="center">
  <img src="docs/assets/molebridge-banner.svg" alt="Molebridge — Stay on NetBird. Exit through Mullvad." width="1000">
</p>

<p align="center">
  <strong>A small, self-hosted Mullvad exit for your NetBird mesh.</strong><br>
  One Compose project. One Mullvad device. A server picker you can use from your phone.
</p>

<p align="center">
  <a href="docs/setup.md"><strong>Get started</strong></a> ·
  <a href="docs/access.md">Panel access</a> ·
  <a href="docs/architecture.md">Architecture</a> ·
  <a href="https://github.com/irashack/molebridge/actions/workflows/ci.yml">CI</a>
</p>

---

## Your mesh, with a Mullvad exit

On a phone, turning on the Mullvad VPN usually means disconnecting NetBird.
Molebridge moves the Mullvad tunnel to a machine in your homelab. Your devices
stay on NetBird and select that machine as their exit node.

Pick a Mullvad server in the web panel, and every device using the exit follows.
No client reconfiguration when you switch; existing connections through the
exit will drop.

| | What you get |
| :--- | :--- |
| **Stay connected** | Keep NetBird active while sending exit traffic through Mullvad. |
| **Pick your exit** | Browse countries and cities, compare measured latency, and switch servers. |
| **Make it fit** | Embed the panel in a dashboard or install it as a home-screen app. |
| **Keep it small** | Four containers, a Python standard-library panel, and dependency-free front-end code. |
| **See what is happening** | Freshness-aware status, verified egress, and host-side doctor and recovery commands. |

## The traffic path

```mermaid
flowchart LR
    device("Your devices<br/>NetBird connected")
    mullvad("Mullvad server<br/>Internet egress")

    subgraph host["Your homelab · shared network namespace"]
        peer("NetBird<br/>exit peer")
        route("Policy<br/>routing")
        tunnel("WireGuard<br/>tunnel")
        blocked("Tunnel unavailable<br/>Unreachable")
        peer --> route
        route --> tunnel
        route -.-> blocked
    end

    device --> peer
    tunnel --> mullvad

    classDef endpoint fill:#24273a,stroke:#8aadf4,color:#cad3f5,stroke-width:2px
    classDef routing fill:#24273a,stroke:#a6da95,color:#cad3f5,stroke-width:2px
    classDef stopped fill:#24273a,stroke:#ed8796,color:#f4dbd6,stroke-width:2px
    class device,peer,mullvad endpoint
    class route,tunnel routing
    class blocked stopped
    style host fill:#1e2030,stroke:#494d64,color:#cad3f5
    linkStyle default stroke:#8087a2,stroke-width:2px
```

The exit's own NetBird and Mullvad control connections use its normal network
path. Forwarded client traffic uses a dedicated tunnel table, with unreachable
fallback routes and a terminal routing rule if the table or its lookup disappears.

**The panel stays outside that namespace.** It has no capabilities and writes
only a desired server request. The trusted applier validates the request against
its own Mullvad relay catalogue, updates the live peer, and publishes status for
the panel to read. See the [full architecture](docs/architecture.md) for the
routing and privilege boundaries.

## Bring your own homelab

You need a Docker host with Compose, a NetBird account, a Mullvad account with
one free device slot, and an authenticated way to reach the panel.

1. **[Check the prerequisites](docs/prerequisites.md)** — accounts, host support,
   and NetBird groups and routes.
2. **[Set up Molebridge](docs/setup.md)** — prepare the tunnel configuration,
   enroll the exit peer, and start the containers.
3. **[Verify the exit](docs/verification.md)** — check real client traffic, both
   address families, DNS, and failure behavior before relying on it.

> [!IMPORTANT]
> **Upgrading from Switchyard?** Keep your existing Compose project name and
> NetBird identity volume. Follow the [rename upgrade notes](docs/operations.md#upgrading-from-switchyard)
> before starting the updated stack. The repository is now named `molebridge`;
> your existing checkout directory can keep its old name.

## Know the boundary

| Boundary | What it means for your deployment |
| :--- | :--- |
| **Panel access** | The panel has **no login**. It binds to loopback by default. Use [authenticated access](docs/access.md); anyone who reaches it can change the shared exit. |
| **Routing protection** | The guards protect traffic received by the exit. They are not a device-wide kill switch when NetBird disconnects or the exit is deselected. |
| **Client privacy** | DNS stays under your client and NetBird account configuration. Verify DNS and IPv6 on every client; a healthy server probe cannot prove the whole client path. |
| **Trusted components** | Docker, the host, NetBird, and the applier are privileged. The applier has no config-file mount, but its namespace privileges can retrieve the live WireGuard key. |

Restrict the NetBird exit route to the devices that should use it. Distribution
groups and access policy are covered in the [NetBird prerequisites](docs/prerequisites.md#netbird).

## Project status

**Early, homelab focused, and still being verified.**

| Where | Verification so far |
| :--- | :--- |
| **Original deployment** | Daily use since 2026-09-16 on macOS / OrbStack / Apple silicon, with self-hosted NetBird 0.78 and iPhone and macOS clients. |
| **Automated checks** | Python regression tests, shell lint, Compose validation, both derived image builds, and isolated Linux IPv4/IPv6 routing failure and recovery drills. [View CI](https://github.com/irashack/molebridge/actions/workflows/ci.yml). |
| **Current hardening pass** | Full NetBird/Mullvad deployment and client checks are still pending. Use the [homelab test guide](docs/homelab-testing.md). |
| **Other deployments** | Linux Docker hosts and NetBird Cloud have not yet been verified end to end. |

There are no releases or project license yet. The repository remains private
during development.

## Find your way around

| Guide | Start here when you want to… |
| :--- | :--- |
| [Setup](docs/setup.md) | Install a fresh exit. |
| [Authenticated access](docs/access.md) | Reach the panel through SSH, an overlay policy, or an authenticating proxy. |
| [Operations](docs/operations.md) | Switch servers, embed the panel, upgrade, or recover the stack. |
| [Configuration](docs/configuration.md) | Look up a setting, secret-file location, or state-file format. |
| [Architecture](docs/architecture.md) | Understand routing, catalogue ownership, and privilege separation. |
| [Verification](docs/verification.md) | Test client privacy and deliberately break the tunnel. |
| [Homelab test guide](docs/homelab-testing.md) | Deploy and validate the current reliability/security pass. |

<details>
<summary><strong>Working on Molebridge</strong></summary>

The panel uses only the Python standard library, and its front end has no
package dependencies. Start with [AGENTS.md](AGENTS.md) and the
[architecture](docs/architecture.md).

```sh
python3 -m venv .venv
.venv/bin/pip install pytest==9.1.1 PyYAML==6.0.3
.venv/bin/python -m pytest -q panel tools

for script in routing/10-exit-routing applier/apply.sh tools/check-routing.sh; do
  sh -n "$script"
done
shellcheck -S warning routing/10-exit-routing applier/apply.sh tools/check-routing.sh
docker compose --env-file .env.example config --quiet
```

On a disposable Linux host, `sudo sh tools/check-routing.sh` exercises forwarding
and failure handling in isolated namespaces without accounts or real endpoints.
These checks complement the real NetBird/Mullvad client drills; they do not
replace them.

</details>

---

Built around [WireGuard's network namespace model](https://www.wireguard.com/netns/).
Molebridge is not affiliated with Mullvad VPN AB or NetBird. The bundled
JetBrains Mono font uses the [SIL Open Font License](panel/static/JetBrainsMono-OFL.txt).
