# hostip

Publish apps running on your PC to the internet through your public IP over
HTTPS. One Rust binary, no third-party tunnel service, and it doesn't care what
stack your app is built with.

```
hostip expose 3000 8080 udp:50000-60000
```

Requirements and design: [docs/REQUIREMENTS.md](docs/REQUIREMENTS.md).

## Status

Milestone **M1** (in progress). Working today:

- TLS termination with an auto-generated self-signed certificate covering the
  public IP, the LAN IP and `localhost`
- Per-port modes: `auto` (HTTP is reverse-proxied, anything else is piped as raw
  TCP), `https`, `tls`, `tcp`, `udp`
- HTTP/1.1 and HTTP/2, streamed request and response bodies, WebSocket and
  other protocol upgrades, `X-Forwarded-*` / `Forwarded` headers, localhost
  redirects rewritten to the public address, plain `http://` redirected to
  `https://`
- Public IP detection, graceful shutdown

Not done yet: Let's Encrypt bare-IP certificates (browsers warn until then),
UPnP port mapping, authentication and rate limits, Windows service, relay mode.

## Usage

```
hostip expose [PORTS]... [--config hostip.toml] [--public-ip IP] [--bind ADDR] [--cert-dir DIR]
hostip ip      # show the public and LAN IP addresses
hostip cert    # show the stored certificate
```

Each port is written `[mode:]local[:public]`:

| Spec | Meaning |
|------|---------|
| `3000` | App on local port 3000, published as `https://<public-ip>:3000` |
| `3000:443` | App on local port 3000, published on public port 443 |
| `tls:5000` | Terminate TLS and pipe raw bytes to port 5000 |
| `tcp:5000` | Raw TCP, no TLS |
| `udp:50000-60000` | UDP range forwarded by the router straight to the app |

### Router port forwarding

hostip can't listen on the app's own port, so when the public port equals the
local port it listens on `local + 10000`. The startup summary prints exactly
what to forward, for example:

```
TCP 3000 -> 192.168.1.10:13000
UDP 50000-60000 -> 192.168.1.10:50000-60000
```

### Config file

```toml
[network]
public_ip = "203.0.113.7"      # optional; detected automatically otherwise

[[port]]
local = 3000
idle_timeout = "30m"

[[port]]
local = 7880
public = 7443

[[port]]
local = "50000-60000"
mode = "udp"
```

## Building

```
cargo build --release
cargo test
```

Logging is controlled with `RUST_LOG`, e.g. `RUST_LOG=hostip=debug`.
