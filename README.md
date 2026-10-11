# hostip

Publish apps running on your PC to the internet through your public IP over
HTTPS. One Rust binary, no third-party tunnel service, and it doesn't care what
stack your app is built with.

```
hostip expose 3000 8080 udp:50000-60000
```

Requirements and design: [docs/REQUIREMENTS.md](docs/REQUIREMENTS.md).

## Status

Milestones **M1** and **M1.5** are done:

- **Let's Encrypt certificate for the bare public IP**: short-lived profile,
  validated via TLS-ALPN-01 (public port 443) or HTTP-01 (public port 80),
  renewed automatically after two thirds of its ~6-day lifetime, and re-issued
  as soon as the public IP changes. A self-signed certificate is served until
  then, and whenever issuing fails (retried with backoff).
- TLS termination with hot-swapped certificates (no dropped connections)
- Per-port modes: `auto` (HTTP is reverse-proxied, anything else is piped as raw
  TCP), `https`, `tls`, `tcp`, `udp`
- HTTP/1.1 and HTTP/2, streamed request and response bodies, WebSocket and
  other protocol upgrades, `X-Forwarded-*` / `Forwarded` headers, localhost
  redirects rewritten to the public address, plain `http://` redirected to
  `https://`
- Public IP detection and change tracking, graceful shutdown

Not done yet: UPnP port mapping, authentication and rate limits, Windows
service, relay mode.

## Usage

```
hostip expose [PORTS]... [--config hostip.toml] [--public-ip IP] [--bind ADDR] [--cert-dir DIR]
              [--no-acme] [--acme-staging] [--acme-email EMAIL] [--http-listen PORT]
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

### Trusted certificate (Let's Encrypt)

Browsers only trust the IP certificate if Let's Encrypt can reach this PC on
**public port 443 or 80**. Publish your main app on 443, e.g.

```
hostip expose 3000:443 8080 udp:50000-60000
```

and forward TCP 443 (and ideally TCP 80) on the router. Using ACME means you
accept the Let's Encrypt Subscriber Agreement. Try `--acme-staging` first while
setting things up; staging certificates are not trusted by browsers but don't
count against rate limits. Certificates and the ACME account live in
`<cert-dir>/acme`.

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
public_ip = "203.0.113.7"      # optional; detected (and re-checked) automatically otherwise
ip_check_interval = "60s"

[acme]
enabled = true                 # default
staging = false
email = "you@example.com"      # optional

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

The ACME tests issue real certificates from [Pebble](https://github.com/letsencrypt/pebble),
Let's Encrypt's test CA, and are skipped unless it is installed:

```
go install github.com/letsencrypt/pebble/v2/cmd/pebble@v2.10.1
```

Logging is controlled with `RUST_LOG`, e.g. `RUST_LOG=hostip=debug`.
