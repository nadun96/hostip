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
- Public IP detection and change tracking, graceful shutdown, a QR code of the
  share link in the console, apps that serve HTTPS themselves
- **Automatic router port mapping**: UPnP-IGD, falling back to PCP / NAT-PMP;
  leases are renewed and removed on exit. Falls back to printed manual
  forwarding rules when the router doesn't cooperate, and warns about double NAT

- **Protection**: optional login (HTTP Basic + signed session cookie, Argon2
  password hashes) with brute-force blocking, IP allow/deny lists, per-port
  connection caps, per-IP connection and rate limits, access log

- **Hand-off to other programs**: the current public IP in a file plus an
  `on_ip_change` command (e.g. restart a WebRTC media server so it announces
  the new IP), and the served certificate exported as PEM with an
  `on_cert_renew` command (e.g. reload a TURN-over-TLS server)

- **Background service**: `hostip service install` registers a Windows
  service (auto-start, restart on failure, low-privilege LocalService account,
  log in `%ProgramData%\hostip\hostip.log`) and opens the Windows Firewall
  ports; on Linux it installs a hardened systemd unit

- **Relay mode** for networks where no port can be opened (CGNAT, no router
  access): a small `hostip relay` on any server with a public IP; your PC dials
  out to it, TLS still terminates on your PC, UDP media is relayed too

Releases are built for Windows, Linux and macOS by `.github/workflows/release.yml`
when a `v*` tag is pushed. A documented example config for a polling app plus a
video conferencing server is in [`examples/hostip.toml`](examples/hostip.toml).

## Usage

```
hostip expose [PORTS]... [--config hostip.toml] [--public-ip IP] [--bind ADDR] [--cert-dir DIR]
              [--no-acme] [--acme-staging] [--acme-email EMAIL] [--http-listen PORT] [--no-upnp]
              [--auth USER:PASSWORD] [--allow CIDR]... [--max-connections N] [--access-log]
              [--max-client-rate RATE] [--cert FILE --key FILE]
              [--ip-file FILE] [--on-ip-change CMD] [--export-cert FILE --export-key FILE]
              [--on-cert-renew CMD]
hostip hash-password   # reads a password on stdin, prints an Argon2 hash for the config
hostip status  # is it running? public links, certificate expiry
hostip ip      # show the public and LAN IP addresses
hostip service install --config hostip.toml [--system]   # run in the background
hostip service uninstall
hostip relay [--listen 0.0.0.0:7000] [--token TOKEN] [--allow-ports LIST]   # on a public server
hostip check [PORTS]... [--config hostip.toml] [--relay HOST:PORT --relay-token T --relay-fingerprint F]
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

### Your own certificate

To serve a certificate you manage yourself (e.g. for a domain), pass
`--cert chain.pem --key key.pem` or set `cert`/`key` under `[tls]`. Let's
Encrypt is then skipped, and the files are re-read automatically when they
change.

### Apps that serve HTTPS themselves

If an app only listens with TLS (often with its own self-signed certificate),
set `upstream_tls = true` on its `[[port]]`; hostip then connects to it over
TLS. Its certificate is not checked, since the connection never leaves this PC.

### Changing the config while running

hostip watches the config file. When it changes and is valid, hostip restarts
its listeners with the new settings (open connections are closed; certificates
are kept and `on_ip_change` is not re-run for an unchanged IP). An invalid edit
is reported and the running setup is kept.

### Who can connect

By default anyone with the link can open an HTTP port. To require a login:

```
hostip expose 3000:443 --auth alice:s3cret
```

Browsers ask once and then get a 12-hour session cookie, so apps that send
their own `Authorization` header keep working; hostip strips its own
credentials before forwarding. After 10 wrong passwords from one address it is
blocked for 15 minutes. A port with a login only accepts HTTP.

Every port also enforces per-IP limits (256 open connections, 1200 new
connections a minute, generous because many participants can share one
address) and can be restricted with `allow`/`deny` lists or a
`max_connections` cap. `max_client_rate` (e.g. `8mbit`) caps how fast each
visitor connection can download, so one viewer cannot use up your upload.

### Video conferencing (WebRTC) servers

hostip proxies the web UI and signaling; the media server's UDP ports are
mapped on the router and go straight to it. The media server must announce the
public IP, which changes on a home connection:

```
hostip expose 7880:443 udp:50000-50100 \
  --ip-file C:\hostip\public_ip.txt \
  --on-ip-change "C:\hostip\restart-sfu.cmd" \
  --export-cert C:\hostip\turn\cert.pem --export-key C:\hostip\turn\key.pem
```

The `on_ip_change` command runs at start and after every change with
`HOSTIP_PUBLIC_IP` and `HOSTIP_PREVIOUS_IP` set; `on_cert_renew` gets
`HOSTIP_CERT_FILE` and `HOSTIP_KEY_FILE`. Commands run through `cmd /C` on
Windows and `sh -c` elsewhere.

### Running in the background

Put the ports and settings in a config file, then from an **Administrator**
prompt:

```
hostip service install --config C:\hostip\hostip.toml
```

This installs and starts the `hostip` Windows service (starts with Windows,
restarts on failure) and adds inbound Windows Firewall rules for exactly the
ports in the config. It runs as the low-privilege LocalService account;
use `--system` if your hooks need to restart other services. Certificates and
the log live in `%ProgramData%\hostip`. `hostip service uninstall` removes the
service and the firewall rules.

On Linux the same command installs a systemd unit (`journalctl -u hostip -f`
for logs).

### When no port can be opened: relay mode

If your connection is behind CGNAT, or you can't change the router, run a relay
on any machine with a public IP (a small VPS):

```
hostip relay --listen 0.0.0.0:7000
```

It prints the exact command for the home PC, including a generated token and
its certificate fingerprint:

```
hostip expose 3000:443 --relay 203.0.113.50:7000 --relay-token ... --relay-fingerprint ...
```

Your PC connects out to the relay, so nothing has to be opened at home. Visitors
use the relay's IP; TLS (including the Let's Encrypt certificate for the relay's
IP) still terminates on your PC, so the relay never sees decrypted traffic. The
relay's certificate is pinned by fingerprint and the token authenticates your
PC. UDP ports (WebRTC media) are relayed too. All traffic flows through the
relay, so it needs enough bandwidth (about 200 Mbit/s for a 100-person call).

### Router port forwarding

hostip opens the needed router ports itself via UPnP (or PCP / NAT-PMP) unless
`--no-upnp` is given. UDP ranges larger than 128 ports are not mapped
automatically; prefer a small range or a single UDP port for media servers that
support it.

hostip can't listen on the app's own port, so when the public port equals the
local port it listens on `local + 10000`. The startup summary prints exactly
what to forward if you do it by hand, for example:

```
TCP 3000 -> 192.168.1.10:13000
UDP 50000-60000 -> 192.168.1.10:50000-60000
```

### Checking that visitors can reach you

`hostip check` (same ports or `--config` as `expose`) tests the path from the
internet: a `hostip relay` you run on a public server connects back to your
public IP on every TCP port and sends a datagram to every UDP port (the first 64
of a range). Ports nothing listens on yet get a temporary listener, and a
temporary router mapping via UPnP, so it works before or while `expose` runs; a
UDP port the app already holds is reported as not tested. The relay only ever
probes the address that connected to it with the right token.

```
Seen from outside (relay 203.0.113.50:7000): public IP 198.51.100.4
Router's internet address: 100.64.12.7

  TCP 443 -> port 443            reachable
  UDP 50000 -> port 50000        NOT RECEIVED

- the router's internet address 100.64.12.7 is private or CGNAT: ... use relay mode
```

It exits with 1 when a checked port is unreachable. Without a relay it reports
the router side only (UPnP, the router's internet address, CGNAT).

### Config file

```toml
[network]
public_ip = "203.0.113.7"      # optional; detected (and re-checked) automatically otherwise
ip_check_interval = "60s"
upnp = true                    # default
ip_file = 'C:\hostip\public_ip.txt'
on_ip_change = 'C:\hostip\restart-sfu.cmd'

[tls.export]
cert = 'C:\hostip\turn\cert.pem'
key = 'C:\hostip\turn\key.pem'
on_renew = 'C:\hostip\reload-turn.cmd'

[acme]
enabled = true                 # default
staging = false
email = "you@example.com"      # optional

[[port]]
local = 3000
idle_timeout = "30m"

[server]
access_log = true

[limits]
max_connections_per_ip = 256
new_connections_per_ip_per_minute = 1200
auth_failures_before_block = 10
block_minutes = 15

[[port]]
local = 7880
public = 7443
max_connections = 150
allow = ["0.0.0.0/0"]
deny = ["198.51.100.0/24"]
auth = { user = "alice", password_hash = "$argon2id$v=19$..." }

[[port]]
local = "50000-60000"
mode = "udp"
```

## Download

Pre-built binaries for Windows, Linux (x86_64, arm64) and macOS are attached to
each [GitHub release](https://github.com/nadun96/hostip/releases), together with
`examples/hostip.toml` and SHA-256 checksums.

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

On Linux the Windows build can be checked and tested with MinGW and Wine:

```
rustup target add x86_64-pc-windows-gnu      # plus gcc-mingw-w64-x86-64 and wine64
CARGO_TARGET_X86_64_PC_WINDOWS_GNU_RUNNER=wine64 cargo test --target x86_64-pc-windows-gnu
```

Logging is controlled with `RUST_LOG`, e.g. `RUST_LOG=hostip=debug`.
