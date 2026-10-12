# hostip — Requirements & Feasibility

**hostip** is a single Rust binary that publishes apps running on `localhost`
(e.g. a dev server on `127.0.0.1:3000`) to the internet through the machine's
public IP address, terminating HTTPS with an automatically generated
self-signed certificate.

```
Internet client ──HTTPS──▶ public IP:443 ──(router port-forward)──▶ hostip ──HTTP──▶ 127.0.0.1:3000
                                                                       │
                                                                       └──────────▶ 127.0.0.1:8080
```

---

## 1. Goals and non-goals

### Goals
- Expose one or more local HTTP(S)/WebSocket apps on the public IP with zero
  external services.
- Serve apps to **other people (the public), not just the owner** — so the
  default certificate must be one their browsers trust without warnings.
- Obtain and renew a browser-trusted certificate automatically (ACME / Let's
  Encrypt), with a self-signed certificate (or local CA) as the offline /
  fallback mode.
- Be safe by default: nothing is exposed unless explicitly configured, and
  optional authentication is easy to turn on.
- Single static binary for Linux, macOS and Windows.

### Non-goals (v1)
- Accepting inbound connections with **no** router mapping and **no** relay —
  physically impossible behind NAT; see the connectivity ladder in §5.3b.
- Proxying raw TCP/UDP itself (games, SSH, databases). WebRTC media goes
  **directly** from the router to the conferencing media server's UDP ports;
  hostip only *opens/maps* those ports and keeps the server's public IP
  up to date (§5.5b).
- Implementing a WebRTC media server (SFU) or TURN server from scratch —
  integrate an existing one (LiveKit, mediasoup, Jitsi, coturn).
- Being a general-purpose production load balancer.

---

## 2. Functional requirements

| ID | Requirement | Priority |
|----|-------------|----------|
| F1 | Listen for HTTPS on a configurable address/port (default `0.0.0.0:443`, fallback `8443`). | Must |
| F2 | Reverse-proxy HTTP/1.1 requests to configured local upstreams (`http://127.0.0.1:<port>`). | Must |
| F3 | **Stack-agnostic port publishing:** the user gives a list of local ports (TCP and/or UDP); each is published on the same public port number by default, with no knowledge of the app's language, framework or media server (see §5.2a). Path-prefix routing is optional. | Must |
| F4 | Self-signed fallback: on first run, generate a certificate with the public IP (and LAN IP, `localhost`) as `iPAddress`/`dNSName` SANs; persist key + cert to disk. | Must |
| F5 | Optional "local CA" mode: generate a root CA once, sign leaf certs with it, and print instructions to install the CA on client devices so browsers stop warning. Useful for testing/private use only — not a solution for public visitors. | Could |
| F6 | Allow user-supplied cert/key (PEM) instead of generating. | Should |
| F7 | Detect the public IP (via HTTPS echo services, configurable) and regenerate the leaf cert when it changes. | Should |
| F8 | WebSocket upgrade passthrough (needed by Vite/Next.js HMR, Jupyter, etc.). | Must |
| F9 | HTTP/2 to clients (ALPN `h2`, `http/1.1`). | Should |
| F10 | Optional plain-HTTP listener on port 80 that only redirects to HTTPS. | Could |
| F11 | Set `X-Forwarded-For`, `X-Forwarded-Proto`, `X-Forwarded-Host`, `Forwarded` headers; optionally rewrite `Host`. | Must |
| F12 | Router auto-config via UPnP-IGD / NAT-PMP / PCP, with automatic removal of the mapping on exit. | Must |
| F13 | Reachability self-test: report whether the public IP:port is actually reachable from outside (and detect CGNAT by comparing WAN IP vs. public IP). | Should |
| F14 | CLI: `hostip up`, `hostip add <name> <port>`, `hostip cert {show,regen,export-ca}`, `hostip status`. Quick mode: `hostip 3000`. | Must |
| F15 | Config file (TOML) with hot reload of routes. | Should |
| F16 | Graceful shutdown (drain in-flight requests on Ctrl-C/SIGTERM). | Must |
| F17 | **ACME bare-IP certificate (default mode):** obtain a browser-trusted Let's Encrypt certificate whose only identifier is the public IP (short-lived profile, ~6-day validity), via TLS-ALPN-01 on 443 or HTTP-01 on 80; renew automatically at ~⅓–½ of lifetime; hot-swap without dropping connections; fall back to self-signed on failure and say so loudly. | Must |
| F18 | Print a ready-to-share URL on start (`https://<public-ip>/…`) and a QR code for phones. | Should |
| F19 | On public-IP change: immediately request a new IP certificate for the new address and print the new share URL. | Must |
| F20 | **Streaming:** forward request and response bodies as streams with backpressure — never buffer whole bodies in memory (video files, live HLS/DASH, MJPEG, SSE, large uploads). | Must |
| F21 | **Streaming:** pass through `Range` / `206 Partial Content`, `Accept-Ranges`, `Content-Length`, chunked transfer encoding unmodified, so video seeking works. | Must |
| F22 | **Streaming:** separate timeouts — short header/handshake timeout, but no total-request timeout and a generous idle timeout (configurable per app) so long-lived streams aren't cut. | Must |
| F23 | **Streaming:** per-app limits on concurrent viewers/connections and optional per-client bandwidth cap, to protect home upload bandwidth. | Should |
| F24 | Disable response compression for media types (video/audio already compressed) and never rewrite media bodies. | Should |
| F25 | **Real-time web:** WebSocket, SSE and HTTP long-polling stay open indefinitely while active (live poll results, chat, conferencing signaling); no response buffering for `text/event-stream`. | Must |
| F26 | **WebRTC port mapping:** map the media server's UDP port range (and TCP fallback port) on the router via UPnP/NAT-PMP, renew leases, remove on exit; print exact manual port-forward rules when UPnP is unavailable. | Must |
| F35 | **Works without UPnP / port forwarding:** walk the connectivity ladder (§5.3b) automatically and pick the first path that the reachability self-test confirms; report which one is active. | Must |
| F36 | **Relay mode:** `hostip relay` runs on any machine with a public IP (small VPS); the home `hostip` dials *out* to it over one TLS/QUIC connection and the relay forwards TCP and UDP ports back through it. No inbound router config needed at home. The certificate is then issued for the **relay's** IP. | Must |
| F27 | **Public-IP propagation:** on start and on every IP change, expose the current public IP to apps — write it to a file, set it in an env file, and run a configurable `on_ip_change` hook (e.g. restart/reconfigure the SFU so it announces the new IP in ICE candidates). | Must |
| F28 | **Certificate export:** write the current IP certificate + key as PEM to a configurable path (and run `on_cert_renew` hook) so a TURN-over-TLS server can reuse the same trusted cert. | Should |
| F30 | Per-port **mode** (§5.2a): `auto` (default), `https`, `tls`, `tcp`, `udp`. | Must |
| F31 | `auto` mode: terminate TLS, peek the first decrypted bytes; if they are an HTTP request, use the HTTP proxy (forwarded headers, WebSocket/SSE, streaming); otherwise pipe raw bytes to the local port. Plain-HTTP or non-TLS clients on the port get a clear error / redirect to `https://`. | Must |
| F32 | Upstreams that already speak HTTPS/TLS locally (often with their own self-signed cert) are supported (`upstream_tls = true`); verification may be skipped only for loopback upstreams. | Should |
| F33 | In `https` mode, rewrite `Location`/`Content-Location` redirect headers that point at `http://localhost:<port>` / `127.0.0.1` to the public `https://<ip>:<port>`. Bodies are never rewritten. | Should |
| F34 | One-line CLI: `hostip expose 3000 8080 7880 udp:3478 udp:50000-60000` publishes ports with defaults, and `hostip expose --config hostip.toml` for full control. | Must |
| F29 | Self-test for conferencing: verify from outside that 443/TCP and the UDP media range are reachable (via a lightweight STUN/echo check). | Should |

## 3. Security requirements

| ID | Requirement | Priority |
|----|-------------|----------|
| S1 | Upstreams restricted to loopback / explicitly listed addresses — never an open proxy (no client-chosen targets, prevents SSRF). | Must |
| S2 | TLS 1.2+ only (rustls; TLS 1.3 preferred), no legacy ciphers. | Must |
| S3 | Per-app authentication: HTTP Basic (argon2-hashed passwords) or bearer token; on by default for quick mode with a generated password printed once. | Must |
| S4 | IP allowlist / denylist (CIDR) per app. | Should |
| S5 | Per-IP rate limiting and connection limits; header/body size limits; read/idle timeouts (slowloris protection). | Must |
| S6 | Private key files written with `0600` permissions (ACL on Windows). | Must |
| S7 | Strip hop-by-hop headers; don't leak internal upstream addresses in errors. | Must |
| S8 | Access log with client IP, status, latency; failed-auth logging. | Should |
| S9 | Least privilege: on Windows run the service as a dedicated low-privilege account / `LocalService` (binding 443 needs no admin on Windows; only firewall/service install does). On Linux use `setcap cap_net_bind_service`. | Must |

## 4. Non-functional requirements

| Area | Target |
|------|--------|
| Platforms | **Windows 10/11 x86_64 is the primary target** (owner's host); Linux and macOS secondary |
| Windows service | Run as a Windows service (`windows-service` crate) with auto-start and auto-restart; also runnable in a console for debugging |
| Windows firewall | `hostip install` adds inbound Windows Defender Firewall rules for 443/TCP, 80/TCP and the media UDP range (admin rights, one-time); `hostip uninstall` removes them |
| Windows paths/ACL | Config and certs under `%ProgramData%\hostip`; private keys readable only by SYSTEM and Administrators |
| Windows port conflicts | Detect if 443/80 are already taken (IIS/HTTP.sys, Skype, VMware, other servers) and name the owning process |
| Distribution | Single binary, no runtime deps; signed `.exe` + MSI installer or `winget`; `cargo install` and GitHub Releases for other OSes |
| Performance | ≥ 5k req/s and < 2 ms added p99 latency on a typical laptop for small responses |
| Streaming throughput | Saturate a 1 Gbit/s link with TLS on a modern CPU (the home **upload** bandwidth is the real bottleneck); time-to-first-byte overhead < 5 ms |
| Streaming memory | Bounded per-connection buffers (≤ 64–256 KiB) regardless of stream length or size |
| Memory | < 30 MB RSS idle |
| Startup | < 500 ms (excluding first-time key generation) |
| Observability | `tracing` logs, `RUST_LOG` filter, optional JSON output |
| Quality | Unit + integration tests (proxy, TLS, WebSocket), `clippy -D warnings`, CI on all three OSes |

---

## 5. Feasibility analysis

### 5.1 Technical — **Feasible, low risk**

The Rust ecosystem covers everything needed with mature crates:

| Concern | Crate(s) |
|---------|----------|
| Async runtime | `tokio` |
| HTTP server/client, proxying | `hyper` 1.x + `hyper-util` (or `axum` for the routing layer) |
| TLS | `rustls` + `tokio-rustls` (pure Rust, no OpenSSL) |
| Cert generation | `rcgen` (self-signed and CA-signed, IP SANs supported) |
| PEM loading | `rustls-pki-types` / `rustls-pemfile` |
| WebSockets | hyper upgrade + `tokio::io::copy_bidirectional` |
| Auth hashing | `argon2` |
| Rate limiting | `governor` |
| UPnP / NAT-PMP | `igd-next`, `natpmp` / `crab_nat` |
| Public IP lookup | `reqwest` (rustls) to configurable endpoints |
| Config / CLI | `serde` + `toml`, `clap` |
| File watching | `notify` |
| Logging | `tracing`, `tracing-subscriber` |

A minimal TLS reverse proxy in this stack is a few hundred lines. Comparable
projects (e.g. `rpxy`, `sozu`, Cloudflare's `pingora`) prove the approach at
production scale.

### 5.2 Routing with only an IP — **the main design constraint**

- **SNI cannot carry an IP address** (RFC 6066), and every client hitting the
  bare IP sends the same `Host`. So **hostname-based routing is impossible
  with a bare IP.** Options:
  1. **Port-based** (`https://IP:8443` → app A, `https://IP:8444` → app B).
     Most robust; each port needs its own router forward. **Recommended default.**
  2. **Path-based** (`https://IP/app-a/…`). One port, but breaks apps that
     emit absolute paths (`/static/…`, SPA routers) unless they support a
     base path. Offer it, with a warning.
  3. **Wildcard-DNS hostnames** via `sslip.io` / `nip.io`
     (`app-a.203-0-113-7.sslip.io` resolves to `203.0.113.7`). Gives real
     hostnames, SNI and `Host` routing on a single port with no DNS setup.
     **Recommended for multiple apps on one port.**

### 5.2a Stack-agnostic port model (decided)

hostip must work for **any** app on **any** given port without knowing its
stack. Therefore routing is **by port**, and the **public port mirrors the
local port** (local 3000 → `https://<public-ip>:3000`). Mirroring keeps
apps working that build URLs from their own port, and it needs no base-path
support from the app. One Let's Encrypt IP certificate covers every port.

| Mode | What hostip does | Use for |
|------|------------------|---------|
| `auto` *(default for TCP)* | TLS-terminate with the IP cert; if the decrypted stream is HTTP → HTTP reverse proxy, otherwise raw TCP pipe | Any web app, API, WebSocket/SSE signaling, and unknown TCP protocols |
| `https` | TLS-terminate + HTTP reverse proxy (forwarded headers, redirect rewrite, streaming) | Force HTTP handling |
| `tls` | TLS-terminate + raw TCP pipe | Non-HTTP TCP protocols that should be encrypted |
| `tcp` | No TLS; map router port + firewall rule, raw TCP pipe or direct forward | Apps that do their own TLS (e.g. TURN-over-TLS using the exported cert, F28) |
| `udp` | Map router port/range via UPnP + Windows Firewall rule; traffic goes **directly** to the app (no relay hop, source addresses preserved) | WebRTC media, TURN/STUN (UDP) |

**Generic limits (no stack knowledge):**
- WebRTC media servers must announce the public IP themselves. Most do via
  STUN or an "external IP" setting; hostip provides the IP through
  `public_ip.txt`, the `HOSTIP_PUBLIC_IP` environment variable and the
  `on_ip_change` hook (F27) so any stack can consume it.
- Apps that hard-code `http://localhost` into page bodies or JavaScript
  can't be fixed without rewriting bodies — out of scope; only redirect
  headers are rewritten (F33).
- Port 443 is owned by hostip (TLS-ALPN-01 challenge); an app wanting 443
  is simply published through hostip on 443. Port 80 is used for HTTP-01
  and redirects.

### 5.3 Network — **Feasible on most home connections, blocked on some**

> **Owner's environment:** hostip will run on a **home PC**, confirmed *not*
> behind CGNAT. Inbound hosting works once the router forwards **TCP 443**
> (and ideally **80**) to the PC and the OS firewall allows them. Home IPs are
> often **dynamic** — with a bare-IP certificate and bare-IP URLs, every IP
> change means a new certificate *and* a new link for viewers (F19). Ask the
> ISP whether a static IP is available.

| Situation | Outcome |
|-----------|---------|
| Router with public WAN IP, port forwarding allowed | ✅ Works (manual forward or UPnP) |
| PC directly on public IP (no router) | ✅ Works; OS firewall rule needed |
| ISP blocks inbound 80/443 | ⚠️ Use a high port (e.g. 8443) |
| Dynamic public IP | ⚠️ Works; cert regeneration (F7) + DDNS/sslip.io hostname changes |
| **CGNAT** (common on mobile/4G/5G and some fibre ISPs) | ❌ No direct inbound possible → relay mode (F36) |
| IPv6 available | ✅ Often easier (no NAT); needs firewall pinhole on router. Support `[::]` listening |

The F13 self-test should detect CGNAT (router WAN IP in `100.64.0.0/10` or
differs from the observed public IP) and tell the user clearly.

### 5.3b Connectivity ladder — working without UPnP or port forwarding

Inbound connections to a PC behind a NAT router need *something* to tell
the router where to send them. hostip tries, in order:

| # | Path | Needs | Notes |
|---|------|-------|-------|
| 1 | Already reachable (manual forward, DMZ, no NAT) | nothing | Detected by the self-test |
| 2 | UPnP-IGD | UPnP enabled on router | Automatic |
| 3 | NAT-PMP / PCP | router support | Automatic |
| 4 | IPv6 direct | ISP + router IPv6, inbound allowed | Only IPv6-capable visitors can connect; cert for the IPv6 address |
| 5 | **Relay mode (F36)** | any server with a public IP (VPS) running `hostip relay` | Works behind any NAT/CGNAT and with no router access. Traffic and certificate use the relay's IP; relay bandwidth must cover the call (~200 Mbit/s for a 100-person call) |
| 6 | Manual instructions | user configures router | Printed if all else fails |

WebRTC media itself can often traverse NAT without forwarding (ICE + STUN
hole punching), but the HTTPS page, signaling and TURN still need one of the
paths above. **There is no way to serve inbound HTTPS from behind NAT with no
router mapping and no relay**; relay mode is the "works anyway" option.

### 5.4 TLS — **self-signed is not enough for public visitors; ACME is required**

Because the app will be used by **other people**, a plain self-signed
certificate is not acceptable as the primary mode: every visitor gets a
full-page "Your connection is not private" interstitial, many will (rightly)
leave, and you can't ask strangers to install your root CA. Self-signed/local
CA stays as the fallback and offline/testing mode; **ACME (F17) moves from v2
into the v1 MVP.**

- Encryption works fine, but **browsers will show "Not secure / Your connection
  is not private"** for a plain self-signed cert. Users must click through,
  and some clients (mobile apps, `fetch` from other sites, webhooks from
  third parties like GitHub/Stripe) will refuse outright.
- Mitigation: **local CA mode (F5)** — install the hostip root CA once on each
  client device; then every regenerated leaf is trusted. Good for personal
  devices, unrealistic for the general public.
- The cert **must** put the IP in a SAN of type `iPAddress`; browsers ignore
  the Common Name.
- Keep leaf validity ≤ 397 days (Apple/Chrome limits) and auto-renew.
- **Chosen option: Let's Encrypt certificate for the bare IP** (option 2
  below). Implications:
  - Validity is only ~6 days → renewal runs every 2–3 days and must be
    reliable; a failed renewal becomes a visible outage within days, so the
    status command and logs must show expiry and last renewal result.
  - Only HTTP-01 (port 80) or TLS-ALPN-01 (port 443) work for IPs; DNS-01
    is impossible. Port 443 forwarding is therefore mandatory.
  - No hostnames → no SNI/`Host` routing (§5.2). Multiple apps use **path
    prefixes** on 443 (app must support a base path, e.g. Jellyfin's "Base
    URL") or **extra ports** (extra ports reuse the same IP certificate).
  - Dynamic IP → new cert + new URL each time the ISP changes the IP.
- **Trusted-cert options considered:**
  1. **Let's Encrypt cert for an `sslip.io` hostname**
     (`203-0-113-7.sslip.io`, resolves to `203.0.113.7`). Standard 90-day
     cert, renewed ~30 days before expiry. Also gives hostname routing
     (§5.2) and a friendlier URL. Caveat: sslip.io is a shared domain, so
     Let's Encrypt's per-registered-domain rate limits may bite; fall back to
     option 2 or a user-owned domain.
  2. **Let's Encrypt cert for the bare IP** using the short-lived (~6-day)
     profile. No third-party DNS at all, but renewal must run every few days
     and failures surface fast — monitoring and retry are essential.
  3. **User-owned domain** (A record → public IP, optional DDNS): most robust
     for long-term public hosting.
- **ACME implementation:** `instant-acme` crate; **TLS-ALPN-01** challenge
  (works on port 443 only, no port 80 needed) or **HTTP-01** (needs port 80).
  IP certificates can't use DNS-01. Store account key + certs on disk, hot-swap
  the cert in rustls without restarting (`ResolvesServerCert`).
- **Hard requirement for ACME:** Let's Encrypt validates on **port 443
  (TLS-ALPN-01) or port 80 (HTTP-01)** — a high port like 8443 alone is not
  enough. If the ISP blocks both, ACME is impossible and only self-signed or a
  user-owned domain with DNS-01 remains. Verify the current Let's Encrypt
  IP-certificate policy before implementing.

### 5.5a Streaming — **Feasible; bandwidth is the limit, not the software**

HTTP-based streaming (progressive MP4 with seeking, HLS/DASH, MJPEG, SSE,
WebSocket-based streams, media servers like Jellyfin/Plex/Navidrome) is a
plain reverse-proxy workload: hyper bodies are already streams, so F20–F24
are mostly about *not* doing harmful things (buffering, compressing,
total-request timeouts).

- **Not carried by the HTTP proxy:** WebRTC media (UDP) — handled in §5.5b.
- **Capacity math (home upload is the bottleneck):** viewers ≈ upload
  bandwidth ÷ stream bitrate. With **300 Mbit/s upload**, ~50 viewers of a
  5 Mbit/s 1080p stream or ~100 at 720p (keep ~20 % headroom).
- **Proxy design notes:** use `hyper` streaming bodies end-to-end, keep
  HTTP/2 flow-control windows reasonable for high-bitrate streams, disable
  Nagle (`TCP_NODELAY`) for low-latency live streams, and enforce the
  connection cap before accepting more viewers.

### 5.5b Live polling + video conferencing — **Feasible with an existing SFU; dynamic IP is the main weakness**

The workload is a **live polling app** and a **video conferencing app**.

**Polling app** — plain HTTPS + WebSocket/SSE/long-polling through hostip
(F25). Trivial bandwidth; feasible, no special work.

**Video conferencing (WebRTC)** has two halves:

| Part | Transport | Who handles it |
|------|-----------|----------------|
| Web UI, signaling, room API | HTTPS + WebSocket on 443 | **hostip reverse proxy** |
| Audio/video media | UDP (e.g. 50000–60000 or a single mux port), TCP fallback | **SFU directly** (router → PC), ports mapped by hostip (F26) |
| Clients behind strict firewalls | TURN over UDP 3478 / TLS 5349 (or 443) | TURN server (coturn, or the SFU's built-in TURN) using hostip's exported cert (F28) |

- **Trusted certificate is mandatory, not nice-to-have:** browsers only allow
  camera/microphone (`getUserMedia`) in a secure context, so the Let's
  Encrypt IP certificate is essential for conferencing.
- **Recommended SFU on Windows:** **LiveKit** (single binary with Windows
  builds, built-in TURN, `use_external_ip`/`node_ip` setting, good SDKs) or
  **mediasoup** (Node.js library, runs on Windows, more DIY). Jitsi works
  best on Linux/Docker. Rust options (`webrtc-rs`, `str0m`) exist but would
  mean building the SFU yourself — out of scope.
- **SFU must announce the public IP** in ICE candidates — hence F27
  (IP propagation + `on_ip_change` hook to update/restart the SFU).
- **Capacity: target is 100 participants per call on 300/300 Mbit/s.**
  An SFU sends each participant a copy of every stream they watch, so host
  upload ≈ participants × (streams each one receives × bitrate).

  | Call layout (100 participants) | Per-viewer download | Host upload | Fits 300 Mbit/s? |
  |---|---|---|---|
  | Everyone sees everyone (100 × 720p) | ~150 Mbit/s | ~15 Gbit/s | ❌ impossible on any home link |
  | Gallery: speaker 720p + 24 thumbnails | ~1.5 + 24×0.15 ≈ 5 Mbit/s | ~500 Mbit/s | ❌ |
  | Speaker 720p + 8 thumbnails | ~1.5 + 8×0.15 ≈ 2.7 Mbit/s | ~270 Mbit/s | ⚠️ no headroom |
  | **Speaker 720p + 4 thumbnails** | ~1.2 + 4×0.15 ≈ 1.8 Mbit/s | **~180 Mbit/s** | ✅ |
  | **Webinar: ≤ 4 presenters on video, 96 viewers** | ~1.5–2 Mbit/s | **~150–200 Mbit/s** | ✅ |
  | Audio-only (top 3 speakers forwarded) | ~0.1 Mbit/s | ~10 Mbit/s | ✅ easily |

  **Conclusion:** 100 per call is feasible **only with "last-N" / pagination
  and simulcast** — each viewer gets the active speaker plus a few small
  thumbnails, never the whole grid. This must be configured in the existing
  conferencing app/SFU (LiveKit: adaptive stream + dynacast + simulcast;
  Jitsi: last-N; mediasoup: app-side). Upload (~100 × 1.5–2.5 Mbit/s with
  simulcast layers ≈ 150–250 Mbit/s) also fits the 300 Mbit/s download.
  Allow ~20–30 % headroom for the polling app, retransmits and other use, so
  plan for **one 100-person call at a time**; several large calls in parallel
  won't fit.
- **CPU:** forwarding ~180 Mbit/s of SRTP to 100 peers is within reach of a
  modern 6–8-core desktop for LiveKit/mediasoup (they forward, not
  transcode). Load-test before relying on it.
- **Dynamic IP impact (no static IP available):** the router's public IP
  can change (typically on router reboot or ISP lease renewal). Then every
  in-progress call drops, the SFU must restart with the new IP, a new
  certificate is issued (~seconds–minutes), and — because links use the
  bare IP — **every shared link changes**. Mitigations:
  1. hostip detects the change within ≤ 60 s and automates re-issue + SFU
     restart (F19, F27); the conferencing app should auto-rejoin.
  2. Avoid router reboots during events; many ISPs keep the same IP as long
     as the router stays online.
  3. **Recommended: add a domain name with dynamic DNS** (a cheap domain or a
     free DDNS name). Links then never change and the cert is for the name;
     calls still drop on an IP change but participants rejoin the same link.
     This would replace the bare-IP certificate decision — owner to decide.
  4. Alternative for a truly static IP: a small VPS with a static IP
     tunnelling (WireGuard) to the home PC — but then all media flows
     through the VPS, so its bandwidth (≥ 300 Mbit/s) and cost matter.
- **Home PC caveats:** the PC must stay on and awake (disable sleep), and
  SFU CPU load grows with participants (fine for tens of users on a modern
  desktop).

### 5.5 Security / operational — **Feasible, needs care**

Publishing dev servers to the internet is inherently risky: dev servers
(Vite, Django debug, Jupyter) often expose source, debug consoles or code
execution. Hence auth-on-by-default (S3), loopback-only upstreams (S1) and
rate limits (S5) are **must-haves**, not extras. Internet-wide scanners will
find the open port within minutes to hours.

### 5.6 Alternatives (build vs. reuse)

| Tool | Gap compared to hostip |
|------|------------------------|
| Caddy / nginx / Traefik | Can do all of this, but need config knowledge; not auto-IP-cert focused |
| Cloudflare Tunnel, ngrok, Tailscale Funnel | Trusted certs and work behind CGNAT, but depend on a third party and route traffic through it |
| `rpxy`, `sozu` | Rust proxies, but no public-IP/self-signed/UPnP onboarding |

**hostip's niche:** zero-config, no third party, one command
(`hostip 3000`) → working HTTPS URL on your own IP, with safe defaults.
This is a reasonable, well-scoped project; it also makes a good learning
project for async Rust and TLS.

### 5.7 Verdict

| Dimension | Rating |
|-----------|--------|
| Technical | ✅ High — mature crates, well-understood problem |
| Network | ✅ High for the owner (not behind CGNAT); ⚠️ for other users of the tool behind CGNAT |
| Trusted TLS for public visitors | ✅ High with Let's Encrypt bare-IP cert (needs port 443/80 forwarded; ~6-day certs need reliable renewal); ❌ not achievable with self-signed alone |
| Live polling | ✅ High — WebSocket/SSE through the proxy |
| Video conferencing | ✅ Feasible using the existing app/SFU + hostip for TLS, signaling, port mapping and IP propagation; **100 per call fits 300 Mbit/s only with last-N/simulcast (speaker + ~4 thumbnails) or webinar layout**; one large call at a time; ⚠️ calls drop and links change on IP change |
| Windows host | ✅ High — Rust, rustls, UPnP, Windows service and firewall APIs all supported |
| Security | ⚠️ Medium — manageable with the defaults above |
| **Overall** | **Feasible.** Ship a Windows-first, real-time-safe reverse proxy with Let's Encrypt bare-IP certificates, UDP port mapping and public-IP propagation for an existing SFU. Get a static IP if possible. |

---

## 6. Risks

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| User is behind CGNAT | Medium | High | Detect and explain (F13); v2 relay mode |
| Exposed dev server gets exploited | Medium | High | Auth on by default, loopback-only upstreams, warnings |
| Browser warnings make it unusable for others | High (self-signed) | High | ACME by default (F17); self-signed only as fallback |
| ACME challenge fails (ports 80/443 blocked, rate limits) | Medium | High | TLS-ALPN-01 on 443, HTTP-01 fallback, clear diagnostics, self-signed fallback, own-domain option |
| Short-lived IP cert expires (renewal outage) | Medium | High | Renew at ~⅓–½ lifetime, retry with backoff, alert in logs/status |
| Home IP changes (dynamic IP) | Medium–High | High | IP watcher → immediate new cert + new URL (F19), `on_ip_change` restarts SFU (F27); ask ISP for static IP |
| Calls drop when IP changes | Medium | High | Fast detection (poll every 30–60 s + router UPnP external-IP query), quick SFU restart, client auto-reconnect in the app |
| Participants behind strict corporate/school firewalls (UDP blocked) | Medium | Medium | TURN over TLS (ideally on 443), SFU TCP fallback |
| 100-person call exceeds 300 Mbit/s upload | High if gallery view is used | High | Enforce last-N/simulcast in the SFU; webinar mode; cap participants; monitor egress |
| Windows sleep/updates restart the PC | Medium | Medium | Service auto-start, disable sleep, schedule update restarts |
| Upload bandwidth saturated by viewers | High | Medium | Viewer/connection caps, per-client bandwidth caps, adaptive-bitrate streams |
| Router/ISP blocks or reserves port 443 (router admin UI, ISP policy) | Medium | High | Move router admin off 443/disable WAN admin; diagnostics in self-test |
| Public IP changes break links/cert | Medium | Medium | IP watcher + cert regen; sslip.io hostnames |
| UPnP unavailable/disabled | High | Medium | NAT-PMP/PCP, IPv6, relay mode (F36), manual instructions |
| Relay VPS bandwidth/cost for large calls | Medium | Medium | Size VPS for ≥ 300 Mbit/s; prefer direct paths when available |
| ISP ToS forbid hosting | Low | Medium | Document; user's responsibility |

---

## 7. Roadmap and effort estimate (one developer)

| Phase | Scope | Estimate |
|-------|-------|----------|
| **M1 — MVP** | CLI quick mode, TOML config, port-based routing, self-signed cert with IP SANs, HTTP/1.1 + WebSocket proxy, forwarded headers, graceful shutdown | 1–2 weeks |
| **M1.5 — Trusted TLS + streaming** | Let's Encrypt bare-IP cert (TLS-ALPN-01 + HTTP-01, short-lived profile), auto-renew + hot-swap, IP-change re-issue, share URL; streaming-safe bodies, Range passthrough, streaming timeouts | ~1–1.5 weeks |
| **M2 — Safe by default** | Basic/token auth, rate limiting, timeouts/limits, IP allow/deny, access logs, key file permissions | 1 week |
| **M2.5 — Conferencing & Windows** | UDP port-range mapping via UPnP (F26), IP propagation + hooks (F27), cert export (F28), Windows service, firewall-rule install, port-conflict detection, LiveKit integration guide | ~1.5 weeks |
| **M3 — Convenience** | Local CA mode + export, viewer/bandwidth caps, public-IP watcher + cert regen, reachability/CGNAT self-test, UPnP/NAT-PMP, HTTP/2, path routing, hot reload | 1–2 weeks |
| **M3.5 — Relay mode** | `hostip relay` server, outbound tunnel (TCP + UDP multiplexed), cert for relay IP, connectivity ladder auto-selection | ~2 weeks |
| **M4 — Distribution** | Cross-platform CI, release binaries, docs, integration tests | ~1 week |
| **v2 (optional)** | Raw TCP/UDP proxying (RTMP/SRT ingest), TURN/HTTPS multiplexing on 443 (ALPN), sslip.io or own-domain hostnames, web dashboard | 2–4 weeks |

**Usable public v1: ~8–11 weeks of focused work** (excluding building the polling and conferencing apps themselves).

---

## 8. Example configuration (draft)

Quick start (no config file):

```
hostip expose 3000 8080 7880 udp:3478 udp:50000-60000
```

Equivalent config file:

```toml
[server]
redirect_http = true           # :80 for HTTP-01 challenges + redirect to https

[tls]
mode = "acme"                  # "acme" | "self-signed" | "local-ca" | "files"
dir = 'C:\ProgramData\hostip\certs'
acme_identifiers = ["ip"]      # bare public IP, Let's Encrypt short-lived profile
renew_before = "4d"            # renew well before the ~6-day expiry
acme_email = "you@example.com"
fallback = "self-signed"       # used if ACME fails; logged as a warning

[tls.export]                   # optional: let apps reuse the IP cert (F28)
cert = 'C:\ProgramData\hostip\export\cert.pem'
key  = 'C:\ProgramData\hostip\export\key.pem'
on_cert_renew = 'powershell -File C:\hostip\on-cert-renew.ps1'

[network]
upnp = true
public_ip_sources = ["https://api.ipify.org", "https://ifconfig.me/ip"]
ip_check_interval = "60s"
ip_file = 'C:\ProgramData\hostip\public_ip.txt'
on_ip_change = 'powershell -File C:\hostip\on-ip-change.ps1'   # receives HOSTIP_PUBLIC_IP

# Any app, any stack: just list ports. Public port = local port by default.
[[port]]
local = 3000                   # e.g. polling app
mode = "auto"
idle_timeout = "30m"

[[port]]
local = 8080                   # e.g. conferencing web UI
mode = "auto"
idle_timeout = "2h"

[[port]]
local = 7880                   # e.g. conferencing signaling (WebSocket)
public = 7443                  # optional: different public port
mode = "auto"

[[port]]
local = "3478"                 # TURN/STUN
protocol = "udp"

[[port]]
local = "50000-60000"          # WebRTC media range
protocol = "udp"
```

## 9. Decisions and open questions

**Decided**
- Audience: **other people / the public**, not just the owner → trusted
  certs are a v1 requirement; self-signed is fallback only.
- Certificate: **Let's Encrypt certificate for the bare public IP**.
- Host: **home PC**, **not behind CGNAT** → router port forwarding of 443 (+80).
- Workload: **live polling app + video conferencing app** (WebRTC); no SSH.
- Bandwidth: **300 Mbit/s upload and download**.
- Public IP: **dynamic**; no static IP available from the ISP.
- Host OS: **Windows**; hostip runs as a Windows service.
- Apps: polling and conferencing apps **already exist** — hostip only
  publishes them, **stack-agnostically, by port** (§5.2a).
- Scale: **~100 participants in one call** (one large call at a time).
- Certificate: **stay with the bare-IP certificate** (no domain / DDNS);
  shared links change when the IP changes — accepted.
- Router: owner's router can forward and supports UPnP, but hostip **must
  also work without UPnP / port forwarding** → connectivity ladder + relay
  mode (§5.3b).

**Open**
- None blocking. Requirements are ready for implementation (M1).

---

## 10. Implementation status (`dev` branch)

✅ done · 🟡 partial · ⬜ not yet

| ID | Status | Where / notes |
|----|--------|---------------|
| F1 | ✅ | Listeners per port; any public port incl. 443 (`src/server.rs`) |
| F2, F8, F11, F20–F22, F25, F33 | ✅ | `src/proxy.rs`: streamed bodies, upgrades (WebSocket), forwarded headers, redirect rewrite, no total timeout; tests in `tests/proxy.rs` |
| F3, F30, F31, F34 | ✅ | Stack-agnostic port specs and modes (`src/config.rs`), HTTP sniffing in `auto` |
| F4 | ✅ | Self-signed fallback with public/LAN IP SANs (`src/cert.rs`) |
| F5 | ⬜ | Local CA mode — superseded in practice by Let's Encrypt IP certificates |
| F6 | ✅ | `--cert/--key` or `[tls] cert/key`, reloaded when the files change |
| F7, F19 | ✅ | IP watcher with confirmation and address-family stickiness; re-issue on change (`src/publicip.rs`, `src/acme.rs`) |
| F9 | ✅ | HTTP/2 via ALPN |
| F10 | ✅ | Port-80 listener: ACME HTTP-01 + redirect to https |
| F12, F26 | ✅ | UPnP-IGD with PCP/NAT-PMP fallback, leases renewed, removed on exit (`src/portmap.rs`; fake-router tests) |
| F13, F29 | 🟡 | Double-NAT/CGNAT warning from the router's WAN address; Let's Encrypt validation proves 443/80 reachability. No independent outside probe yet |
| F14 | ✅ | `expose`, `status`, `ip`, `cert`, `hash-password`, `service`, `relay`. `status` shows links, certificate expiry, the last Let's Encrypt result and next renewal, open connections; `--json`; exit code 1 when not running (`src/status.rs`) |
| F15 | ✅ | Config file polled; valid changes restart the listeners in-process, invalid ones are rejected |
| F16 | ✅ | Graceful shutdown with drain (Ctrl+C, SIGTERM, service stop) |
| F17 | ✅ | Let's Encrypt bare-IP certificates, short-lived profile, TLS-ALPN-01 + HTTP-01 with rotation, renewal at ⅔ lifetime (`src/acme.rs`; Pebble tests) |
| F18 | ✅ | Share links and a terminal QR code |
| F23 | ✅ | Per-port connection cap and per-connection download rate cap (`max_client_rate`) |
| F24 | ✅ | Bodies are never compressed or rewritten |
| F27, F28 | ✅ | IP file + `on_ip_change`; certificate export + `on_cert_renew` (`src/hooks.rs`) |
| F32 | ✅ | `upstream_tls` for apps that serve HTTPS themselves |
| F35, F36 | ✅ | Connectivity ladder: already reachable → UPnP → PCP/NAT-PMP → relay mode (`src/relay.rs`; end-to-end tests incl. UDP). IPv6-only path not specially handled |
| S1 | ✅ | Upstreams are always 127.0.0.1 |
| S2 | ✅ | rustls safe defaults (TLS 1.2/1.3) |
| S3 | 🟡 | Basic auth + session cookie, Argon2; **opt-in** (`--auth`), not on by default — public conferencing links must work without a password prompt; the startup summary warns about open ports |
| S4, S5, S8 | ✅ | `src/access.rs`: allow/deny, per-IP connection/rate limits, brute-force blocking, access log |
| S6 | ✅ | Private keys 0600 on Unix; Windows data folder ACL set by the service installer |
| S7 | ✅ | Hop-by-hop headers stripped; generic 502 text |
| S9 | ✅ | Windows service as LocalService by default; systemd unit with only CAP_NET_BIND_SERVICE |
| Windows | ✅ | Service, firewall rules, CI on windows-latest, Wine-based local testing |
| Distribution | ✅ | Release workflow for Windows/Linux/macOS binaries |
