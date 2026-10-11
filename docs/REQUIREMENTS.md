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
- Traversing CGNAT / double NAT without a relay (see §5.3 — needs a VPS).
- Raw TCP/UDP forwarding (games, SSH, databases).
- Being a general-purpose production load balancer.

---

## 2. Functional requirements

| ID | Requirement | Priority |
|----|-------------|----------|
| F1 | Listen for HTTPS on a configurable address/port (default `0.0.0.0:443`, fallback `8443`). | Must |
| F2 | Reverse-proxy HTTP/1.1 requests to configured local upstreams (`http://127.0.0.1:<port>`). | Must |
| F3 | Support multiple apps, routed by **port**, **path prefix**, or **hostname** (see §5.2). | Must |
| F4 | Self-signed fallback: on first run, generate a certificate with the public IP (and LAN IP, `localhost`) as `iPAddress`/`dNSName` SANs; persist key + cert to disk. | Must |
| F5 | Optional "local CA" mode: generate a root CA once, sign leaf certs with it, and print instructions to install the CA on client devices so browsers stop warning. Useful for testing/private use only — not a solution for public visitors. | Could |
| F6 | Allow user-supplied cert/key (PEM) instead of generating. | Should |
| F7 | Detect the public IP (via HTTPS echo services, configurable) and regenerate the leaf cert when it changes. | Should |
| F8 | WebSocket upgrade passthrough (needed by Vite/Next.js HMR, Jupyter, etc.). | Must |
| F9 | HTTP/2 to clients (ALPN `h2`, `http/1.1`). | Should |
| F10 | Optional plain-HTTP listener on port 80 that only redirects to HTTPS. | Could |
| F11 | Set `X-Forwarded-For`, `X-Forwarded-Proto`, `X-Forwarded-Host`, `Forwarded` headers; optionally rewrite `Host`. | Must |
| F12 | Optional router auto-config via UPnP-IGD / NAT-PMP / PCP, with automatic removal of the mapping on exit. | Could |
| F13 | Reachability self-test: report whether the public IP:port is actually reachable from outside (and detect CGNAT by comparing WAN IP vs. public IP). | Should |
| F14 | CLI: `hostip up`, `hostip add <name> <port>`, `hostip cert {show,regen,export-ca}`, `hostip status`. Quick mode: `hostip 3000`. | Must |
| F15 | Config file (TOML) with hot reload of routes. | Should |
| F16 | Graceful shutdown (drain in-flight requests on Ctrl-C/SIGTERM). | Must |
| F17 | **ACME mode (default when the port is publicly reachable):** obtain a browser-trusted certificate from Let's Encrypt for (a) the bare public IP (short-lived profile) and/or (b) an `sslip.io` hostname for that IP; renew automatically; fall back to self-signed on failure and say so loudly. | Must |
| F18 | Print a ready-to-share URL on start (e.g. `https://<ip-dashed>.sslip.io:8443`) and a QR code for phones. | Should |

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
| S9 | Run without root: document `setcap cap_net_bind_service` on Linux, or use a high port. | Must |

## 4. Non-functional requirements

| Area | Target |
|------|--------|
| Platforms | Linux x86_64/aarch64, macOS (arm64/x86_64), Windows x86_64 |
| Distribution | Single binary, no runtime deps; `cargo install`, GitHub Releases |
| Performance | ≥ 5k req/s and < 2 ms added p99 latency on a typical laptop for small responses (home upload bandwidth will be the real bottleneck) |
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

### 5.3 Network — **Feasible on most home connections, blocked on some**

> **Owner's environment:** confirmed *not* behind CGNAT — the public IP is
> directly reachable, so inbound hosting works once the port is forwarded /
> opened in the firewall. (If hostip will run on a cloud VM rather than a home
> PC, there is no NAT at all; only the provider's firewall / security group
> and the OS firewall need the port opened.)

| Situation | Outcome |
|-----------|---------|
| Router with public WAN IP, port forwarding allowed | ✅ Works (manual forward or UPnP) |
| PC directly on public IP (no router) | ✅ Works; OS firewall rule needed |
| ISP blocks inbound 80/443 | ⚠️ Use a high port (e.g. 8443) |
| Dynamic public IP | ⚠️ Works; cert regeneration (F7) + DDNS/sslip.io hostname changes |
| **CGNAT** (common on mobile/4G/5G and some fibre ISPs) | ❌ No inbound possible. Needs a relay (VPS tunnel) — out of scope for v1, candidate for v2 |
| IPv6 available | ✅ Often easier (no NAT); needs firewall pinhole on router. Support `[::]` listening |

The F13 self-test should detect CGNAT (router WAN IP in `100.64.0.0/10` or
differs from the observed public IP) and tell the user clearly.

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
- **Trusted-cert options (in order of recommendation):**
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
| Trusted TLS for public visitors | ✅ High with ACME (needs port 443 or 80 reachable); ❌ not achievable with self-signed alone |
| Security | ⚠️ Medium — manageable with the defaults above |
| **Overall** | **Feasible.** Ship port-based routing + ACME (sslip.io hostname / IP cert) + self-signed fallback in v1; add hostname routing on one port next. |

---

## 6. Risks

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| User is behind CGNAT | Medium | High | Detect and explain (F13); v2 relay mode |
| Exposed dev server gets exploited | Medium | High | Auth on by default, loopback-only upstreams, warnings |
| Browser warnings make it unusable for others | High (self-signed) | High | ACME by default (F17); self-signed only as fallback |
| ACME challenge fails (ports 80/443 blocked, rate limits) | Medium | High | TLS-ALPN-01 on 443, HTTP-01 fallback, clear diagnostics, self-signed fallback, own-domain option |
| Short-lived IP cert expires (renewal outage) | Medium | High | Renew at ~half lifetime, retry with backoff, alert in logs/status |
| Public IP changes break links/cert | Medium | Medium | IP watcher + cert regen; sslip.io hostnames |
| UPnP unavailable/disabled | High | Low | Manual port-forward instructions printed by CLI |
| ISP ToS forbid hosting | Low | Medium | Document; user's responsibility |

---

## 7. Roadmap and effort estimate (one developer)

| Phase | Scope | Estimate |
|-------|-------|----------|
| **M1 — MVP** | CLI quick mode, TOML config, port-based routing, self-signed cert with IP SANs, HTTP/1.1 + WebSocket proxy, forwarded headers, graceful shutdown | 1–2 weeks |
| **M1.5 — Trusted TLS** | ACME (TLS-ALPN-01 + HTTP-01) for sslip.io hostname and bare IP, auto-renew with cert hot-swap, share URL output | ~1 week |
| **M2 — Safe by default** | Basic/token auth, rate limiting, timeouts/limits, IP allow/deny, access logs, key file permissions | 1 week |
| **M3 — Convenience** | Local CA mode + export, sslip.io hostname routing on one port, public-IP watcher + cert regen, reachability/CGNAT self-test, UPnP/NAT-PMP, HTTP/2, path routing, hot reload | 1–2 weeks |
| **M4 — Distribution** | Cross-platform CI, release binaries, docs, integration tests | ~1 week |
| **v2 (optional)** | IPv6, VPS relay for CGNAT, web dashboard | 2–4 weeks |

**Usable public v1: ~5–7 weeks of focused work.**

---

## 8. Example configuration (draft)

```toml
[server]
listen = "0.0.0.0:443"         # 443 needed for ACME TLS-ALPN-01
redirect_http = true           # listen on :80: HTTP-01 challenges + redirect

[tls]
mode = "acme"                  # "acme" | "self-signed" | "local-ca" | "files"
dir = "~/.hostip/certs"
acme_identifiers = ["sslip", "ip"]   # sslip.io hostname and/or bare public IP
acme_email = "you@example.com"
fallback = "self-signed"       # used if ACME fails; logged as a warning

[network]
upnp = true
public_ip_sources = ["https://api.ipify.org", "https://ifconfig.me/ip"]

[[app]]
name = "web"
upstream = "http://127.0.0.1:3000"
route = { port = 443 }
auth = { basic = { user = "me", password_hash = "$argon2id$..." } }

[[app]]
name = "api"
upstream = "http://127.0.0.1:8080"
route = { path = "/api" }
allow = ["203.0.113.0/24"]
```

## 9. Decisions and open questions

**Decided**
- Audience: **other people / the public**, not just the owner → ACME trusted
  certs are a v1 requirement; self-signed is fallback only.
- Owner's connection is **not behind CGNAT** → direct inbound hosting is
  feasible; no relay needed for the owner.

**Open**
1. Do you need raw TCP (SSH, databases, game servers) or only HTTP(S)?
2. Can ports 443 and/or 80 be opened (router forward, ISP not blocking)?
   Required for Let's Encrypt validation.
3. Is the host a home PC or a cloud VM? (Affects NAT/UPnP vs. security-group setup.)
4. Is a free shared hostname (sslip.io) acceptable, or will you buy a domain?
5. Should hostip run as a background service (systemd / Windows service) in v1?
