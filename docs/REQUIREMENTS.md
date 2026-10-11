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
- Generate and manage a self-signed certificate (or a local CA) automatically.
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
| F4 | On first run, generate a certificate with the public IP (and LAN IP, `localhost`) as `iPAddress`/`dNSName` SANs; persist key + cert to disk. | Must |
| F5 | Optional "local CA" mode: generate a root CA once, sign leaf certs with it, and print instructions to install the CA on client devices so browsers stop warning. | Should |
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

### 5.4 Self-signed TLS — **Feasible, with UX caveats**

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
- **Better alternative worth adding later:** Let's Encrypt now issues
  short-lived certificates for IP addresses, and certs for `sslip.io`-style
  hostnames have long been possible. An optional ACME mode (`instant-acme`
  crate, HTTP-01 / TLS-ALPN-01 challenge) would give browser-trusted certs
  with no warnings, provided port 80 or 443 is reachable. Check the current
  CA policy before implementing.

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
| Network | ⚠️ Medium — works unless the user is behind CGNAT |
| UX of self-signed TLS | ⚠️ Medium — warnings unless local CA or ACME is used |
| Security | ⚠️ Medium — manageable with the defaults above |
| **Overall** | **Feasible.** Ship port-based routing + self-signed/local-CA first; add sslip.io hostnames and ACME next. |

---

## 6. Risks

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| User is behind CGNAT | Medium | High | Detect and explain (F13); v2 relay mode |
| Exposed dev server gets exploited | Medium | High | Auth on by default, loopback-only upstreams, warnings |
| Browser warnings make it unusable for others | High | Medium | Local CA mode; ACME mode later |
| Public IP changes break links/cert | Medium | Medium | IP watcher + cert regen; sslip.io hostnames |
| UPnP unavailable/disabled | High | Low | Manual port-forward instructions printed by CLI |
| ISP ToS forbid hosting | Low | Medium | Document; user's responsibility |

---

## 7. Roadmap and effort estimate (one developer)

| Phase | Scope | Estimate |
|-------|-------|----------|
| **M1 — MVP** | CLI quick mode, TOML config, port-based routing, self-signed cert with IP SANs, HTTP/1.1 + WebSocket proxy, forwarded headers, graceful shutdown | 1–2 weeks |
| **M2 — Safe by default** | Basic/token auth, rate limiting, timeouts/limits, IP allow/deny, access logs, key file permissions | 1 week |
| **M3 — Convenience** | Local CA mode + export, public-IP watcher + cert regen, reachability/CGNAT self-test, UPnP/NAT-PMP, HTTP/2, path routing, hot reload | 1–2 weeks |
| **M4 — Distribution** | Cross-platform CI, release binaries, docs, integration tests | ~1 week |
| **v2 (optional)** | sslip.io hostname routing, ACME (trusted certs), IPv6, VPS relay for CGNAT, web dashboard | 2–4 weeks |

**MVP to usable v1: ~4–6 weeks part-time-equivalent of focused work.**

---

## 8. Example configuration (draft)

```toml
[server]
listen = "0.0.0.0:8443"
redirect_http = false          # listen on :80 and redirect

[tls]
mode = "local-ca"              # "self-signed" | "local-ca" | "files" | "acme" (v2)
dir = "~/.hostip/certs"
extra_sans = ["myhost.example"]

[network]
upnp = true
public_ip_sources = ["https://api.ipify.org", "https://ifconfig.me/ip"]

[[app]]
name = "web"
upstream = "http://127.0.0.1:3000"
route = { port = 8443 }
auth = { basic = { user = "me", password_hash = "$argon2id$..." } }

[[app]]
name = "api"
upstream = "http://127.0.0.1:8080"
route = { path = "/api" }
allow = ["203.0.113.0/24"]
```

## 9. Open questions

1. Is the audience only you and your own devices (→ local CA is fine), or the
   public (→ ACME / trusted certs become important)?
2. Do you need raw TCP (SSH, databases, game servers) or only HTTP(S)?
3. Is your connection behind CGNAT? (Compare your router's WAN IP with
   `curl https://api.ipify.org`.)
4. Should hostip run as a background service (systemd / Windows service) in v1?
