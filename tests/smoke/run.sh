#!/usr/bin/env bash
# End-to-end smoke test of a built hostip binary with the test data in tests/smoke/.
# Used by the `test` stage of the promotion pipeline (docs/WORKFLOW.md).
#
#   tests/smoke/run.sh [path/to/hostip]
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
bin="${1:-$here/../../target/release/hostip}"
work="$(mktemp -d)"
python=""
for candidate in python3 python; do
    if "$candidate" -c 'import sys' 2>/dev/null; then python="$candidate"; break; fi
done
[ -n "$python" ] || { echo "FAIL: python is needed to serve the test data" >&2; exit 1; }
pids=()
cleanup() {
    for pid in "${pids[@]}"; do kill "$pid" 2>/dev/null || true; done
    rm -rf "$work"
}
trap cleanup EXIT

fail() {
    echo "FAIL: $*" >&2
    [ -f "$work/hostip.log" ] && { echo "--- hostip log ---" >&2; cat "$work/hostip.log" >&2; }
    exit 1
}
pass() { echo "ok   $*"; }

# The local app: serves the test data, with Range support.
"$python" "$here/app.py" 3999 "$here/data" >"$work/app.log" 2>&1 &
pids+=($!)
"$bin" expose --config "$here/smoke.toml" --cert-dir "$work/certs" >"$work/hostip.log" 2>&1 &
pids+=($!)

curl_() { curl --noproxy '*' -sk --max-time 10 "$@"; }
# Ready once a request goes all the way through to the app.
for _ in $(seq 1 100); do
    curl_ -f -o /dev/null "https://127.0.0.1:9443/hello.txt" && break
    sleep 0.2
done

expected="$(cat "$here/data/hello.txt")"

body="$(curl_ "https://127.0.0.1:9443/hello.txt")" || fail "HTTPS request failed"
[ "$body" = "$expected" ] || fail "body was '$body'"
pass "HTTPS proxies the app's file unchanged"

code="$(curl_ -o "$work/part" -w '%{http_code}' -H 'Range: bytes=0-4' "https://127.0.0.1:9443/hello.txt")"
[ "$code" = 206 ] && [ "$(cat "$work/part")" = "Hello" ] || fail "range request gave $code '$(cat "$work/part")'"
pass "Range requests pass through (206 Partial Content)"

# Asked through Python: some curl builds (e.g. Windows' own) lack HTTP/2.
alpn="$("$python" -c '
import socket, ssl
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
ctx.set_alpn_protocols(["h2", "http/1.1"])
with ctx.wrap_socket(socket.create_connection(("127.0.0.1", 9443)), server_hostname="127.0.0.1") as s:
    print(s.selected_alpn_protocol())
')" || fail "TLS connection for the ALPN check failed"
[ "$alpn" = h2 ] || fail "ALPN selected '$alpn' instead of h2"
pass "HTTP/2 is negotiated"

code="$(curl_ -o /dev/null -w '%{http_code}' "https://127.0.0.1:9444/hello.txt")"
[ "$code" = 401 ] || fail "port with auth answered $code without a login"
pass "login is required on the protected port"

body="$(curl_ -u demo:secret "https://127.0.0.1:9444/hello.txt")" || fail "login request failed"
[ "$body" = "$expected" ] || fail "body with login was '$body'"
pass "the right login gets through"

code="$(curl_ -o /dev/null -w '%{http_code}' -u demo:wrong "https://127.0.0.1:9444/hello.txt")"
[ "$code" = 401 ] || fail "wrong password answered $code"
pass "a wrong password is refused"

issuer="$(echo | openssl s_client -connect 127.0.0.1:9443 2>/dev/null | openssl x509 -noout -ext subjectAltName 2>/dev/null || true)"
case "$issuer" in
    *203.0.113.7*) pass "certificate names the public IP" ;;
    *) fail "certificate SANs: $issuer" ;;
esac

echo "smoke test passed"
