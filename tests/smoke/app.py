"""Stand-in for a user's app in the smoke test: serves tests/smoke/data with
Range support, so hostip's 206 pass-through can be checked.

    python app.py PORT DATA_DIR
"""

import http.server
import os
import re
import sys


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        path = os.path.join(DATA, os.path.basename(self.path.split("?")[0]))
        if not os.path.isfile(path):
            self.send_error(404)
            return
        with open(path, "rb") as f:
            body = f.read()
        match = re.fullmatch(r"bytes=(\d+)-(\d*)", self.headers.get("Range", ""))
        if match:
            start = int(match[1])
            end = int(match[2]) if match[2] else len(body) - 1
            part = body[start : end + 1]
            self.send_response(206)
            self.send_header("Content-Range", f"bytes {start}-{end}/{len(body)}")
            body = part
        else:
            self.send_response(200)
        self.send_header("Accept-Ranges", "bytes")
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


if __name__ == "__main__":
    DATA = sys.argv[2]
    http.server.ThreadingHTTPServer(("127.0.0.1", int(sys.argv[1])), Handler).serve_forever()
