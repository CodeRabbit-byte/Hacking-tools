"""Minimal local test website used by the unit tests."""

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse, unquote
import time


class ExampleHandler(BaseHTTPRequestHandler):
    server_version = "ExampleTestSite/1.0"

    def _write(self, code=200, body="", headers=None):
        self.send_response(code)
        hdrs = headers or {}
        for k, v in hdrs.items():
            self.send_header(k, v)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.end_headers()
        self.wfile.write(body.encode("utf-8", "replace"))

    def do_GET(self):
        parsed = urlparse(self.path)
        route = parsed.path
        query = parse_qs(parsed.query)

        if route == "/":
            return self._write(200, "ok")

        if route == "/item":
            item_id = query.get("id", [""])[0]
            if item_id == "admin":
                return self._write(200, "interesting marker: admin profile")
            if item_id in {"1", "2"}:
                return self._write(200, f"record {item_id}")
            return self._write(404, "not found")

        if route == "/lfi":
            value = unquote(query.get("file", [""])[0])
            if "etc/passwd" in value:
                return self._write(200, "root:x:0:0:root:/root:/bin/bash")
            return self._write(200, "no file")

        if route == "/flag":
            return self._write(200, "CTF{web_flag}")

        return self._write(404, "not found")

    def do_POST(self):
        parsed = urlparse(self.path)
        if parsed.path != "/login":
            return self._write(404, "not found")

        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length).decode("utf-8", "replace")
        params = parse_qs(body)
        username = params.get("username", [""])[0]

        if "SLEEP(2)" in username or "WAITFOR DELAY" in username:
            time.sleep(2)
            return self._write(200, "delay handled")

        if "' OR '1'='1" in username or "' OR 1=1--" in username:
            return self._write(200, "Welcome admin")

        if "'" in username or '"' in username:
            return self._write(200, "SQL syntax error near quote")

        return self._write(200, "login failed")

    def log_message(self, *args, **kwargs):
        return


def create_server(port=0):
    return ThreadingHTTPServer(("127.0.0.1", port), ExampleHandler)
