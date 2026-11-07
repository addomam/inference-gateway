#!/usr/bin/env python3
"""Tiny OpenAI-compatible chat stub for the kind smoke test."""

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

BODY = json.dumps(
    {
        "id": "chatcmpl-smoke",
        "object": "chat.completion",
        "choices": [
            {
                "index": 0,
                "message": {"role": "assistant", "content": "pong"},
                "finish_reason": "stop",
            }
        ],
    }
).encode()


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        if self.path != "/health":
            self.send_error(404)
            return
        payload = b'{"status":"ok"}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        self.rfile.read(length)
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(BODY)))
        self.end_headers()
        self.wfile.write(BODY)

    def log_message(self, fmt, *args):
        return


ThreadingHTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
