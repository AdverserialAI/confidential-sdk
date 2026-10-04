"""A loopback HTTP surface for OpenAI-compatible confidential clients."""
from __future__ import annotations

import argparse
import json
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .config import Config, ConfigError
from .core import AuthorizationError, ClientRequestError, Dispatcher, GatewayError


class Handler(BaseHTTPRequestHandler):
    dispatcher: Dispatcher
    server_version = "AdverserialConfidentialGateway/0.1"
    protocol_version = "HTTP/1.1"

    def log_message(self, *_args):
        # Do not log request paths, headers, bodies, identities, or prompts.
        return

    def _json(self, status: int, payload: dict):
        data = json.dumps(payload, separators=(",", ":")).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path == "/healthz":
            return self._json(HTTPStatus.OK, {"status": "ok", "bind": "loopback"})
        return self._json(HTTPStatus.NOT_FOUND, {"error": {"message": "Not found"}})

    def do_POST(self):
        if self.path != "/v1/chat/completions":
            return self._json(HTTPStatus.NOT_FOUND, {"error": {"message": "Unsupported local gateway endpoint"}})
        length = self.headers.get("content-length")
        try:
            size = int(length or "0")
        except ValueError:
            size = 0
        if size < 1 or size > 64 * 1024 * 1024:
            return self._json(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, {"error": {"message": "Invalid request size"}})
        auth = self.headers.get("authorization", "")
        api_key = auth.removeprefix("Bearer ").strip() if auth.startswith("Bearer ") else ""
        try:
            payload = json.loads(self.rfile.read(size))
            if not isinstance(payload, dict):
                raise ClientRequestError("Request must be a JSON object")
            if payload.get("stream"):
                raise ClientRequestError("Streaming is not enabled in the initial local gateway release")
            result = self.dispatcher.completion(api_key, payload)
            self._json(HTTPStatus.OK, dict(result))
        except GatewayError as exc:
            self._json(exc.status_code, {"error": {"type": "confidential_gateway_error", "message": str(exc)}})
        except (ValueError, TypeError) as exc:
            self._json(HTTPStatus.BAD_REQUEST, {"error": {"message": str(exc)}})


def main() -> None:
    parser = argparse.ArgumentParser(description="Loopback-only Adverserial confidential OpenAI gateway")
    parser.parse_args()
    try:
        config = Config.from_env()
    except ConfigError as exc:
        raise SystemExit(f"configuration error: {exc}")
    Handler.dispatcher = Dispatcher(config)
    server = ThreadingHTTPServer((config.listen_host, config.listen_port), Handler)
    print(f"adverserial confidential gateway listening on http://{config.listen_host}:{config.listen_port}", flush=True)
    server.serve_forever()
