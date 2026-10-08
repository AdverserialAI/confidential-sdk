"""A loopback HTTP surface for OpenAI-compatible confidential clients."""
from __future__ import annotations

import argparse
import json
import uuid
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .config import Config, ConfigError
from adverserial import VerificationError

from .compat import anthropic_to_chat, chat_to_anthropic, chat_to_response, responses_to_chat
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

    def _sse_start(self):
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Accel-Buffering", "no")
        # No Content-Length and no chunked framing: the only end-of-response
        # signal is closing the connection. Without this, HTTP/1.1 keep-alive
        # leaves clients waiting forever after [DONE].
        self.close_connection = True
        self.send_header("Connection", "close")
        self.end_headers()

    def _sse(self, payload: dict, event: str | None = None):
        if event:
            self.wfile.write(f"event: {event}\n".encode())
        self.wfile.write(b"data: " + json.dumps(payload, separators=(",", ":")).encode() + b"\n\n")
        self.wfile.flush()

    def _stream_openai(self, stream):
        self._sse_start()
        try:
            for chunk in stream:
                self._sse(chunk)
            if not stream.receipt_verified:
                raise ClientRequestError("confidential stream ended without a verified receipt")
            self.wfile.write(b"data: [DONE]\n\n")
        except (GatewayError, VerificationError, ValueError, OSError) as exc:
            self._sse({"error": {"type": "confidential_gateway_error", "message": str(exc)}}, "error")

    def _stream_anthropic(self, stream, model: str):
        self._sse_start(); message_id = "msg_" + uuid.uuid4().hex
        self._sse({"type":"message_start","message":{"id":message_id,"type":"message","role":"assistant","model":model,"content":[],"stop_reason":None,"stop_sequence":None,"usage":{"input_tokens":0,"output_tokens":0}}}, "message_start")
        # GLM reasoning streams in delta.reasoning_content; map it to an
        # Anthropic thinking block at index 0, with text following at index 1.
        index = 0; open_block = None
        def close_block():
            nonlocal index, open_block
            if open_block is not None:
                if open_block == "thinking":
                    # Anthropic clients expect a signature before the thinking
                    # block closes; nothing verifies it on this path.
                    self._sse({"type":"content_block_delta","index":index,"delta":{"type":"signature_delta","signature":""}}, "content_block_delta")
                self._sse({"type":"content_block_stop","index":index}, "content_block_stop")
                index += 1; open_block = None
        try:
            usage = {}
            for chunk in stream:
                choice = (chunk.get("choices") or [{}])[0]
                delta = choice.get("delta") or {}
                thinking = delta.get("reasoning_content")
                text = delta.get("content")
                if thinking:
                    if open_block != "thinking":
                        close_block()
                        self._sse({"type":"content_block_start","index":index,"content_block":{"type":"thinking","thinking":""}}, "content_block_start")
                        open_block = "thinking"
                    self._sse({"type":"content_block_delta","index":index,"delta":{"type":"thinking_delta","thinking":thinking}}, "content_block_delta")
                if text:
                    if open_block != "text":
                        close_block()
                        self._sse({"type":"content_block_start","index":index,"content_block":{"type":"text","text":""}}, "content_block_start")
                        open_block = "text"
                    self._sse({"type":"content_block_delta","index":index,"delta":{"type":"text_delta","text":text}}, "content_block_delta")
                usage = chunk.get("usage") or usage
            if not stream.receipt_verified:
                raise ClientRequestError("confidential stream ended without a verified receipt")
            close_block()
            self._sse({"type":"message_delta","delta":{"stop_reason":"end_turn","stop_sequence":None},"usage":{"output_tokens":usage.get("completion_tokens",0)}}, "message_delta")
            self._sse({"type":"message_stop"}, "message_stop")
        except (GatewayError, VerificationError, ValueError, OSError) as exc:
            self._sse({"type":"error","error":{"type":"api_error","message":str(exc)}}, "error")

    def _stream_responses(self, stream, model: str):
        self._sse_start(); rid = "resp_" + uuid.uuid4().hex; mid = "msg_" + uuid.uuid4().hex
        self._sse({"type":"response.created","response":{"id":rid,"object":"response","status":"in_progress","model":model,"output":[]}}, "response.created")
        self._sse({"type":"response.output_item.added","output_index":0,"item":{"id":mid,"type":"message","status":"in_progress","role":"assistant","content":[]}}, "response.output_item.added")
        self._sse({"type":"response.content_part.added","item_id":mid,"output_index":0,"content_index":0,"part":{"type":"output_text","text":"","annotations":[]}}, "response.content_part.added")
        try:
            usage = {}
            for chunk in stream:
                choice = (chunk.get("choices") or [{}])[0]
                delta = choice.get("delta") or {}
                text = delta.get("content")
                if text:
                    self._sse({"type":"response.output_text.delta","item_id":mid,"output_index":0,"content_index":0,"delta":text}, "response.output_text.delta")
                usage = chunk.get("usage") or usage
            if not stream.receipt_verified:
                raise ClientRequestError("confidential stream ended without a verified receipt")
            self._sse({"type":"response.output_text.done","item_id":mid,"output_index":0,"content_index":0,"text":""}, "response.output_text.done")
            self._sse({"type":"response.content_part.done","item_id":mid,"output_index":0,"content_index":0,"part":{"type":"output_text","text":"","annotations":[]}}, "response.content_part.done")
            item={"id":mid,"type":"message","status":"completed","role":"assistant","content":[]}
            self._sse({"type":"response.output_item.done","output_index":0,"item":item}, "response.output_item.done")
            self._sse({"type":"response.completed","response":{"id":rid,"object":"response","status":"completed","model":model,"output":[item],"usage":{"input_tokens":usage.get("prompt_tokens",0),"output_tokens":usage.get("completion_tokens",0),"total_tokens":usage.get("total_tokens",0)}}}, "response.completed")
        except (GatewayError, VerificationError, ValueError, OSError) as exc:
            self._sse({"type":"response.failed","response":{"id":rid,"object":"response","status":"failed","error":{"code":"confidential_gateway_error","message":str(exc)}}}, "response.failed")

    def do_GET(self):
        if self.path == "/healthz":
            return self._json(HTTPStatus.OK, {"status": "ok", "bind": "loopback"})
        return self._json(HTTPStatus.NOT_FOUND, {"error": {"message": "Not found"}})

    def do_POST(self):
        path = self.path.split("?", 1)[0]
        if path not in {"/v1/chat/completions", "/v1/messages", "/v1/responses", "/responses"}:
            return self._json(HTTPStatus.NOT_FOUND, {"error": {"message": "Unsupported local gateway endpoint"}})
        length = self.headers.get("content-length")
        try:
            size = int(length or "0")
        except ValueError:
            size = 0
        if size < 1 or size > 64 * 1024 * 1024:
            return self._json(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, {"error": {"message": "Invalid request size"}})
        auth = self.headers.get("authorization", "")
        api_key = auth.removeprefix("Bearer ").strip() if auth.startswith("Bearer ") else self.headers.get("x-api-key", "").strip()
        try:
            payload = json.loads(self.rfile.read(size))
            if not isinstance(payload, dict):
                raise ClientRequestError("Request must be a JSON object")
            streaming = bool(payload.get("stream"))
            if path == "/v1/messages":
                model = payload.get("model")
                if not isinstance(model, str):
                    raise ClientRequestError("model is required")
                chat = anthropic_to_chat(payload); chat["stream"] = streaming
                result = self.dispatcher.adapted_completion(api_key, model, chat)
                if streaming: return self._stream_anthropic(result, model)
                self._json(HTTPStatus.OK, chat_to_anthropic(dict(result), model))
            elif path in {"/v1/responses", "/responses"}:
                model = payload.get("model")
                if not isinstance(model, str):
                    raise ClientRequestError("model is required")
                chat = responses_to_chat(payload); chat["stream"] = streaming
                result = self.dispatcher.adapted_completion(api_key, model, chat)
                if streaming: return self._stream_responses(result, model)
                self._json(HTTPStatus.OK, chat_to_response(dict(result), model))
            else:
                result = self.dispatcher.completion(api_key, payload)
                if streaming: return self._stream_openai(result)
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
