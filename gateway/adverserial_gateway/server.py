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
        # Preserve each OpenAI stream tool-call index. Anthropic requires
        # content blocks to close in order, so each upstream tool-call block
        # is closed before the next begins while its argument fragments remain
        # associated with its original OpenAI index.
        next_index = 0; open_block = None; blocks = {}; saw_tool = False
        def close_block(block):
            nonlocal open_block
            if block is None or block.get("closed"):
                return
            if block["kind"] == "thinking":
                # Anthropic clients require a terminal signature marker for a
                # thinking block. It is a transport marker only here; the
                # attested receipt remains the cryptographic proof.
                self._sse({"type":"content_block_delta","index":block["index"],"delta":{"type":"signature_delta","signature":""}}, "content_block_delta")
            self._sse({"type":"content_block_stop","index":block["index"]}, "content_block_stop")
            block["closed"] = True
            if open_block is block:
                open_block = None

        def start_plain(kind):
            nonlocal next_index, open_block
            if open_block is not None and open_block["kind"] != kind:
                close_block(open_block)
            if open_block is not None:
                return open_block
            block = {"kind": kind, "index": next_index, "closed": False}
            next_index += 1
            payload = {"type": kind, kind: ""}
            self._sse({"type":"content_block_start","index":block["index"],"content_block":payload}, "content_block_start")
            open_block = block
            return block

        def tool_block(call):
            nonlocal next_index, open_block, saw_tool
            raw_index = call.get("index")
            key = raw_index if isinstance(raw_index, int) else call.get("id")
            if key is None:
                raise ClientRequestError("upstream streamed a tool call without an index or id")
            block = blocks.get(key)
            fn = call.get("function") or {}
            name = fn.get("name") if isinstance(fn, dict) and isinstance(fn.get("name"), str) else ""
            call_id = call.get("id") if isinstance(call.get("id"), str) else ""
            if block is None:
                if not name:
                    raise ClientRequestError("upstream streamed a tool argument before its function name")
                if open_block is not None:
                    close_block(open_block)
                block = {"kind": "tool_use", "index": next_index, "closed": False, "id": call_id or "toolu_" + uuid.uuid4().hex, "name": name}
                next_index += 1
                blocks[key] = block
                self._sse({"type":"content_block_start","index":block["index"],"content_block":{"type":"tool_use","id": "toolu_" + block["id"].removeprefix("toolu_"), "name":name,"input":{}}}, "content_block_start")
                open_block = block
                saw_tool = True
            elif block is not open_block:
                if block.get("closed"):
                    raise ClientRequestError("upstream interleaved tool arguments after an earlier tool block closed")
                if open_block is not None:
                    close_block(open_block)
                open_block = block
            return block
        try:
            usage = {}
            for chunk in stream:
                choice = (chunk.get("choices") or [{}])[0]
                delta = choice.get("delta") or {}
                thinking = delta.get("reasoning_content")
                text = delta.get("content")
                if thinking:
                    block = start_plain("thinking")
                    self._sse({"type":"content_block_delta","index":block["index"],"delta":{"type":"thinking_delta","thinking":thinking}}, "content_block_delta")
                for call in (delta.get("tool_calls") or []):
                    if not isinstance(call, dict):
                        raise ClientRequestError("upstream streamed an invalid tool call")
                    block = tool_block(call)
                    fn = call.get("function") or {}
                    args = fn.get("arguments") if isinstance(fn, dict) and isinstance(fn.get("arguments"), str) else ""
                    if args:
                        self._sse({"type":"content_block_delta","index":block["index"],"delta":{"type":"input_json_delta","partial_json":args}}, "content_block_delta")
                if text:
                    block = start_plain("text")
                    self._sse({"type":"content_block_delta","index":block["index"],"delta":{"type":"text_delta","text":text}}, "content_block_delta")
                usage = chunk.get("usage") or usage
            if not stream.receipt_verified:
                raise ClientRequestError("confidential stream ended without a verified receipt")
            close_block(open_block)
            for block in blocks.values():
                close_block(block)
            self._sse({"type":"message_delta","delta":{"stop_reason":"tool_use" if saw_tool else "end_turn","stop_sequence":None},"usage":{"output_tokens":usage.get("completion_tokens",0)}}, "message_delta")
            self._sse({"type":"message_stop"}, "message_stop")
        except (GatewayError, VerificationError, ValueError, OSError) as exc:
            self._sse({"type":"error","error":{"type":"api_error","message":str(exc)}}, "error")

    def _stream_responses(self, stream, model: str):
        self._sse_start(); rid = "resp_" + uuid.uuid4().hex
        self._sse({"type":"response.created","response":{"id":rid,"object":"response","status":"in_progress","model":model,"output":[]}}, "response.created")
        next_index = 0; text_state = None; tools = {}; completed = []

        def start_text():
            nonlocal next_index, text_state
            if text_state is not None:
                return text_state
            text_state = {"id":"msg_" + uuid.uuid4().hex, "index":next_index, "text":""}
            next_index += 1
            self._sse({"type":"response.output_item.added","output_index":text_state["index"],"item":{"id":text_state["id"],"type":"message","status":"in_progress","role":"assistant","content":[]}}, "response.output_item.added")
            self._sse({"type":"response.content_part.added","item_id":text_state["id"],"output_index":text_state["index"],"content_index":0,"part":{"type":"output_text","text":"","annotations":[]}}, "response.content_part.added")
            return text_state

        def start_tool(call):
            nonlocal next_index
            raw_index = call.get("index")
            key = raw_index if isinstance(raw_index, int) else call.get("id")
            if key is None:
                raise ClientRequestError("upstream streamed a tool call without an index or id")
            state = tools.get(key)
            fn = call.get("function") or {}
            name = fn.get("name") if isinstance(fn, dict) and isinstance(fn.get("name"), str) else ""
            call_id = call.get("id") if isinstance(call.get("id"), str) else ""
            if state is None:
                if not name:
                    raise ClientRequestError("upstream streamed a tool argument before its function name")
                call_id = call_id or "call_" + uuid.uuid4().hex
                state = {"id":"fc_" + call_id, "call_id":call_id, "name":name, "index":next_index, "arguments":""}
                next_index += 1
                tools[key] = state
                self._sse({"type":"response.output_item.added","output_index":state["index"],"item":{"id":state["id"],"type":"function_call","status":"in_progress","call_id":call_id,"name":name,"arguments":""}}, "response.output_item.added")
            return state
        try:
            usage = {}
            for chunk in stream:
                choice = (chunk.get("choices") or [{}])[0]
                delta = choice.get("delta") or {}
                text = delta.get("content")
                if text:
                    state = start_text(); state["text"] += text
                    self._sse({"type":"response.output_text.delta","item_id":state["id"],"output_index":state["index"],"content_index":0,"delta":text}, "response.output_text.delta")
                for call in (delta.get("tool_calls") or []):
                    if not isinstance(call, dict):
                        raise ClientRequestError("upstream streamed an invalid tool call")
                    state = start_tool(call)
                    fn = call.get("function") or {}
                    args = fn.get("arguments") if isinstance(fn, dict) and isinstance(fn.get("arguments"), str) else ""
                    if args:
                        state["arguments"] += args
                        self._sse({"type":"response.function_call_arguments.delta","item_id":state["id"],"output_index":state["index"],"delta":args}, "response.function_call_arguments.delta")
                usage = chunk.get("usage") or usage
            if not stream.receipt_verified:
                raise ClientRequestError("confidential stream ended without a verified receipt")
            if text_state is not None:
                item={"id":text_state["id"],"type":"message","status":"completed","role":"assistant","content":[{"type":"output_text","text":text_state["text"],"annotations":[]}]}
                self._sse({"type":"response.output_text.done","item_id":text_state["id"],"output_index":text_state["index"],"content_index":0,"text":text_state["text"]}, "response.output_text.done")
                self._sse({"type":"response.content_part.done","item_id":text_state["id"],"output_index":text_state["index"],"content_index":0,"part":item["content"][0]}, "response.content_part.done")
                self._sse({"type":"response.output_item.done","output_index":text_state["index"],"item":item}, "response.output_item.done")
                completed.append((text_state["index"], item))
            for state in tools.values():
                item={"id":state["id"],"type":"function_call","status":"completed","call_id":state["call_id"],"name":state["name"],"arguments":state["arguments"]}
                self._sse({"type":"response.function_call_arguments.done","item_id":state["id"],"output_index":state["index"],"name":state["name"],"arguments":state["arguments"]}, "response.function_call_arguments.done")
                self._sse({"type":"response.output_item.done","output_index":state["index"],"item":item}, "response.output_item.done")
                completed.append((state["index"], item))
            output=[item for _index, item in sorted(completed)]
            self._sse({"type":"response.completed","response":{"id":rid,"object":"response","status":"completed","model":model,"output":output,"usage":{"input_tokens":usage.get("prompt_tokens",0),"output_tokens":usage.get("completion_tokens",0),"total_tokens":usage.get("total_tokens",0)}}}, "response.completed")
        except (GatewayError, VerificationError, ValueError, OSError) as exc:
            self._sse({"type":"response.failed","response":{"id":rid,"object":"response","status":"failed","error":{"code":"confidential_gateway_error","message":str(exc)}}}, "response.failed")

    def do_GET(self):
        if self.path == "/healthz":
            return self._json(HTTPStatus.OK, {"status": "ok", "bind": "loopback"})
        return self._json(HTTPStatus.NOT_FOUND, {"error": {"message": "Not found"}})

    def do_POST(self):
        path = self.path.split("?", 1)[0]
        # Shape-only request log: method, path, and outcome — never content,
        # headers, or keys. This is the local debugging trail.
        log = getattr(self.server, "logger", None) or (lambda *a: print(*a, flush=True))
        log(f"[gateway] POST {path}")
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
            log(f"[gateway] POST {path} -> {exc.status_code} {exc}")
            self._json(exc.status_code, {"error": {"type": "confidential_gateway_error", "message": str(exc)}})
        except (ValueError, TypeError) as exc:
            log(f"[gateway] POST {path} -> 400 {exc}")
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
