"""Lossless-enough local adapters for common Claude and Responses client flows.

These run only on the caller's loopback gateway.  They turn client request
formats into the OpenAI-compatible request accepted by the attested proxy;
the proxy still receives one canonical request and signs one receipt for its
exact bytes.  Unsupported multimodal/server-state features fail closed rather
than being silently discarded.
"""
from __future__ import annotations

import base64
import hashlib
import json
import time
import uuid
from typing import Any, Mapping

from .core import ClientRequestError


def _text(blocks: Any) -> str:
    if isinstance(blocks, str):
        return blocks
    if not isinstance(blocks, list):
        raise ClientRequestError("content must be text or a list of supported text blocks")
    parts: list[str] = []
    for block in blocks:
        if isinstance(block, Mapping) and block.get("type") in {"thinking", "redacted_thinking"}:
            continue  # thinking blocks are dropped at the confidential boundary
        if not isinstance(block, Mapping) or block.get("type") != "text" or not isinstance(block.get("text"), str):
            raise ClientRequestError("only text content is available through the confidential preview")
        parts.append(block["text"])
    return "\n".join(parts)


def anthropic_to_chat(payload: Mapping[str, Any]) -> dict[str, Any]:
    messages: list[dict[str, Any]] = []
    system = payload.get("system")
    if system:
        messages.append({"role": "system", "content": _text(system)})
    for message in payload.get("messages", []):
        # Claude Code ≥2.1 also carries system-role context entries inside the
        # messages array; accept them alongside user/assistant.
        if not isinstance(message, Mapping) or message.get("role") not in {"user", "assistant", "system"}:
            raise ClientRequestError("Anthropic messages must use user, assistant, or system roles")
        messages.append({"role": message["role"], "content": _text(message.get("content", ""))})
    if not messages:
        raise ClientRequestError("at least one message is required")
    max_tokens = payload.get("max_tokens")
    if isinstance(max_tokens, bool) or not isinstance(max_tokens, int) or max_tokens < 1:
        raise ClientRequestError("Anthropic max_tokens must be a positive integer")
    out: dict[str, Any] = {"messages": messages, "max_tokens": max_tokens}
    for name in ("temperature", "top_p"):
        if name in payload:
            out[name] = payload[name]
    if payload.get("stop_sequences"):
        out["stop"] = payload["stop_sequences"]
    tools = payload.get("tools")
    if tools:
        converted = []
        for tool in tools:
            if not isinstance(tool, Mapping) or not isinstance(tool.get("name"), str):
                raise ClientRequestError("invalid Anthropic tool")
            converted.append({"type": "function", "function": {"name": tool["name"], "description": tool.get("description", ""), "parameters": tool.get("input_schema", {"type": "object"})}})
        out["tools"] = converted
    return out


def chat_to_anthropic(response: Mapping[str, Any], model: str) -> dict[str, Any]:
    choice = (response.get("choices") or [{}])[0]
    if not isinstance(choice, Mapping):
        raise ClientRequestError("confidential endpoint returned invalid completion choices")
    message = choice.get("message") or {}
    content: list[dict[str, Any]] = []
    # GLM-style reasoning rides in reasoning_content; surface it as an
    # Anthropic thinking block so Claude Code renders the reasoning instead of
    # an empty reply. The signature is a local content marker — nothing
    # verifies it, and thinking blocks are dropped on the way back in.
    if isinstance(message, Mapping) and isinstance(message.get("reasoning_content"), str) and message["reasoning_content"]:
        thinking = message["reasoning_content"]
        content.append({"type": "thinking", "thinking": thinking, "signature": base64.b64encode(hashlib.sha256(thinking.encode()).digest()).decode()})
    if isinstance(message, Mapping) and message.get("content"):
        content.append({"type": "text", "text": str(message["content"])})
    for call in (message.get("tool_calls") or []) if isinstance(message, Mapping) else []:
        fn = call.get("function", {}) if isinstance(call, Mapping) else {}
        try:
            args = json.loads(fn.get("arguments") or "{}")
        except (TypeError, ValueError):
            args = {}
        content.append({"type": "tool_use", "id": call.get("id", "toolu_confidential"), "name": fn.get("name", "tool"), "input": args if isinstance(args, dict) else {}})
    if not content:
        content = [{"type": "text", "text": ""}]
    usage = response.get("usage") or {}
    details = usage.get("prompt_tokens_details") or {}
    reason = {"length": "max_tokens", "tool_calls": "tool_use"}.get(choice.get("finish_reason"), "end_turn")
    return {"id": response.get("id", "msg_" + uuid.uuid4().hex), "type": "message", "role": "assistant", "model": response.get("model", model), "content": content, "stop_reason": reason, "stop_sequence": None, "usage": {"input_tokens": usage.get("prompt_tokens", 0), "output_tokens": usage.get("completion_tokens", 0), "cache_read_input_tokens": details.get("cached_tokens", 0)}}


def responses_to_chat(payload: Mapping[str, Any]) -> dict[str, Any]:
    if payload.get("previous_response_id") or payload.get("conversation") or payload.get("background"):
        raise ClientRequestError("server-side Responses state is unavailable; send complete history in input")
    items = payload.get("input", [])
    if isinstance(items, str):
        items = [{"role": "user", "content": items}]
    if not isinstance(items, list):
        raise ClientRequestError("Responses input must be a string or array")
    messages: list[dict[str, Any]] = []
    instructions = payload.get("instructions")
    if instructions:
        messages.append({"role": "system", "content": str(instructions)})
    for item in items:
        if not isinstance(item, Mapping):
            raise ClientRequestError("Responses input items must be objects")
        if item.get("type", "message") != "message":
            raise ClientRequestError("only message input items are available through the confidential preview")
        role = item.get("role", "user")
        if role not in {"user", "assistant", "system", "developer"}:
            raise ClientRequestError("unsupported Responses role")
        content = item.get("content", "")
        if isinstance(content, list):
            texts = []
            for part in content:
                if not isinstance(part, Mapping) or part.get("type") not in {"input_text", "output_text", "text"} or not isinstance(part.get("text"), str):
                    raise ClientRequestError("only text Responses content is available through the confidential preview")
                texts.append(part["text"])
            content = "\n".join(texts)
        if not isinstance(content, str):
            raise ClientRequestError("Responses content must be text")
        messages.append({"role": "system" if role == "developer" else role, "content": content})
    if not messages:
        raise ClientRequestError("at least one input message is required")
    out: dict[str, Any] = {"messages": messages}
    if payload.get("max_output_tokens"):
        out["max_tokens"] = payload["max_output_tokens"]
    for name in ("temperature", "top_p"):
        if name in payload:
            out[name] = payload[name]
    return out


def chat_to_response(response: Mapping[str, Any], model: str) -> dict[str, Any]:
    choice = (response.get("choices") or [{}])[0]
    message = choice.get("message") or {}
    text = message.get("content", "") if isinstance(message, Mapping) else ""
    usage = response.get("usage") or {}
    status = "incomplete" if choice.get("finish_reason") == "length" else "completed"
    return {"id": "resp_" + uuid.uuid4().hex, "object": "response", "created_at": int(time.time()), "status": status, "model": response.get("model", model), "output": [{"id": "msg_" + uuid.uuid4().hex, "type": "message", "status": "completed", "role": "assistant", "content": [{"type": "output_text", "text": str(text), "annotations": []}]}], "usage": {"input_tokens": usage.get("prompt_tokens", 0), "output_tokens": usage.get("completion_tokens", 0), "total_tokens": usage.get("total_tokens", usage.get("prompt_tokens", 0) + usage.get("completion_tokens", 0))}}
