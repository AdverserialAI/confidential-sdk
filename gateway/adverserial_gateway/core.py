"""Entitlement exchange and direct, pinned confidential dispatch."""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any, Mapping
from urllib.parse import urlsplit

from adverserial import VerificationError, VerifiedProof, VerifiedSession, verify_endpoint

from .config import CANONICAL_MODELS, Config
from .hardware import verifier_from_command


class GatewayError(RuntimeError):
    status_code = 502


class ClientRequestError(GatewayError):
    status_code = 400


class AuthorizationError(GatewayError):
    status_code = 401


class VerificationFailed(GatewayError):
    status_code = 503


@dataclass
class ProofCache:
    proof: VerifiedProof | None = None

    def fresh_for(self, model: str) -> bool:
        return self.proof is not None and self.proof.model_id == model and self.proof.expires_epoch > int(time.time()) + 15


class Dispatcher:
    def __init__(self, config: Config):
        self.config = config
        self._proofs: dict[str, ProofCache] = {model: ProofCache() for model in CANONICAL_MODELS}

    def proof_for(self, model: str) -> VerifiedProof:
        if model not in CANONICAL_MODELS:
            raise ClientRequestError("Use a canonical confidential model ID: lordx64/cyberglm or lordx64/cyberkimi.")
        cached = self._proofs[model]
        if cached.fresh_for(model):
            return cached.proof  # type: ignore[return-value]
        try:
            # The proxy signs the receipt's endpoint claim with the bare origin
            # (e.g. https://api.adverserial.ai), while cc_api_url carries the
            # /v1 suffix for the OpenAI API; compare against the origin.
            parts = urlsplit(self.config.cc_api_url)
            expected_endpoint = f"{parts.scheme}://{parts.netloc}"
            proof = verify_endpoint(
                self.config.cc_api_url,
                expected_model_id=model,
                trusted_receipt_keys=self.config.receipt_keys,
                issuer=self.config.issuer,
                audience=self.config.audience,
                expected_endpoint=expected_endpoint,
                hardware_verifier=verifier_from_command(self.config.hardware_verifier_command),
            )
        except VerificationError as exc:
            raise VerificationFailed(f"Confidential endpoint verification failed: {exc}") from exc
        if proof.dev_mode:
            raise VerificationFailed("Confidential endpoint exposed synthetic dev-mode evidence.")
        cached.proof = proof
        return proof

    def entitlement(self, api_key: str, model: str, max_input_tokens: int, max_output_tokens: int, proof: VerifiedProof) -> str:
        payload = json.dumps({
            "model": model,
            "max_input_tokens": max_input_tokens,
            "max_output_tokens": max_output_tokens,
            "endpoint_spki_sha256": proof.tls_spki_sha256,
        }).encode()
        request = urllib.request.Request(
            self.config.billing_url + "/cc/entitlements",
            data=payload,
            method="POST",
            headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json", "Accept": "application/json"},
        )
        try:
            with urllib.request.urlopen(request, timeout=15) as response:
                body = response.read(64 * 1024)
        except urllib.error.HTTPError as exc:
            detail = exc.read(1024).decode("utf-8", "replace")
            if exc.code in {401, 403, 429}:
                error = AuthorizationError(detail or "Billing denied the confidential request.")
                error.status_code = exc.code
                raise error
            raise GatewayError("Billing entitlement service failed.") from exc
        except OSError as exc:
            raise GatewayError("Billing entitlement service is unavailable.") from exc
        try:
            result = json.loads(body)
            entitlement = result["entitlement"]
        except (ValueError, KeyError, TypeError) as exc:
            raise GatewayError("Billing returned an invalid confidential entitlement.") from exc
        if not isinstance(entitlement, str) or len(entitlement) > 16_384:
            raise GatewayError("Billing returned an invalid confidential entitlement.")
        return entitlement

    def completion(self, api_key: str, payload: Mapping[str, Any]):
        model = payload.get("model")
        if not isinstance(model, str):
            raise ClientRequestError("model is required")
        if not api_key.startswith("sk-") or len(api_key) < 20:
            raise AuthorizationError("A normal Adverserial API key is required.")
        # The JSON wire body is a safe upper bound on token count for text JSON:
        # a byte-level tokenizer cannot produce more than one token per UTF-8 byte.
        # The SDK re-serializes the payload before sending (adding "stream" and
        # its own separators), so reserve with headroom; the proxy bounds the
        # actual received body and settlement charges actual usage only.
        serialized = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        max_input = 2 * len(serialized) + 4096
        if not 1 <= max_input <= self.config.max_input_tokens:
            raise ClientRequestError(f"Request exceeds the confidential input policy: {max_input} bytes reserved (limit {self.config.max_input_tokens}).")
        requested_output = payload.get("max_tokens", 4096)
        if isinstance(requested_output, bool) or not isinstance(requested_output, int) or requested_output < 1:
            raise ClientRequestError("max_tokens must be a positive integer")
        max_output = min(requested_output, self.config.max_output_tokens)
        proof = self.proof_for(model)
        entitlement = self.entitlement(api_key, model, max_input, max_output, proof)
        outbound = dict(payload)
        outbound.pop("model", None)
        stream = bool(outbound.pop("stream", False))
        outbound["max_tokens"] = max_output
        session = VerifiedSession(self.config.cc_api_url, proof=proof, entitlement=entitlement, timeout=600)
        try:
            return session.chat_completions(outbound.pop("messages", []), model=model, stream=stream, **outbound)
        except Exception as exc:
            # Release the billing reservation only when the request provably
            # never ran at the enclave: local setup failures, or a 4xx from
            # the gate (the request was rejected before any generation, so no
            # meter event will arrive to settle it). Never release after a
            # 5xx/timeout/stream break — the meter may still settle, and a
            # released-then-settled reservation poisons the proxy outbox.
            message = str(exc)
            pre_send = isinstance(exc, (TypeError, ValueError)) or "EHBP" in message or "entitlement" in message
            rejected = "failed with HTTP 4" in message
            if pre_send or rejected:
                self.release_reservation(api_key, entitlement)
            raise

    def release_reservation(self, api_key: str, entitlement: str) -> None:
        """Best-effort release of the billing reservation behind a minted
        entitlement (its jti is the reservation id). Never raises."""
        try:
            parts = entitlement.split(".")
            if len(parts) != 3:
                return
            import base64 as _b64
            claims = json.loads(_b64.urlsafe_b64decode(parts[1] + "=" * (-len(parts[1]) % 4)))
            reservation_id = claims.get("jti")
            if not isinstance(reservation_id, str) or not reservation_id:
                return
            request = urllib.request.Request(
                self.config.billing_url + "/cc/release",
                data=json.dumps({"reservation_id": reservation_id}).encode(),
                method="POST",
                headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
            )
            with urllib.request.urlopen(request, timeout=10):
                pass
        except Exception:
            pass

    def adapted_completion(self, api_key: str, model: str, payload: Mapping[str, Any]):
        """Dispatch a locally translated request after binding it to a canonical model."""
        outbound = dict(payload)
        outbound["model"] = model
        return self.completion(api_key, outbound)
