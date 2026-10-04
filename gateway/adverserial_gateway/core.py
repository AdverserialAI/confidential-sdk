"""Entitlement exchange and direct, pinned confidential dispatch."""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any, Mapping

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
            proof = verify_endpoint(
                self.config.cc_api_url,
                expected_model_id=model,
                trusted_receipt_keys=self.config.receipt_keys,
                issuer=self.config.issuer,
                audience=self.config.audience,
                expected_endpoint=self.config.cc_api_url,
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
        serialized = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        max_input = len(serialized)
        if not 1 <= max_input <= self.config.max_input_tokens:
            raise ClientRequestError("Request exceeds the confidential input policy.")
        requested_output = payload.get("max_tokens", 4096)
        if isinstance(requested_output, bool) or not isinstance(requested_output, int) or requested_output < 1:
            raise ClientRequestError("max_tokens must be a positive integer")
        max_output = min(requested_output, self.config.max_output_tokens)
        proof = self.proof_for(model)
        entitlement = self.entitlement(api_key, model, max_input, max_output, proof)
        outbound = dict(payload)
        outbound.pop("model", None)
        outbound["max_tokens"] = max_output
        session = VerifiedSession(self.config.cc_api_url, proof=proof, api_key=entitlement, timeout=600)
        return session.chat_completions(outbound.pop("messages", []), model=model, **outbound)
