import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from adverserial_gateway.config import Config
from adverserial_gateway.core import ClientRequestError, Dispatcher, canonical_model_id


class CoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        keys = Path(self.tmp.name) / "keys.json"
        keys.write_text(json.dumps({"kid": {"kty": "EC"}}))
        self.cfg = Config.from_env({
            "ADVERSERIAL_RECEIPT_KEYS_FILE": str(keys),
            "ADVERSERIAL_HARDWARE_VERIFIER_COMMAND": "/bin/true",
        })
        self.dispatcher = Dispatcher(self.cfg)

    def tearDown(self):
        self.tmp.cleanup()

    def test_unknown_models_cannot_reach_the_entitlement_exchange(self):
        with self.assertRaises(ClientRequestError):
            self.dispatcher.completion("sk-" + "x" * 24, {"model": "gpt-5", "messages": []})

    def test_claude_child_model_aliases_resolve_to_canonical_cyberglm(self):
        self.assertEqual(canonical_model_id("claude-haiku-4-5-20251001"), "lordx64/cyberglm")
        self.assertEqual(canonical_model_id("claude-sonnet-4-6"), "lordx64/cyberglm")
        self.assertEqual(canonical_model_id("cyberglm"), "lordx64/cyberglm")

    def test_claude_alias_is_canonicalized_before_proof_entitlement_and_runtime(self):
        proof = object()
        payload = {"model": "claude-haiku-4-5-20251001", "messages": [{"role": "user", "content": "hello"}], "max_tokens": 12}
        with patch.object(self.dispatcher, "proof_for", return_value=proof) as proof_for, patch.object(
            self.dispatcher, "entitlement", return_value="signed-entitlement"
        ) as entitlement, patch("adverserial_gateway.core.VerifiedSession") as session:
            session.return_value.chat_completions.return_value = {"id": "ok"}
            self.dispatcher.completion("sk-" + "x" * 24, payload)
        self.assertEqual(proof_for.call_args.args[0], "lordx64/cyberglm")
        self.assertEqual(entitlement.call_args.args[1], "lordx64/cyberglm")
        self.assertEqual(session.return_value.chat_completions.call_args.kwargs["model"], "lordx64/cyberglm")

    def test_gateway_replaces_api_key_with_entitlement_before_direct_call(self):
        proof = object()
        payload = {"model": "lordx64/cyberglm", "messages": [{"role": "user", "content": "hello"}], "max_tokens": 12}
        with patch.object(self.dispatcher, "proof_for", return_value=proof), patch.object(
            self.dispatcher, "entitlement", return_value="signed-entitlement"
        ) as entitlement, patch("adverserial_gateway.core.VerifiedSession") as session:
            session.return_value.chat_completions.return_value = {"id": "ok"}
            result = self.dispatcher.completion("sk-" + "x" * 24, payload)
        self.assertEqual(result, {"id": "ok"})
        self.assertEqual(entitlement.call_args.args[0], "sk-" + "x" * 24)
        self.assertEqual(session.call_args.kwargs["entitlement"], "signed-entitlement")
        self.assertNotEqual(session.call_args.kwargs["entitlement"], entitlement.call_args.args[0])
        self.assertEqual(session.return_value.chat_completions.call_args.kwargs["model"], "lordx64/cyberglm")

    def test_gateway_forwards_stream_flag_to_verified_session(self):
        proof = object()
        payload = {"model": "lordx64/cyberglm", "messages": [{"role": "user", "content": "hello"}], "max_tokens": 12, "stream": True}
        with patch.object(self.dispatcher, "proof_for", return_value=proof), patch.object(
            self.dispatcher, "entitlement", return_value="signed-entitlement"
        ), patch("adverserial_gateway.core.VerifiedSession") as session:
            stream = object(); session.return_value.chat_completions.return_value = stream
            result = self.dispatcher.completion("sk-" + "x" * 24, payload)
        self.assertIs(result, stream)
        self.assertTrue(session.return_value.chat_completions.call_args.kwargs["stream"])


if __name__ == "__main__":
    unittest.main()
