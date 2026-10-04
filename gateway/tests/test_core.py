import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from adverserial_gateway.config import Config
from adverserial_gateway.core import ClientRequestError, Dispatcher


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

    def test_only_canonical_models_can_reach_the_entitlement_exchange(self):
        with self.assertRaises(ClientRequestError):
            self.dispatcher.completion("sk-" + "x" * 24, {"model": "cyberglm", "messages": []})

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
        self.assertEqual(session.call_args.kwargs["api_key"], "signed-entitlement")
        self.assertNotEqual(session.call_args.kwargs["api_key"], entitlement.call_args.args[0])
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
