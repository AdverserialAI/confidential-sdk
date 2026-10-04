import json
import tempfile
import unittest
from pathlib import Path

from adverserial_gateway.config import Config, ConfigError


class ConfigTests(unittest.TestCase):
    def test_loopback_and_required_verifier(self):
        with tempfile.TemporaryDirectory() as tmp:
            keys = Path(tmp) / "keys.json"
            keys.write_text(json.dumps({"kid": {"kty": "EC"}}))
            env = {"ADVERSERIAL_RECEIPT_KEYS_FILE": str(keys), "ADVERSERIAL_HARDWARE_VERIFIER_COMMAND": "/bin/true"}
            cfg = Config.from_env(env)
            self.assertEqual(cfg.listen_host, "127.0.0.1")
            self.assertEqual(cfg.max_output_tokens, 65536)
            with self.assertRaises(ConfigError):
                Config.from_env({**env, "ADVERSERIAL_GATEWAY_HOST": "0.0.0.0"})
            with self.assertRaises(ConfigError):
                Config.from_env({k: v for k, v in env.items() if k != "ADVERSERIAL_HARDWARE_VERIFIER_COMMAND"})


if __name__ == "__main__":
    unittest.main()
