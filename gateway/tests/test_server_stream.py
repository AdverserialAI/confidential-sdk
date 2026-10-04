import io
import unittest

from adverserial_gateway.server import Handler


class Stream:
    def __init__(self, chunks, verified=True):
        self.chunks = chunks
        self.receipt_verified = verified

    def __iter__(self):
        return iter(self.chunks)


class TestHandler(Handler):
    def __init__(self):
        self.wfile = io.BytesIO()

    def send_response(self, *_args):
        pass

    def send_header(self, *_args):
        pass

    def end_headers(self):
        pass


class GatewayStreamTests(unittest.TestCase):
    def test_openai_emits_done_only_after_verified_receipt(self):
        handler = TestHandler()
        handler._stream_openai(Stream([{"choices": [{"delta": {"content": "pong"}}]}]))
        wire = handler.wfile.getvalue()
        self.assertIn(b'"pong"', wire)
        self.assertTrue(wire.endswith(b"data: [DONE]\n\n"))

    def test_openai_emits_error_when_receipt_is_missing(self):
        handler = TestHandler()
        handler._stream_openai(Stream([{"choices": []}], verified=False))
        wire = handler.wfile.getvalue()
        self.assertIn(b"confidential stream ended without a verified receipt", wire)
        self.assertNotIn(b"data: [DONE]", wire)

    def test_claude_and_responses_streams_emit_native_event_names(self):
        chunk = {"choices": [{"delta": {"content": "pong"}}], "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2}}
        claude = TestHandler(); claude._stream_anthropic(Stream([chunk]), "lordx64/cyberglm")
        responses = TestHandler(); responses._stream_responses(Stream([chunk]), "lordx64/cyberglm")
        self.assertIn(b"event: message_start", claude.wfile.getvalue())
        self.assertIn(b"event: message_stop", claude.wfile.getvalue())
        self.assertIn(b"event: response.created", responses.wfile.getvalue())
        self.assertIn(b"event: response.completed", responses.wfile.getvalue())
