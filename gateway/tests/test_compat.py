import unittest

from adverserial_gateway.compat import anthropic_to_chat, chat_to_anthropic, chat_to_response, responses_to_chat
from adverserial_gateway.core import ClientRequestError


class CompatibilityTests(unittest.TestCase):
    def test_anthropic_text_is_translated_without_dropping_system(self):
        chat = anthropic_to_chat({"system": "Be precise", "max_tokens": 50, "messages": [{"role": "user", "content": [{"type": "text", "text": "hello"}]}]})
        self.assertEqual(chat["messages"], [{"role": "system", "content": "Be precise"}, {"role": "user", "content": "hello"}])
        self.assertEqual(chat["max_tokens"], 50)

    def test_anthropic_refuses_unrepresentable_content(self):
        with self.assertRaises(ClientRequestError):
            anthropic_to_chat({"max_tokens": 1, "messages": [{"role": "user", "content": [{"type": "image"}]}]})

    def test_responses_maps_developer_and_text_content(self):
        chat = responses_to_chat({"instructions": "top", "input": [{"role": "developer", "content": [{"type": "input_text", "text": "policy"}]}, {"role": "user", "content": "hi"}], "max_output_tokens": 9})
        self.assertEqual(chat["messages"][0], {"role": "system", "content": "top"})
        self.assertEqual(chat["messages"][1], {"role": "system", "content": "policy"})
        self.assertEqual(chat["max_tokens"], 9)

    def test_response_adapters_preserve_usage(self):
        raw = {"id": "chat_1", "model": "lordx64/cyberglm", "choices": [{"message": {"content": "pong"}, "finish_reason": "stop"}], "usage": {"prompt_tokens": 2, "completion_tokens": 1}}
        anthropic = chat_to_anthropic(raw, "lordx64/cyberglm")
        response = chat_to_response(raw, "lordx64/cyberglm")
        self.assertEqual(anthropic["content"][0]["text"], "pong")
        self.assertEqual(response["output"][0]["content"][0]["text"], "pong")
        self.assertEqual(response["usage"]["total_tokens"], 3)
