"""unwrap_fenced_json unit tests (retirement Task 2 trim).

The old fence tests rode the retired strict step client; these exercise
the same provider-convention semantics directly.
"""

import unittest

from lima.cxx_llm import unwrap_fenced_json


class UnwrapFencedJsonTests(unittest.TestCase):
    def test_single_json_fence_is_unwrapped(self):
        raw = "```json\n{\"action\": \"final\"}\n```"
        self.assertEqual("{\"action\": \"final\"}", unwrap_fenced_json(raw))

    def test_bare_fence_is_unwrapped(self):
        raw = "```\n{\"action\": \"tool\"}\n```"
        self.assertEqual("{\"action\": \"tool\"}", unwrap_fenced_json(raw))

    def test_uppercase_json_fence_is_unwrapped(self):
        raw = "```JSON\n{}\n```"
        self.assertEqual("{}", unwrap_fenced_json(raw))

    def test_unfenced_payload_is_unchanged(self):
        raw = '{"action":"final","candidates":[]}'
        self.assertEqual(raw, unwrap_fenced_json(raw))

    def test_prose_around_fence_is_returned_untouched(self):
        raw = "Here is my answer:\n```json\n{}\n```\nHope this helps."
        self.assertEqual(raw, unwrap_fenced_json(raw))

    def test_multiple_fences_are_returned_untouched(self):
        raw = "```json\n{}\n```\n```json\n{}\n```"
        self.assertEqual(raw, unwrap_fenced_json(raw))

    def test_unterminated_fence_is_returned_untouched(self):
        raw = "```json\n{}"
        self.assertEqual(raw, unwrap_fenced_json(raw))

    def test_unusual_opening_language_is_returned_untouched(self):
        raw = "```python\n{}\n```"
        self.assertEqual(raw, unwrap_fenced_json(raw))

    def test_inner_fence_is_returned_untouched(self):
        raw = "```json\n{}\n```\n```\n{}\n```"
        self.assertEqual(raw, unwrap_fenced_json(raw))


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
