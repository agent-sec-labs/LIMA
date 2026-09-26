import hashlib
import hmac
import unittest

from lima.github import pull_request_commit_shas, verify_signature

HEAD = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"
BASE = "f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1"


def payload(head=HEAD, base=BASE):
    return {
        "action": "opened",
        "number": 7,
        "pull_request": {
            "head": {"ref": "feature/x", "sha": head},
            "base": {"ref": "main", "sha": base},
        },
        "repository": {"full_name": "org/repo"},
    }


class GitHubSignatureTests(unittest.TestCase):
    def test_signature_verification(self):
        body = b'{"ok":true}'
        signature = "sha256=" + hmac.new(b"secret", body, hashlib.sha256).hexdigest()
        self.assertTrue(verify_signature("secret", body, signature))
        self.assertFalse(verify_signature("wrong", body, signature))


class PullRequestCommitShaTests(unittest.TestCase):
    def test_extracts_head_and_base_sha(self):
        self.assertEqual((HEAD, BASE), pull_request_commit_shas(payload()))

    def test_missing_sha_is_rejected(self):
        with self.assertRaises(ValueError):
            pull_request_commit_shas(payload(head=None))
        with self.assertRaises(ValueError):
            pull_request_commit_shas(payload(base=""))

    def test_branch_ref_is_never_accepted_as_sha(self):
        with self.assertRaises(ValueError):
            pull_request_commit_shas(payload(head="feature/uaf"))
        with self.assertRaises(ValueError):
            pull_request_commit_shas(payload(base="main"))

    def test_short_or_uppercase_sha_is_rejected(self):
        with self.assertRaises(ValueError):
            pull_request_commit_shas(payload(head=HEAD[:39]))
        with self.assertRaises(ValueError):
            pull_request_commit_shas(payload(base=BASE.upper()))

    def test_malformed_payload_is_rejected(self):
        with self.assertRaises(ValueError):
            pull_request_commit_shas({})
        with self.assertRaises(ValueError):
            pull_request_commit_shas({"pull_request": "opened"})
        with self.assertRaises(ValueError):
            pull_request_commit_shas({"pull_request": {"head": HEAD, "base": BASE}})
        with self.assertRaises(ValueError):
            pull_request_commit_shas(None)


if __name__ == "__main__":
    unittest.main()
