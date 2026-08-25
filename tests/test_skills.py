import hashlib
import hmac
import json
import tempfile
import unittest
from pathlib import Path

from lima.skills import SkillRegistry


class SkillManifestPortabilityTests(unittest.TestCase):
    CANONICAL_SOURCE = b"def create_skill():\n    return None\n"

    def _write_skill(self, root: Path, source: bytes, signing_key: bytes = b"") -> Path:
        skill = root / "portable-skill"
        skill.mkdir()
        (skill / "skill.py").write_bytes(source)
        manifest = {
            "name": "portable-skill",
            "version": "1.0.0",
            "description": "Cross-platform checksum fixture",
            "entrypoint": "skill.py",
            "sha256": hashlib.sha256(self.CANONICAL_SOURCE).hexdigest(),
            "permissions": [],
        }
        if signing_key:
            manifest["signature"] = hmac.new(
                signing_key, self.CANONICAL_SOURCE, hashlib.sha256
            ).hexdigest()
        (skill / "skill.json").write_text(
            json.dumps(manifest), encoding="utf-8"
        )
        return skill

    def test_crlf_checkout_matches_lf_manifest_and_signature(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            key = b"test-signing-key"
            self._write_skill(root, self.CANONICAL_SOURCE.replace(b"\n", b"\r\n"), key)

            registry = SkillRegistry(str(root), signing_key=key.decode("ascii"))

            self.assertEqual("portable-skill", registry.reload()[0]["name"])

    def test_content_change_still_fails_checksum_after_crlf_normalization(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            changed = b"def create_skill():\r\n    return True\r\n"
            self._write_skill(root, changed)

            with self.assertRaisesRegex(ValueError, "skill checksum mismatch"):
                SkillRegistry(str(root)).reload()


if __name__ == "__main__":
    unittest.main()
