from __future__ import annotations

from pathlib import Path
import tomllib
import unittest

import lima


ROOT = Path(__file__).resolve().parents[1]


class LimaBrandingTests(unittest.TestCase):
    def test_distribution_package_and_version_use_lima_namespace(self) -> None:
        metadata = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
        self.assertEqual("lima-security-agent", metadata["project"]["name"])
        self.assertEqual("1.6.0", lima.__version__)
        self.assertTrue((ROOT / "lima" / "__main__.py").is_file())
        self.assertFalse((ROOT / "evoagent").exists())

    def test_launcher_and_roadmap_use_lima_names(self) -> None:
        self.assertTrue((ROOT / "scripts" / "lima.ps1").is_file())
        self.assertFalse((ROOT / "scripts" / "security-agent.ps1").exists())
        self.assertTrue((ROOT / "LIMA_ROADMAP.md").is_file())
        self.assertFalse((ROOT / "SECURITY_AGENT_ROADMAP.md").exists())

    def test_docker_runtime_uses_lima_service_and_image(self) -> None:
        compose = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
        dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
        self.assertIn("name: lima", compose)
        self.assertIn("  lima:\n    image: lima:local", compose)
        self.assertEqual(2, compose.count("external: true"))
        self.assertIn('CMD ["python", "-m", "lima"]', dockerfile)

    def test_public_brand_and_configuration_prefix_are_lima(self) -> None:
        html = (ROOT / "web" / "index.html").read_text(encoding="utf-8")
        example = (ROOT / ".env.example").read_text(encoding="utf-8")
        self.assertIn("砺码 · LIMA", html)
        self.assertIn("LIMA_LLM_PROVIDER", example)
        self.assertNotIn("EVOAGENT_LLM_PROVIDER", example)
