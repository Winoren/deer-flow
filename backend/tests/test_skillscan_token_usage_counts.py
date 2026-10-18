"""Token-usage statistics are counts, while credential bindings remain findings."""

import pytest

from deerflow.skills.review import LocalDirectoryReader, analyze_skill_package
from deerflow.skills.skillscan.orchestrator import scan_skill_dir

COUNT_NAMES = ["total_tokens", "input_tokens", "output_tokens", "prompt_tokens", "completion_tokens", "cached_tokens"]


def scan(tmp_path, text, filename="usage.md"):
    (tmp_path / "SKILL.md").write_text("---\nname: demo\ndescription: Demo skill\n---\nBody.\n", encoding="utf-8")
    (tmp_path / filename).write_text(text, encoding="utf-8")
    return scan_skill_dir(tmp_path)["findings"]


def assignments(findings):
    return [f for f in findings if f["rule_id"] == "secret-env-assignment"]


@pytest.mark.parametrize("name", COUNT_NAMES)
@pytest.mark.parametrize("template", ['{"%s": 84852}', "%s: 84852", "%s=84852", '{"%s": "84852"}'])
def test_numeric_usage_metrics_are_not_credentials(tmp_path, name, template):
    assert assignments(scan(tmp_path, template % name)) == []


@pytest.mark.parametrize("name", ["token", "access_token", "password", "api_key", "secret_total_tokens", "credential"])
def test_numeric_credentials_are_still_reported(tmp_path, name):
    assert len(assignments(scan(tmp_path, f"{name}: 84852"))) == 1


@pytest.mark.parametrize("value", ['"9f8e7d6c5b4a3210ff"', '"84852-not-a-count"', "-84852", "84852.5"])
def test_usage_name_does_not_exempt_non_count_values(tmp_path, value):
    assert len(assignments(scan(tmp_path, '{"total_tokens": ' + value + "}"))) == 1


@pytest.mark.parametrize("same_line", [True, False])
def test_count_does_not_hide_later_credential(tmp_path, same_line):
    text = '{"total_tokens": 84852, "access_token": "9f8e7d6c5b4a3210ff"}' if same_line else "total_tokens: 84852\naccess_token: 9f8e7d6c5b4a3210ff"
    found = assignments(scan(tmp_path, text))
    assert len(found) == 1
    assert found[0]["line"] == (1 if same_line else 2)
    assert "9f8e7d6c5b4a3210ff" not in str(found)


def test_recognized_cloud_token_remains_critical_under_usage_name(tmp_path):
    text = "total_tokens: ghp_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4"
    found = scan(tmp_path, text)
    assert any(f["rule_id"] == "secret-cloud-token" and f["severity"] == "CRITICAL" for f in found)


def test_usage_counts_do_not_fail_package_review(tmp_path):
    scan(tmp_path, '```json\n{"total_tokens": 84852, "input_tokens": 42000}\n```')
    facts = analyze_skill_package(LocalDirectoryReader(tmp_path).read())
    assert not [f for f in facts["findings"] if f["rule_id"] == "secret-env-assignment"]
    assert facts["summary"]["errors"] == 0


def test_long_unrelated_identifier_does_not_become_a_secret(tmp_path):
    assert assignments(scan(tmp_path, "prefix_" * 10000 + "other: 84852")) == []
