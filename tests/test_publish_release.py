"""Verify release notes and publication without contacting GitHub."""

import importlib.util
import json
from pathlib import Path
from unittest.mock import Mock

import pytest

SPEC = importlib.util.spec_from_file_location(
    "publish_release", Path(__file__).parents[1] / "scripts" / "publish_release.py"
)
assert SPEC is not None and SPEC.loader is not None
release = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(release)


@pytest.mark.parametrize("previous", [None, "1.0.0"])
def test_notes_preserve_full_messages_and_commit_range(monkeypatch, previous):
    message = "Fix release\n\n```sh\n$(echo unsafe)\n```"
    raw = f"{'a' * 40}\0{message}\0\n{'b' * 40}\0Second commit\0"
    command = Mock(
        side_effect=["current", "base", "", raw] if previous else ["current", raw]
    )
    monkeypatch.setattr(release, "command", command)

    notes = release.release_notes("owner/repo", "1.1.0", previous)

    assert message in notes
    assert "````text" in notes
    assert notes.index("aaaaaaa") < notes.index("bbbbbbb")
    assert command.call_args.args[-2:] == (
        "base..current" if previous else "current",
        "--",
    )
    assert ("Full Changelog" in notes) == bool(previous)


def test_publication_uses_latest_published_release_and_notes_file(monkeypatch):
    releases = [
        [
            {"tag_name": "1.0.0", "draft": False, "published_at": "2026-01-01"},
            {"tag_name": "1.1.0", "draft": False, "published_at": "2026-02-01"},
            {"tag_name": "1.9.0", "draft": True, "published_at": None},
        ]
    ]
    calls = []

    def command(*args):
        calls.append(args)
        if args[:3] == ("gh", "release", "create"):
            assert Path(args[-1]).read_text(encoding="utf-8") == "release notes"
            assert "--verify-tag" in args
            return ""
        if "--paginate" in args:
            return json.dumps(releases)
        return "current"

    notes = Mock(return_value="release notes")
    monkeypatch.setattr(release, "command", command)
    monkeypatch.setattr(release, "release_notes", notes)

    release.publish_release("owner/repo", "1.2.0")

    notes.assert_called_once_with("owner/repo", "1.2.0", "1.1.0")
    assert calls[-1][:4] == ("gh", "release", "create", "1.2.0")


@pytest.mark.parametrize("draft", [False, True])
def test_existing_release_is_not_overwritten(monkeypatch, draft):
    command = Mock(
        side_effect=[
            "current",
            "current",
            "current",
            json.dumps([[{"tag_name": "1.2.0", "draft": draft}]]),
        ]
    )
    monkeypatch.setattr(release, "command", command)
    if draft:
        with pytest.raises(ValueError, match="draft"):
            release.publish_release("owner/repo", "1.2.0")
    else:
        release.publish_release("owner/repo", "1.2.0")
    assert command.call_count == 4


def test_mismatched_remote_tag_prevents_publication(monkeypatch):
    command = Mock(side_effect=["local", "remote"])
    monkeypatch.setattr(release, "command", command)
    with pytest.raises(ValueError, match="must match"):
        release.publish_release("owner/repo", "1.2.0")
    assert command.call_count == 2
