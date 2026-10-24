"""Publish a GitHub Release after package publication has succeeded."""

import argparse
import json
import os
import re
import subprocess
import tempfile
from pathlib import Path
from urllib.parse import quote


def command(*args: str) -> str:
    """Run arguments without interpreting commit messages as shell code."""
    return subprocess.run(
        args, check=True, capture_output=True, text=True
    ).stdout.strip()


def release_notes(repository: str, tag: str, previous: str | None) -> str:
    """Collect full commit messages in oldest-first topological order."""
    current = command("git", "rev-parse", "--verify", f"refs/tags/{tag}^{{commit}}")
    revision = current
    if previous:
        base = command(
            "git", "rev-parse", "--verify", f"refs/tags/{previous}^{{commit}}"
        )
        command("git", "merge-base", "--is-ancestor", base, current)
        revision = f"{base}..{current}"
    raw = command(
        "git",
        "log",
        "--reverse",
        "--topo-order",
        "--format=%H%x00%B%x00",
        revision,
        "--",
    )
    parts = raw.split("\0")
    notes = [
        f"## {tag}",
        f"Changes since {previous}." if previous else "Initial release.",
        "",
    ]
    for index in range(0, len(parts) - 1, 2):
        sha, message = parts[index].strip(), parts[index + 1].strip()
        fence = "`" * max(
            3, max((len(m) + 1 for m in re.findall(r"`+", message)), default=3)
        )
        notes.extend(
            [
                f"### [{sha[:7]}](https://github.com/{repository}/commit/{sha})",
                f"{fence}text",
                message,
                fence,
                "",
            ]
        )
    if previous:
        notes.append(
            f"[Full Changelog](https://github.com/{repository}/compare/"
            f"{quote(previous, safe='')}...{quote(tag, safe='')})"
        )
    return "\n".join(notes) + "\n"


def publish_release(repository: str, tag: str) -> None:
    """Create a release once, using the last published release as the baseline."""
    if not re.fullmatch(r"[0-9]+(?:\.[0-9]+)*", tag):
        raise ValueError("Release tags must contain dot-separated numbers.")
    current = command("git", "rev-parse", "--verify", f"refs/tags/{tag}^{{commit}}")
    remote = command("gh", "api", f"repos/{repository}/commits/{tag}", "--jq", ".sha")
    if current != remote or current != command("git", "rev-parse", "HEAD"):
        raise ValueError(
            "The remote tag, local tag, and checked-out commit must match."
        )
    pages = json.loads(
        command(
            "gh",
            "api",
            "--paginate",
            "--slurp",
            f"repos/{repository}/releases?per_page=100",
        )
    )
    releases = [release for page in pages for release in page]
    existing = next((r for r in releases if r["tag_name"] == tag), None)
    if existing:
        if existing["draft"]:
            raise ValueError("A draft already exists for this tag; review it manually.")
        print(f"Release {tag} already exists; leaving its content unchanged.")
        return
    published = [r for r in releases if not r["draft"]]
    previous = (
        max(published, key=lambda r: r["published_at"])["tag_name"]
        if published
        else None
    )
    notes = release_notes(repository, tag, previous)
    with tempfile.TemporaryDirectory(prefix="logsentinelai-release-") as temporary:
        path = Path(temporary) / "release-notes.md"
        path.write_text(notes, encoding="utf-8")
        command(
            "gh",
            "release",
            "create",
            tag,
            "--repo",
            repository,
            "--verify-tag",
            "--title",
            tag,
            "--notes-file",
            str(path),
        )
    print(f"Published GitHub Release {tag} (previous release: {previous or 'none'}).")


def main() -> None:
    """Publish only when explicitly called by the final release job."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("tag")
    args = parser.parse_args()
    try:
        publish_release(os.environ["GITHUB_REPOSITORY"], args.tag)
    except subprocess.CalledProcessError as error:
        parser.exit(1, f"Release command failed: {error.stderr or error}\n")
    except (ValueError, KeyError, OSError) as error:
        parser.exit(1, f"GitHub Release failed: {error}\n")


if __name__ == "__main__":
    main()
