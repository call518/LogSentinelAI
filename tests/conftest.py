from pathlib import Path
import sys

import pytest


@pytest.fixture()
def configured_project(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Import LogSentinelAI against a temporary local config file."""
    (tmp_path / ".env").write_text(
        "\n".join(
            [
                f"LOG_FILE={tmp_path / 'logsentinelai.log'}",
                "LLM_PROVIDER=openai",
                "TELEGRAM_ENABLED=false",
            ]
        ),
        encoding="utf-8",
    )
    monkeypatch.chdir(tmp_path)

    for module_name in list(sys.modules):
        if module_name == "logsentinelai" or module_name.startswith("logsentinelai."):
            sys.modules.pop(module_name)

    return tmp_path
