from importlib.metadata import version

import pytest


def _version_tuple(version_text: str) -> tuple[int, ...]:
    return tuple(int(part) for part in version_text.split(".") if part.isdigit())


def test_security_dependency_updates_keep_runtime_importable() -> None:
    import outlines
    import paramiko
    import setuptools

    assert outlines is not None
    assert _version_tuple(paramiko.__version__) >= (5, 0, 0)
    assert _version_tuple(setuptools.__version__) >= (83, 0, 0)
    assert version("outlines")


def test_chunked_iterable_preserves_lines(configured_project) -> None:
    from logsentinelai.utils.general import chunked_iterable

    chunks = list(chunked_iterable(["one\n", "two", "three\n"], 2))

    assert chunks == [["one\n", "two\n"], ["three\n"]]


def test_prompt_templates_cover_supported_log_types(configured_project) -> None:
    from logsentinelai.core.prompts import (
        get_general_log_prompt,
        get_httpd_access_prompt,
        get_httpd_server_error_prompt,
        get_linux_system_prompt,
    )

    prompts = [
        get_httpd_access_prompt(),
        get_httpd_server_error_prompt(),
        get_linux_system_prompt(),
        get_general_log_prompt(),
    ]

    for prompt in prompts:
        assert "{model_schema}" in prompt
        assert "{response_language}" in prompt
        assert "<LOGS BEGIN>" in prompt
        assert "<LOGS END>" in prompt


def test_cli_ssh_arguments_are_validated_and_parsed(configured_project) -> None:
    from logsentinelai.core.commons import (
        create_argument_parser,
        get_log_path_from_args,
        get_remote_mode_from_args,
        parse_ssh_config_from_args,
        validate_args,
    )

    parser = create_argument_parser("smoke")
    args = parser.parse_args(
        [
            "--remote",
            "--ssh",
            "alice@example.com:2222",
            "--ssh-key",
            "/tmp/id_ed25519",
            "--log-path",
            "/var/log/auth.log",
        ]
    )

    validate_args(args)

    assert get_remote_mode_from_args(args) == "ssh"
    assert get_log_path_from_args(args) == "/var/log/auth.log"
    assert parse_ssh_config_from_args(args) == {
        "user": "alice",
        "host": "example.com",
        "port": 2222,
        "key_path": "/tmp/id_ed25519",
    }


def test_remote_cli_requires_authentication(configured_project) -> None:
    from logsentinelai.core.commons import create_argument_parser, validate_args

    parser = create_argument_parser("smoke")
    args = parser.parse_args(["--remote", "--ssh", "alice@example.com"])

    with pytest.raises(ValueError, match="Either --ssh-key or --ssh-password"):
        validate_args(args)


def test_raw_response_debug_handles_empty_response(
    configured_project,
    capsys: pytest.CaptureFixture[str],
) -> None:
    from logsentinelai.core.commons import print_raw_response_debug

    print_raw_response_debug("", max_preview_chars=20)

    output = capsys.readouterr().out
    assert "(empty response)" in output
    assert "Response length: 0 characters" in output


def test_raw_response_debug_shows_error_context(
    configured_project,
    capsys: pytest.CaptureFixture[str],
) -> None:
    import json

    from logsentinelai.core.commons import print_raw_response_debug

    raw_response = '{"summary": "unfinished'
    try:
        json.loads(raw_response)
    except json.JSONDecodeError as error:
        print_raw_response_debug(raw_response, error, max_preview_chars=20)

    output = capsys.readouterr().out
    assert '{"summary": "unfinis' in output
    assert "Response length: 23 characters" in output
    assert "Error position:" in output


def test_ollama_reasoning_effort_is_passed_when_configured(
    configured_project,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from logsentinelai.core import llm

    captured: dict[str, object] = {}

    def fake_model(prompt, model_class, **kwargs):
        captured.update(kwargs)
        return '{"ok": true}'

    monkeypatch.setitem(llm.LLM_REASONING_EFFORT, "ollama", "none")

    assert llm.generate_with_model(fake_model, "prompt", dict, "ollama")
    assert captured["reasoning_effort"] == "none"


@pytest.mark.parametrize(
    ("module_name", "log_type"),
    [
        ("logsentinelai.analyzers.httpd_access", "httpd_access"),
        ("logsentinelai.analyzers.httpd_server", "httpd_server"),
        ("logsentinelai.analyzers.linux_system", "linux_system"),
        ("logsentinelai.analyzers.general_log", "general_log"),
    ],
)
def test_analyzer_batch_main_passes_chunk_size(
    configured_project,
    monkeypatch: pytest.MonkeyPatch,
    module_name: str,
    log_type: str,
) -> None:
    import importlib
    import sys

    module = importlib.import_module(module_name)
    captured: dict[str, object] = {}

    def fake_batch_analysis(**kwargs) -> None:
        captured.update(kwargs)

    monkeypatch.setattr(module, "run_generic_batch_analysis", fake_batch_analysis)
    monkeypatch.setattr(module, "handle_ssh_arguments", lambda args: None)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            module_name,
            "--mode",
            "batch",
            "--log-path",
            "./sample-logs/access-100.log",
            "--chunk-size",
            "3",
        ],
    )

    assert module.main() is None
    assert captured["log_type"] == log_type
    assert captured["chunk_size"] == 3


def test_analyzer_models_validate_minimum_structured_results(
    configured_project,
) -> None:
    from logsentinelai.analyzers import (
        general_log,
        httpd_access,
        httpd_server,
        linux_system,
    )

    httpd_access.LogAnalysis.model_validate(
        {
            "summary": "normal access traffic",
            "events": [
                {
                    "event_type": "normal_traffic",
                    "severity": "INFO",
                    "related_logs": ["127.0.0.1 - - GET / HTTP/1.1 200"],
                    "description": "routine request",
                    "confidence_score": 0.9,
                    "url_pattern": "/",
                    "http_method": "GET",
                    "source_ips": ["127.0.0.1"],
                    "response_codes": ["200"],
                    "attack_patterns": ["UNKNOWN"],
                    "recommended_actions": ["continue monitoring"],
                    "requires_human_review": False,
                }
            ],
            "statistics": {
                "total_requests": 1,
                "unique_ips": 1,
                "error_rate": 0.0,
                "response_code_dist": ["200:1"],
            },
            "highest_severity": "INFO",
            "requires_immediate_attention": False,
        }
    )

    httpd_server.LogAnalysis.model_validate(
        {
            "summary": "server notice",
            "events": [
                {
                    "event_type": "startup",
                    "severity": "INFO",
                    "related_logs": ["[notice] Apache started"],
                    "description": "normal startup",
                    "confidence_score": 0.8,
                    "file_path": None,
                    "source_ips": [],
                    "attack_patterns": ["UNKNOWN"],
                    "recommended_actions": ["continue monitoring"],
                    "requires_human_review": False,
                }
            ],
            "statistics": {
                "total_event": 1,
                "event_by_level": ["INFO:1"],
                "event_by_type": ["startup:1"],
            },
            "highest_severity": "INFO",
            "requires_immediate_attention": False,
        }
    )

    linux_system.LogAnalysis.model_validate(
        {
            "summary": "routine system activity",
            "events": [
                {
                    "event_type": "SYSTEM_EVENT",
                    "severity": "INFO",
                    "related_logs": ["systemd[1]: Started service"],
                    "description": "normal service start",
                    "confidence_score": 0.8,
                    "source_ips": [],
                    "username": None,
                    "process": "systemd",
                    "service": "example",
                    "recommended_actions": ["continue monitoring"],
                    "requires_human_review": False,
                }
            ],
            "statistics": {
                "total_events": 1,
                "auth_failures": 0,
                "unique_ips": 0,
                "unique_users": 0,
                "event_by_type": ["SYSTEM_EVENT:1"],
            },
            "highest_severity": "INFO",
            "requires_immediate_attention": False,
        }
    )

    general_log.LogAnalysis.model_validate(
        {
            "events": [
                {
                    "category": "SYSTEM",
                    "severity": "INFO",
                    "related_logs": ["service started"],
                    "description": "normal event",
                    "confidence_score": 0.8,
                    "source_ips": [],
                    "pattern_type": "Plain Text",
                    "recommended_actions": ["continue monitoring"],
                    "requires_human_review": False,
                }
            ],
            "detected_formats": ["Plain Text"],
            "timestamp_patterns": [],
            "common_fields": ["message"],
            "log_sources": ["app"],
            "statistics_event": {
                "total_events": 1,
                "security_events": 0,
                "error_events": 0,
                "warning_events": 0,
                "performance_events": 0,
                "access_events": 0,
                "authentication_events": 0,
                "authorization_events": 0,
                "network_events": 0,
                "database_events": 0,
                "application_events": 0,
                "system_events": 1,
                "user_action_events": 0,
                "business_logic_events": 0,
                "unknown_events": 0,
            },
            "statistics_severity": {
                "critical_events": 0,
                "high_events": 0,
                "medium_events": 0,
                "low_events": 0,
                "info_events": 1,
            },
            "unique_sources": 1,
            "requires_human_review_count": 0,
            "analysis_summary": "normal event",
            "recommendations": ["continue monitoring"],
        }
    )
