"""
Token counting utilities for prompts and LLM responses
"""
from __future__ import annotations

from typing import Optional


def _fallback_token_count(text: str) -> int:
    # Simple heuristic fallback when tiktoken is unavailable
    # Count non-empty whitespace-separated tokens
    return len([w for w in text.split() if w])


def count_tokens(text: str, model_name: Optional[str] = None) -> int:
    """
    Return token count for the given text.

    - Uses tiktoken when available.
    - Falls back to a heuristic word-count when tiktoken is not installed.
    - For unknown models, defaults to cl100k_base which is a good general-purpose approximation.
    """
    try:
        import tiktoken  # type: ignore
    except Exception:
        return _fallback_token_count(text)

    # Try to get model-specific encoding, otherwise fallback to cl100k_base
    enc = None
    if model_name:
        try:
            enc = tiktoken.encoding_for_model(model_name)
        except Exception:
            pass
    if enc is None:
        try:
            enc = tiktoken.get_encoding("cl100k_base")
        except Exception:
            # Shouldn't happen normally, but be safe
            return _fallback_token_count(text)

    try:
        return len(enc.encode(text or ""))
    except Exception:
        return _fallback_token_count(text)
