"""Shared helpers for coercing model text into schema-valid structured output."""

from __future__ import annotations

import json
from typing import Any

import jsonschema

from .base import ProviderError


def extract_json(text: str) -> dict[str, Any]:
    """Extract the first JSON object from model text (tolerating code fences/prose)."""
    if not text:
        raise ProviderError("empty model response")
    s = text.strip()
    if s.startswith("```"):
        # strip a ```json ... ``` fence
        s = s.split("```", 2)[1] if s.count("```") >= 2 else s
        if s.lstrip().lower().startswith("json"):
            s = s.lstrip()[4:]
    start = s.find("{")
    end = s.rfind("}")
    if start == -1 or end == -1 or end <= start:
        raise ProviderError("no JSON object found in model response")
    try:
        data: dict[str, Any] = json.loads(s[start : end + 1])
    except json.JSONDecodeError as exc:  # pragma: no cover - defensive
        raise ProviderError(f"model response was not valid JSON: {exc}") from exc
    return data


def validate(data: dict[str, Any], schema: dict[str, Any]) -> dict[str, Any]:
    """Validate ``data`` against a JSON schema, raising ProviderError on mismatch."""
    try:
        jsonschema.validate(data, schema)
    except jsonschema.ValidationError as exc:
        raise ProviderError(f"structured output failed schema validation: {exc.message}") from exc
    return data


def schema_instruction(schema: dict[str, Any]) -> str:
    """A system-appended directive telling the model to emit only conforming JSON."""
    return (
        "Respond with a single JSON object and nothing else — no prose, no code fence. "
        "The object MUST conform to this JSON schema:\n"
        f"{json.dumps(schema, separators=(',', ':'))}"
    )
