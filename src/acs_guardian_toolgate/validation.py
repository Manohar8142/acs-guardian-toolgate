# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Rayavarapu Manohar
"""JSON Schema validation against the vendored ACS v0.1.0 schemas.

Every schema file under ``schemas/v0.1.0`` is registered by its ``$id`` so the
relative ``$ref``s inside them (``handshake.json#/$defs/ServerHello``,
``../provenance.json``) resolve exactly the way the published schemas do.
"""

from __future__ import annotations

import json
import re
from functools import lru_cache
from importlib import resources
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry, Resource
from referencing.jsonschema import DRAFT202012

SCHEMA_BASE = "https://genai-security-project.github.io/agent-control-standard/schema/v0.1.0/"
SPEC_VERSION = "0.1.0"


def _schema_root():
    return resources.files("acs_guardian_toolgate") / "schemas" / "v0.1.0"


def _iter_schema_files(node, prefix=""):
    for child in node.iterdir():
        if child.is_dir():
            yield from _iter_schema_files(child, f"{prefix}{child.name}/")
        elif child.name.endswith(".json"):
            yield f"{prefix}{child.name}", child


@lru_cache(maxsize=1)
def _registry() -> tuple[Registry, dict[str, dict]]:
    by_path: dict[str, dict] = {}
    registry = Registry()
    for rel, file in _iter_schema_files(_schema_root()):
        doc = json.loads(file.read_text(encoding="utf-8"))
        by_path[rel] = doc
        uri = doc.get("$id", SCHEMA_BASE + rel)
        registry = registry.with_resource(uri, Resource.from_contents(doc, default_specification=DRAFT202012))
    return registry, by_path


_FORMAT_CHECKER = FormatChecker()


@lru_cache(maxsize=None)
def _validator(ref: str) -> Draft202012Validator:
    """``ref`` is a path relative to the v0.1.0 directory, optionally with a JSON pointer fragment."""
    registry, _ = _registry()
    schema = {"$ref": SCHEMA_BASE + ref}
    return Draft202012Validator(schema, registry=registry, format_checker=_FORMAT_CHECKER)


def errors(ref: str, instance: Any) -> list[str]:
    """Return human-readable validation errors (empty list = valid)."""
    out = []
    for err in sorted(_validator(ref).iter_errors(instance), key=lambda e: list(e.absolute_path)):
        path = "/".join(str(p) for p in err.absolute_path) or "<root>"
        out.append(f"{path}: {err.message}")
    return out


def _kebab(name: str) -> str:
    return re.sub(r"(?<!^)(?=[A-Z])", "-", name).lower()


def payload_schema_for(method: str, provenance_profile: bool = False) -> str | None:
    """The hook payload schema for a method, or None when v0.1.0 defines none."""
    _, by_path = _registry()
    if method.startswith("steps/"):
        base = "hooks/" + _kebab(method[len("steps/"):])
    elif method == "system/ping":
        base = "hooks/system-ping"
    elif method in ("agbom/snapshot", "agbom/changed"):
        base = "hooks/agbom-" + method.split("/", 1)[1]
    else:
        return None
    if provenance_profile and f"{base}.acs-provenance.json" in by_path:
        return f"{base}.acs-provenance.json"
    return f"{base}.json" if f"{base}.json" in by_path else None


def request_errors(envelope: Any, provenance_profile: bool = False, payload_methods=None) -> list[str]:
    """Envelope errors, then hook-payload errors. ``payload_methods`` limits which
    methods get their payload checked (a Guardian checks payloads it evaluates)."""
    errs = errors("request-envelope.json", envelope)
    if errs:
        return errs
    method = envelope["method"]
    if payload_methods is not None and method not in payload_methods:
        return []
    payload = envelope["params"]["payload"]
    if method == "handshake/hello":
        return [f"payload/{e}" for e in errors("handshake.json#/$defs/ClientHello", payload)]
    ref = payload_schema_for(method, provenance_profile)
    if ref is not None:
        return [f"payload/{e}" for e in errors(ref, payload)]
    return []


def response_errors(envelope: Any) -> list[str]:
    return errors("response-envelope.json", envelope)


def known_step_methods() -> set[str]:
    """steps/* methods v0.1.0 defines a payload schema for."""
    _, by_path = _registry()
    out = set()
    for rel in by_path:
        if rel.startswith("hooks/") and not rel.endswith(".acs-provenance.json"):
            stem = rel[len("hooks/"):-len(".json")]
            if stem in ("system-ping", "agbom-snapshot", "agbom-changed"):
                continue
            parts = stem.split("-")
            out.add("steps/" + parts[0] + "".join(p.title() for p in parts[1:]))
    return out
