"""The closed JSON Schema subset validator (lib/fleet/core/schema.mjs) and the frozen fleet schema set (schemas.mjs).

A schema is compiled once; any keyword this file doesn't implement refuses the schema at load time. Patterns are
limited to what means the same in JavaScript's unicode-mode RegExp and in Python's re: anchored character classes,
literals, `\\.`, and quantifiers; a final `$` is translated to `\\Z` (Python's `$` would also match before a newline).
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from .core import CANON_DEPTH, FleetError, canon, refuse

CANON_MAX = 16 * 1024
FREEZE = {"revision": "r2.4.1", "sha256": "a64b07dd36f9295bc9e75b59ff15ddb466cacd176a74af5a7824992bd42f37c8"}

ANNOTATIONS = {"$comment", "$id", "$schema", "title", "description"}
KNOWN = ANNOTATIONS | {
    "type", "properties", "required", "additionalProperties", "items", "prefixItems", "enum", "const", "pattern",
    "minLength", "maxLength", "minimum", "maximum", "minItems", "maxItems", "uniqueItems", "$ref", "$defs", "oneOf", "not",
}
TYPES = {"object", "array", "string", "integer", "number", "boolean", "null"}
REF = re.compile(r"#/\$defs/[A-Za-z0-9_-]+")
# (a pattern the two engines read alike: no escapes but "\.", no "$" except the last character, no lookaround or flags)
PORTABLE = re.compile(r"(?:[^\\$(]|\\\.|\((?!\?))*\$?")


def _is_int(v) -> bool:
    return isinstance(v, int) and not isinstance(v, bool)


def _same(a, b) -> bool:
    x, _ = canon(a, CANON_MAX)
    y, _ = canon(b, CANON_MAX)
    return x is not None and y is not None and x == y


def _utf16(k: str) -> bytes:
    return k.encode("utf-16-be", "surrogatepass")


def _key(v, depth=0) -> str:
    """uniqueItems' total key (schema.mjs's key): values from parseCanonical, so numbers are safe integers."""
    if v is None:
        return "null"
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, int):
        return ("i:" if abs(v) <= 2**53 - 1 else "f:") + str(v)
    if isinstance(v, float):
        return "f:" + repr(v)
    if isinstance(v, str):
        return json.dumps(v, ensure_ascii=False)
    if depth >= CANON_DEPTH:
        refuse("bad_form", "nested too deeply")
    if isinstance(v, list):
        return "[" + ",".join(_key(x, depth + 1) for x in v) + "]"
    return "{" + ",".join(json.dumps(k, ensure_ascii=False) + ":" + _key(v[k], depth + 1) for k in sorted(v, key=_utf16)) + "}"


def _type_of(v) -> str:
    if v is None:
        return "null"
    if isinstance(v, bool):
        return "boolean"
    if isinstance(v, list):
        return "array"
    if isinstance(v, dict):
        return "object"
    if isinstance(v, str):
        return "string"
    if _is_int(v):
        return "integer" if abs(v) <= 2**53 - 1 else "number"
    if isinstance(v, float):
        return "number"
    return "other"


def _pattern(p: str, at: str):
    if not isinstance(p, str) or PORTABLE.fullmatch(p) is None:
        raise ValueError(f"schema {at}: a pattern outside the portable subset")
    if p.endswith("$"):
        p = p[:-1] + r"\Z"
    return re.compile(p)


def compile_schema(doc):
    """validate(value) -> True, or raises FleetError("bad_form") naming only the schema path that failed."""
    defs = doc.get("$defs", {})
    compiled = {}

    def check(s, at):
        if s is True:
            return lambda v: None
        if not isinstance(s, dict):
            raise ValueError(f"schema {at}: not a schema")
        for k in s:
            if k not in KNOWN:
                raise ValueError(f"schema {at}: unsupported keyword {k}")
        if "additionalProperties" in s and s["additionalProperties"] is not False:
            raise ValueError(f"schema {at}: additionalProperties must be false")
        if "type" in s and s["type"] not in TYPES:
            raise ValueError(f"schema {at}: unsupported type")
        if "$ref" in s and (not isinstance(s["$ref"], str) or REF.fullmatch(s["$ref"]) is None):
            raise ValueError(f"schema {at}: only #/$defs refs")
        steps = []

        def fail():
            refuse("bad_form", f"does not match {at}")

        if s.get("$ref"):
            name = s["$ref"][8:]
            if name not in defs:
                raise ValueError(f"schema {at}: no $defs/{name}")
            steps.append(lambda v, name=name: ref(name)(v))
        t = s.get("type")
        if t == "number":
            steps.append(lambda v: fail() if _type_of(v) not in ("integer", "number") else None)
        elif t:
            steps.append(lambda v: fail() if _type_of(v) != t else None)
        members = list(s.get("enum", [])) + ([s["const"]] if "const" in s else [])
        for e in members:
            if canon(e, CANON_MAX)[0] is None:
                raise ValueError(f"schema {at}: enum/const values must be canonical")
        if "enum" in s:
            steps.append(lambda v: None if any(_same(e, v) for e in s["enum"]) else fail())
        if "const" in s:
            steps.append(lambda v: None if _same(s["const"], v) else fail())
        if s.get("pattern"):
            rx = _pattern(s["pattern"], at)
            steps.append(lambda v: fail() if isinstance(v, str) and rx.search(v) is None else None)
        # (lengths in code points, as JSON Schema counts: a Python str is code points, lone surrogates one each)
        if "minLength" in s:
            steps.append(lambda v: fail() if isinstance(v, str) and len(v) < s["minLength"] else None)
        if "maxLength" in s:
            steps.append(lambda v: fail() if isinstance(v, str) and len(v) > s["maxLength"] else None)
        num = lambda v: _type_of(v) in ("integer", "number")  # noqa: E731
        if "minimum" in s:
            steps.append(lambda v: fail() if num(v) and v < s["minimum"] else None)
        if "maximum" in s:
            steps.append(lambda v: fail() if num(v) and v > s["maximum"] else None)
        if "minItems" in s:
            steps.append(lambda v: fail() if isinstance(v, list) and len(v) < s["minItems"] else None)
        if "maxItems" in s:
            steps.append(lambda v: fail() if isinstance(v, list) and len(v) > s["maxItems"] else None)
        if s.get("uniqueItems"):
            steps.append(lambda v: fail() if isinstance(v, list) and len({_key(x) for x in v}) != len(v) else None)
        if s.get("prefixItems"):
            ps = [check(p, f"{at}/prefixItems/{i}") for i, p in enumerate(s["prefixItems"])]

            def prefix(v):
                if isinstance(v, list):
                    for i, p in enumerate(ps):
                        if i < len(v):
                            p(v[i])

            steps.append(prefix)
        if "items" in s:
            start = len(s["prefixItems"]) if s.get("prefixItems") else 0
            if s["items"] is False:
                steps.append(lambda v: fail() if isinstance(v, list) and len(v) > start else None)
            else:
                it = check(s["items"], f"{at}/items")

                def items(v):
                    if isinstance(v, list):
                        for x in v[start:]:
                            it(x)

                steps.append(items)
        if s.get("properties") or s.get("required") or s.get("additionalProperties") is False:
            props = {k: check(p, f"{at}/properties/{k}") for k, p in s.get("properties", {}).items()}
            req = s.get("required", [])
            closed = s.get("additionalProperties") is False

            def properties(v):
                if not isinstance(v, dict):
                    return
                for k in req:
                    if k not in v:
                        fail()
                for k in v:
                    if k in props:
                        props[k](v[k])
                    elif closed:
                        fail()

            steps.append(properties)
        if s.get("oneOf"):
            alts = [check(a, f"{at}/oneOf/{i}") for i, a in enumerate(s["oneOf"])]

            def one_of(v):
                n = 0
                for a in alts:
                    try:
                        a(v)
                        n += 1
                    except FleetError as e:
                        if e.code != "bad_form":
                            raise
                if n != 1:
                    fail()

            steps.append(one_of)
        if "not" in s:
            no = check(s["not"], f"{at}/not")

            def not_(v):
                try:
                    no(v)
                except FleetError as e:
                    if e.code != "bad_form":
                        raise
                    return
                fail()

            steps.append(not_)

        def run(v):
            for f in steps:
                f(v)

        return run

    def ref(name):
        if name not in compiled:
            holder = {}
            compiled[name] = lambda v: holder["real"](v)  # (a placeholder, so recursive refs compile)
            holder["real"] = check(defs[name], f"#/$defs/{name}")
            compiled[name] = holder["real"]
        return compiled[name]

    for name in defs:
        ref(name)
    root = check({k: v for k, v in doc.items() if k != "$defs"}, "#")

    def validate(value):
        root(value)
        return True

    return validate


class Schemas:
    """The frozen fleet schema set: fleet.schema.json and reasons.json, refused unless they are r2.3's."""

    def __init__(self, directory):
        d = Path(directory)
        fleet = json.loads((d / "fleet.schema.json").read_text(encoding="utf-8"))
        reasons = json.loads((d / "reasons.json").read_text(encoding="utf-8"))
        if not isinstance(fleet.get("$comment"), str) or FREEZE["sha256"] not in fleet["$comment"] or not isinstance(fleet.get("$defs"), dict):
            raise ValueError("fleet.schema.json isn't the frozen revision's")
        if reasons.get("freeze") != FREEZE["sha256"] or not isinstance(reasons.get("reasons"), list):
            raise ValueError("reasons.json isn't the frozen revision's")
        self.fleet = fleet
        self.reasons = tuple(r["name"] for r in reasons["reasons"])
        self._cache = {}

    def body(self, name):
        """The validator for one $defs entry (a body type such as "host-grant")."""
        if name not in self.fleet["$defs"]:
            raise KeyError(f"no fleet schema {name}")
        if name not in self._cache:
            self._cache[name] = compile_schema({"$defs": self.fleet["$defs"], "$ref": f"#/$defs/{name}"})
        return self._cache[name]
