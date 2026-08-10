#!/usr/bin/env python3
"""NULL-discipline gate.

NULL means that no object exists.  This gate rejects NULL callback slots and
ratchets decoded-string guards through a reviewed, per-occurrence inventory.
The inventory is intentionally permissive about removals: eliminating a guard
after establishing its producer contract is progress.  It rejects only new,
unclassified guards, where a reviewer would otherwise have no record of which
NULL contract is being preserved.

  --report     show decoded-null records grouped by classification
  --self-test  prove callable detection and the decoded-null ratchet
"""
import argparse
from collections import defaultdict
from dataclasses import dataclass
import hashlib
import os
import re
import subprocess
import sys
import tempfile

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.dirname(SCRIPT_DIR)
INVENTORY_PATH = os.path.join(SCRIPT_DIR, "null-discipline-decoded.inventory.tsv")

SCAN_ROOTS = ("src", "internal")
LAYOUT_ROOTS = ("src", "internal", "vendored")

CLASSIFICATIONS = (
    "allocation-failure",
    "lookup-not-found",
    "semantically-absent",
    "display-log-boundary",
    "wrongly-nullable-decoded-string",
)
FAMILIES = (
    "cli-display",
    "cypher-metadata",
    "daemon-status",
    "extractor-metadata",
    "fqn-oom",
    "graph-property-presence",
    "json-display",
    "lookup-default",
    "lsp-ast-metadata",
    "pipeline-metadata",
    "runtime-metadata",
    "sql-decoder",
)

FN_PTR_FIELD_RE = re.compile(r'\(\s*\*\s*([A-Za-z_]\w*)\s*\)\s*\(')
STRUCT_BLOCK_RE = re.compile(
    r'(?:typedef\s+)?struct\s+(?:([A-Za-z_]\w*)\s*)?\{(.*?)\}\s*([A-Za-z_]\w*)?\s*;',
    re.DOTALL)
DESIGNATED_NULL_RE = re.compile(r'\.\s*([A-Za-z_]\w*)\s*=\s*NULL\s*[,}]')
DECODED_NULL_RE = re.compile(
    r'\b(?P<expression>[A-Za-z_][\w\->\.]*)\s*\?\s*'
    r'(?P=expression)\s*:\s*(?P<fallback>"(?:[^"\\]|\\.)*")')


@dataclass(frozen=True)
class Violation:
    """One detected NULL use and its review identity, if decoded."""

    path: str
    line: int
    kind: str
    detail: str
    identity: str = ""
    expression: str = ""
    fallback: str = ""


@dataclass(frozen=True)
class InventoryRecord:
    """The reviewed semantic classification and producer/accessor family."""

    classification: str
    family: str


def _find(roots, exts, drop_vendored):
    pattern = " -o ".join(f"-name '*{extension}'" for extension in exts)
    command = f"find {' '.join(roots)} \\( {pattern} \\)"
    if drop_vendored:
        command += " | grep -v vendored"
    result = subprocess.run(
        ["bash", "-c", command], cwd=PROJECT_DIR, check=False,
        capture_output=True, text=True)
    return sorted(result.stdout.split())


def struct_layouts():
    """Return function-pointer field positions and names from visible layouts."""
    positions = {}
    names = set()
    for path in _find(LAYOUT_ROOTS, (".h", ".c"), drop_vendored=False):
        try:
            with open(os.path.join(PROJECT_DIR, path), errors="replace") as source:
                text = source.read()
        except OSError:
            continue
        for tag, body, alias in STRUCT_BLOCK_RE.findall(text):
            field_positions = set()
            for index, field in enumerate(
                    field for field in body.split(";") if field.strip()):
                match = FN_PTR_FIELD_RE.search(field)
                if match:
                    field_positions.add(index)
                    names.add(match.group(1))
            if not field_positions:
                continue
            for key in (tag, alias):
                if key:
                    positions.setdefault(key, set()).update(field_positions)
    return positions, names


def _split_top_level(text):
    """Split an initializer body on commas that are not nested."""
    parts, depth, current = [], 0, ""
    for character in text:
        if character in "([{":
            depth += 1
        elif character in ")]}":
            depth -= 1
        if character == "," and depth == 0:
            parts.append(current)
            current = ""
            continue
        current += character
    parts.append(current)
    return parts


def _normalize_expression(expression):
    return " ".join(expression.split())


def _normalized_conditional(expression, fallback):
    expression = _normalize_expression(expression)
    return f"{expression} ? {expression} : {_normalize_expression(fallback)}"


def _decoded_identity(path, expression, fallback, ordinal):
    """Return a location-independent identity for the entire NULL conditional."""
    digest = hashlib.sha256(
        _normalized_conditional(expression, fallback).encode("utf-8")).hexdigest()
    return f"{path}|{digest}|{ordinal}"


def find_violations(positions, names):
    """Detect callable NULLs and decoded-string guards in first-party code."""
    found = []
    decoded_candidates = []
    type_alt = "|".join(re.escape(name) for name in sorted(positions))
    init_res = ([
        re.compile(
            r'\b(?:struct\s+)?(' + type_alt + r')\b[^;{=]*=\s*\{(.*?)\}\s*;',
            re.DOTALL),
        re.compile(r'\(\s*(?:struct\s+)?(' + type_alt + r')\s*\)\s*\{(.*?)\}',
                   re.DOTALL),
    ] if type_alt else [])

    for path in _find(SCAN_ROOTS, (".c", ".h"), drop_vendored=True):
        with open(os.path.join(PROJECT_DIR, path), errors="replace") as source:
            text = source.read()
        lines = text.split("\n")

        for line_number, line in enumerate(lines, start=1):
            if line.lstrip().startswith(("*", "//", "/*")):
                continue
            match = DESIGNATED_NULL_RE.search(line)
            if match and match.group(1) in names:
                found.append(Violation(path, line_number, "callable-slot", match.group(1)))
            for decoded in DECODED_NULL_RE.finditer(line):
                expression = _normalize_expression(decoded.group("expression"))
                detail = expression.split("->")[-1].split(".")[-1]
                decoded_candidates.append((
                    path, line_number, detail, expression, decoded.group("fallback")))

        for init_re in init_res:
            for match in init_re.finditer(text):
                type_name, body = match.group(1), match.group(2)
                if "." in body:
                    continue
                line_number = text[:match.start()].count("\n") + 1
                for index, part in enumerate(_split_top_level(body)):
                    if part.strip() == "NULL" and index in positions[type_name]:
                        found.append(Violation(
                            path, line_number, "callable-slot", f"{type_name}[{index}]"))

    ordinals = defaultdict(int)
    for path, line_number, detail, expression, fallback in decoded_candidates:
        key = (path, _normalized_conditional(expression, fallback))
        ordinals[key] += 1
        found.append(Violation(
            path, line_number, "decoded-null", detail,
            _decoded_identity(path, expression, fallback, ordinals[key]), expression, fallback))
    return sorted(found, key=lambda item: (item.path, item.line, item.kind, item.detail))


def load_inventory(path=INVENTORY_PATH):
    """Read reviewed decoded-null identities, classifications, and families."""
    records = {}
    try:
        with open(path, encoding="utf-8") as inventory:
            for line_number, line in enumerate(inventory, start=1):
                text = line.rstrip("\n")
                if not text or text.startswith("#"):
                    continue
                try:
                    identity, classification, family = text.split("\t")
                except ValueError as exc:
                    raise ValueError(
                        f"{path}:{line_number}: expected identity<TAB>classification<TAB>family") from exc
                if classification not in CLASSIFICATIONS:
                    raise ValueError(
                        f"{path}:{line_number}: unknown classification {classification!r}")
                if family not in FAMILIES:
                    raise ValueError(f"{path}:{line_number}: unknown family {family!r}")
                if identity in records:
                    raise ValueError(f"{path}:{line_number}: duplicate identity {identity}")
                records[identity] = InventoryRecord(classification, family)
    except OSError as exc:
        raise ValueError(f"cannot read decoded-null inventory {path}: {exc}") from exc
    return records


def ratchet_missing(decoded, inventory):
    return [record for record in decoded if record.identity not in inventory]


def decoded_report(decoded, inventory):
    """Render decoded-null records by reviewed classification and source family."""
    grouped = defaultdict(lambda: defaultdict(list))
    for record in decoded:
        review = inventory.get(record.identity)
        classification = review.classification if review else "UNCLASSIFIED"
        family = review.family if review else "UNCLASSIFIED"
        grouped[classification][family].append(record)
    lines = []
    classifications = list(CLASSIFICATIONS)
    if "UNCLASSIFIED" in grouped:
        classifications.append("UNCLASSIFIED")
    for classification in classifications:
        families = grouped.get(classification, {})
        lines.append(f"{classification} ({sum(len(records) for records in families.values())}):")
        for family in sorted(families):
            lines.append(f"  {family} ({len(families[family])}):")
            for record in families[family]:
                lines.append(
                    f"    {record.path}:{record.line}\t{record.identity}\t"
                    f"{record.expression} : {record.fallback}")
    lines.append(
        f"\n{len(decoded)} decoded-null site(s): " + ", ".join(
            f"{classification}={sum(len(records) for records in grouped.get(classification, {}).values())}"
            for classification in classifications))
    return "\n".join(lines)


SELF_TEST = '''
typedef struct {
    void *(*xMalloc)(int);
    int (*xInit)(void *);
} probe_methods;
static probe_methods m = {probe_malloc, NULL};
'''


def _positional_callable_detected(text):
    local_positions = {}
    for tag, body, alias in STRUCT_BLOCK_RE.findall(text):
        positions = {
            index for index, field in enumerate(body.split(";"))
            if field.strip() and FN_PTR_FIELD_RE.search(field)
        }
        for key in (tag, alias):
            if key and positions:
                local_positions.setdefault(key, set()).update(positions)
    type_alt = "|".join(re.escape(name) for name in local_positions)
    initializer = re.compile(
        r'\b(?:struct\s+)?(' + type_alt + r')\b[^;{=]*=\s*\{(.*?)\}\s*;', re.DOTALL)
    return any(
        part.strip() == "NULL" and index in local_positions[match.group(1)]
        for match in initializer.finditer(text)
        for index, part in enumerate(_split_top_level(match.group(2))))


def self_test():
    """Prove the detector and inventory ratchet reject only unreviewed data."""
    positional = _positional_callable_detected(SELF_TEST)
    probe = Violation(
        "src/probe.c", 17, "decoded-null", "name",
        _decoded_identity("src/probe.c", "node->name", '""', 1), "node->name", '""')
    review = InventoryRecord("semantically-absent", "graph-property-presence")
    matching_inventory = {probe.identity: review}
    matching_passes = not ratchet_missing([probe], matching_inventory)
    unclassified = ratchet_missing([probe], {})
    removed_record_passes = not ratchet_missing(
        [probe], {probe.identity: review,
                  "removed|record|1": InventoryRecord("lookup-not-found", "lookup-default")})
    fallback_changed = Violation(
        "src/probe.c", 17, "decoded-null", "name",
        _decoded_identity("src/probe.c", "node->name", '"(missing)"', 1),
        "node->name", '"(missing)"')
    fallback_change_is_unclassified = (
        ratchet_missing([fallback_changed], matching_inventory) == [fallback_changed])
    visible_report = decoded_report([probe], {})
    report_visible = (probe.identity in visible_report
                      and "UNCLASSIFIED" in visible_report
                      and "graph-property-presence" in decoded_report([probe], matching_inventory))
    unclassified_fails_with_identity = (
        len(unclassified) == 1 and unclassified[0].identity == probe.identity)
    if (positional and matching_passes and unclassified_fails_with_identity
            and fallback_change_is_unclassified and removed_record_passes and report_visible):
        print("SELF-TEST OK: positional callable, classified inventory, missing identity, "
              "fallback identity, removed inventory, and family report are verified")
        return 0
    print("SELF-TEST FAILED: NULL-discipline detection or ratchet contract regressed")
    return 1


def main():
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--report", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()

    if args.self_test:
        return self_test()

    positions, names = struct_layouts()
    if not positions:
        print("MISSING: no struct layouts parsed — refusing to report a clean tree.")
        return 1
    try:
        inventory = load_inventory()
    except ValueError as exc:
        print(f"BLOCKED: {exc}")
        return 1

    violations = find_violations(positions, names)
    callable_slots = [item for item in violations if item.kind == "callable-slot"]
    decoded = [item for item in violations if item.kind == "decoded-null"]
    report = decoded_report(decoded, inventory)
    print(report)

    if args.report:
        return 0
    if callable_slots:
        print(f"\nBLOCKED: {len(callable_slots)} NULL callable slot(s).")
        for record in callable_slots:
            print(f"  {record.path}:{record.line}\t{record.detail}")
        return 1

    missing = ratchet_missing(decoded, inventory)
    if missing:
        print(f"\nBLOCKED: {len(missing)} decoded-null record(s) lack a reviewed classification:")
        for record in missing:
            print(f"  {record.identity}\t{record.path}:{record.line}\t"
                  f"{record.expression} : {record.fallback}")
        return 1

    print("\nOK: no NULL callable slots; every decoded-null site is classified")
    return 0


if __name__ == "__main__":
    sys.exit(main())
