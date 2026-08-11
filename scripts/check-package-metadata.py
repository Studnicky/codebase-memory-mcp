#!/usr/bin/env python3
"""Validate checked-in package metadata against the MCP server manifest."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Dict


PRODUCT = "codebase-memory-mcp"
MCP_NAME = "io.github.DeusData/codebase-memory-mcp"
REPOSITORY = "https://github.com/DeusData/codebase-memory-mcp"
LICENSE = "MIT"


def read(root: Path, relative_path: str) -> str:
    path = root / relative_path
    try:
        return path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ValueError(f"cannot read {relative_path}: {exc}") from exc


def match(text: str, pattern: str, label: str) -> str:
    found = re.search(pattern, text, re.MULTILINE)
    if found is None:
        raise ValueError(f"{label} is missing")
    return found.group(1)


def require_equal(actual: str, expected: str, label: str) -> None:
    if actual != expected:
        raise ValueError(f"{label} is {actual!r}, expected {expected!r}")


def require_contains(text: str, expected: str, label: str) -> None:
    if expected not in text:
        raise ValueError(f"{label} must contain {expected!r}")


def normalize_git_url(url: str) -> str:
    if url.startswith("git+"):
        url = url[4:]
    if url.endswith(".git"):
        url = url[:-4]
    return url


def language_count(root: Path) -> int:
    grammars = list((root / "internal/cbm").glob("grammar_*.c"))
    if not grammars:
        raise ValueError("internal/cbm/grammar_*.c is empty")
    return len(grammars)


def check_versions(root: Path, version: str) -> None:
    checks = {
        "flake.nix version": lambda: match(read(root, "flake.nix"), r'^\s*version\s*=\s*"([^"]+)";', "flake.nix version"),
        "pkg/npm/package.json version": lambda: json.loads(read(root, "pkg/npm/package.json"))["version"],
        "pkg/pypi/pyproject.toml version": lambda: match(read(root, "pkg/pypi/pyproject.toml"), r'^version\s*=\s*"([^"]+)"$', "pkg/pypi/pyproject.toml version"),
        "Go installer version": lambda: match(read(root, "pkg/go/cmd/codebase-memory-mcp/main.go"), r'^\s*version\s*=\s*"([^"]+)"$', "Go installer version"),
        "PyPI fallback version": lambda: match(read(root, "pkg/pypi/src/codebase_memory_mcp/_cli.py"), r'^\s*return\s+"([^"]+)"$', "PyPI fallback version"),
        "Chocolatey nuspec version": lambda: match(read(root, "pkg/chocolatey/codebase-memory-mcp.nuspec"), r"<version>([^<]+)</version>", "Chocolatey nuspec version"),
        "Chocolatey installer version": lambda: match(read(root, "pkg/chocolatey/tools/chocolateyInstall.ps1"), r"^\$version\s*=\s*'([^']+)'", "Chocolatey installer version"),
        "Homebrew formula version": lambda: match(read(root, "pkg/homebrew/Formula/codebase-memory-mcp.rb"), r'^\s*version\s+"([^"]+)"$', "Homebrew formula version"),
        "AUR package version": lambda: match(read(root, "pkg/aur/PKGBUILD"), r'^pkgver=([^\n]+)$', "AUR package version"),
        "Scoop manifest version": lambda: json.loads(read(root, "pkg/scoop/codebase-memory-mcp.json"))["version"],
    }
    winget = root / "pkg/winget/manifests/d/DeusData/CodebaseMemoryMcp" / version
    for name in (
        "DeusData.CodebaseMemoryMcp.yaml",
        "DeusData.CodebaseMemoryMcp.installer.yaml",
        "DeusData.CodebaseMemoryMcp.locale.en-US.yaml",
    ):
        checks[f"Winget {name} version"] = lambda name=name: match(
            read(winget, name), r"^PackageVersion:\s*([^\n]+)$", f"Winget {name} version"
        )
    for label, get_value in checks.items():
        require_equal(get_value(), version, label)


def check_identity(root: Path, server: Dict[str, object], languages: int) -> None:
    repository = server["repository"]
    if not isinstance(repository, dict):
        raise ValueError("server.json repository must be an object")
    require_equal(str(server.get("name")), MCP_NAME, "server.json name")
    require_equal(str(repository.get("url")), REPOSITORY, "server.json repository.url")

    npm = json.loads(read(root, "pkg/npm/package.json"))
    require_equal(str(npm.get("name")), PRODUCT, "pkg/npm/package.json name")
    require_equal(str(npm.get("mcpName")), MCP_NAME, "pkg/npm/package.json mcpName")
    require_equal(str(npm.get("license")), LICENSE, "pkg/npm/package.json license")
    require_equal(str(npm.get("homepage")), REPOSITORY, "pkg/npm/package.json homepage")
    require_equal(normalize_git_url(str(npm.get("repository", {}).get("url", ""))), REPOSITORY, "pkg/npm/package.json repository")

    pyproject = read(root, "pkg/pypi/pyproject.toml")
    require_equal(match(pyproject, r'^name\s*=\s*"([^"]+)"$', "pkg/pypi name"), PRODUCT, "pkg/pypi name")
    require_equal(match(pyproject, r'^license\s*=\s*\{\s*text\s*=\s*"([^"]+)"\s*\}$', "pkg/pypi license"), LICENSE, "pkg/pypi license")
    for label, url in (("Homepage", REPOSITORY), ("Repository", REPOSITORY), ("Issues", f"{REPOSITORY}/issues")):
        require_equal(match(pyproject, rf'^{label}\s*=\s*"([^"]+)"$', f"pkg/pypi {label}"), url, f"pkg/pypi {label}")

    flake = read(root, "flake.nix")
    require_equal(match(flake, r'^\s*pname\s*=\s*"([^"]+)";', "flake pname"), PRODUCT, "flake pname")
    require_equal(match(flake, r'^\s*homepage\s*=\s*"([^"]+)";', "flake homepage"), REPOSITORY, "flake homepage")
    require_contains(flake, "licenses.mit", "flake license")

    require_contains(read(root, "LICENSE"), "MIT License", "LICENSE")
    require_contains(read(root, "pkg/chocolatey/codebase-memory-mcp.nuspec"), f"<id>{PRODUCT}</id>", "Chocolatey package name")
    require_contains(read(root, "pkg/chocolatey/codebase-memory-mcp.nuspec"), REPOSITORY, "Chocolatey repository URL")
    require_contains(read(root, "pkg/homebrew/Formula/codebase-memory-mcp.rb"), f'homepage "{REPOSITORY}"', "Homebrew repository URL")
    require_contains(read(root, "pkg/homebrew/Formula/codebase-memory-mcp.rb"), 'license "MIT"', "Homebrew license")
    require_contains(read(root, "pkg/aur/PKGBUILD"), f"pkgname={PRODUCT}", "AUR package name")
    require_contains(read(root, "pkg/aur/PKGBUILD"), f'url="{REPOSITORY}"', "AUR repository URL")
    require_contains(read(root, "pkg/aur/PKGBUILD"), "license=('MIT')", "AUR license")
    scoop = json.loads(read(root, "pkg/scoop/codebase-memory-mcp.json"))
    require_equal(str(scoop.get("homepage")), REPOSITORY, "Scoop homepage")
    require_equal(str(scoop.get("license")), LICENSE, "Scoop license")

    winget = root / "pkg/winget/manifests/d/DeusData/CodebaseMemoryMcp" / str(server["version"])
    winget_locale = read(winget, "DeusData.CodebaseMemoryMcp.locale.en-US.yaml")
    require_contains(winget_locale, f"PackageName: {PRODUCT}", "Winget package name")
    require_contains(winget_locale, f"PackageUrl: {REPOSITORY}", "Winget repository URL")
    require_contains(winget_locale, "License: MIT", "Winget license")

    descriptions = {
        "server.json description": str(server.get("description", "")),
        "pkg/npm README": read(root, "pkg/npm/README.md"),
        "Chocolatey description": read(root, "pkg/chocolatey/codebase-memory-mcp.nuspec"),
        "Winget description": winget_locale,
        "root README": read(root, "README.md"),
    }
    for label, description in descriptions.items():
        require_contains(description, f"{languages} languages", label)


def check(root: Path) -> None:
    try:
        server = json.loads(read(root, "server.json"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"server.json is invalid JSON: {exc}") from exc
    version = server.get("version")
    if not isinstance(version, str) or not re.fullmatch(r"\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?", version):
        raise ValueError("server.json version must be a semantic version")
    packages = server.get("packages")
    if not isinstance(packages, list) or not packages:
        raise ValueError("server.json packages must be a non-empty array")
    for package in packages:
        if not isinstance(package, dict):
            raise ValueError("server.json package entry must be an object")
        require_equal(str(package.get("identifier")), PRODUCT, "server.json package identifier")
        require_equal(str(package.get("version")), version, "server.json package version")
    languages = language_count(root)
    check_versions(root, version)
    check_identity(root, server, languages)
    print(f"OK: metadata version {version}; {languages} grammar-backed languages")


def main() -> int:
    root = Path(sys.argv[1]).resolve() if len(sys.argv) == 2 else Path(__file__).resolve().parents[1]
    try:
        check(root)
    except ValueError as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
