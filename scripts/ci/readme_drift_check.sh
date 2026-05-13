#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FCP_REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
export FCP_REPO_ROOT

python3 - "$@" <<'PY'
import argparse
import json
import os
import pathlib
import re
import sys
from dataclasses import dataclass


INLINE_CODE_RE = re.compile(r"(?<!`)`([^`\n]+)`(?!`)")
PATH_RE = re.compile(
    r"(?P<path>(?:\.github|artifacts|connectors|crates|docs|scripts|specs|fuzz)/"
    r"[A-Za-z0-9_./*{}@:+-]+)"
)
SYMBOL_RE = re.compile(r"\b(?P<symbol>[a-z][a-z0-9_]*(?:::[A-Za-z_][A-Za-z0-9_]*)+)\b")
SUPPORTED_EXTENSIONS = {
    ".cbor",
    ".json",
    ".jsonl",
    ".lean",
    ".md",
    ".rs",
    ".sh",
    ".toml",
    ".txt",
    ".yaml",
    ".yml",
}
SKIP_HINT = "drift-check:skip"


@dataclass(frozen=True)
class Reference:
    kind: str
    value: str
    line: int


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Check README inline code references for stale repo paths and Rust symbols."
    )
    parser.add_argument("--readme", default="README.md")
    parser.add_argument("--repo-root", default=os.environ.get("FCP_REPO_ROOT", "."))
    parser.add_argument("--debug", action="store_true")
    return parser.parse_args()


def resolve_path(path_text: str, repo_root: pathlib.Path) -> pathlib.Path:
    path = pathlib.Path(path_text)
    return path if path.is_absolute() else repo_root / path


def normalize_path_token(token: str) -> str:
    return token.rstrip(".,;:)]}")


def is_candidate_path(path_text: str) -> bool:
    path = pathlib.PurePosixPath(path_text)
    if "*" in path_text or "{" in path_text or "}" in path_text:
        return True
    if path_text.endswith("/"):
        return True
    return path.suffix in SUPPORTED_EXTENSIONS


def extract_references(readme_path: pathlib.Path) -> list[Reference]:
    references: list[Reference] = []
    in_fence = False
    for line_no, line in enumerate(readme_path.read_text(encoding="utf-8").splitlines(), 1):
        stripped = line.lstrip()
        if stripped.startswith("```"):
            in_fence = not in_fence
            continue
        if in_fence or SKIP_HINT in line:
            continue
        for match in INLINE_CODE_RE.finditer(line):
            inline = match.group(1)
            for path_match in PATH_RE.finditer(inline):
                value = normalize_path_token(path_match.group("path"))
                if is_candidate_path(value):
                    references.append(Reference("path", value, line_no))
            for symbol_match in SYMBOL_RE.finditer(inline):
                value = symbol_match.group("symbol")
                if value.count("::") >= 1:
                    references.append(Reference("symbol", value, line_no))
    return references


def crate_source_root(symbol: str, repo_root: pathlib.Path) -> pathlib.Path | None:
    crate_name = symbol.split("::", 1)[0]
    candidates = [repo_root / "crates" / crate_name.replace("_", "-")]
    if crate_name == "fwc":
        candidates.append(repo_root / "crates" / "fwc")
    for candidate in candidates:
        source_root = candidate / "src"
        if source_root.is_dir():
            return source_root
    return None


def rust_sources(source_root: pathlib.Path) -> list[pathlib.Path]:
    return sorted(path for path in source_root.rglob("*.rs") if path.is_file())


def symbol_exists(symbol: str, repo_root: pathlib.Path) -> bool:
    source_root = crate_source_root(symbol, repo_root)
    if source_root is None:
        return False
    needle = symbol.rsplit("::", 1)[-1]
    pattern = re.compile(rf"\b{re.escape(needle)}\b")
    for source in rust_sources(source_root):
        try:
            if pattern.search(source.read_text(encoding="utf-8")):
                return True
        except UnicodeDecodeError:
            continue
    return False


def path_exists(path_text: str, repo_root: pathlib.Path) -> bool:
    absolute = resolve_path(path_text, repo_root)
    if "*" in path_text or "{" in path_text or "}" in path_text:
        return bool(list(repo_root.glob(path_text)))
    return absolute.exists()


def main() -> int:
    args = parse_args()
    repo_root = resolve_path(args.repo_root, pathlib.Path.cwd()).resolve()
    readme_path = resolve_path(args.readme, repo_root).resolve()
    references = extract_references(readme_path)

    paths_checked = 0
    paths_missing: list[Reference] = []
    symbols_checked = 0
    symbols_missing: list[Reference] = []

    for reference in references:
        if reference.kind == "path":
            paths_checked += 1
            ok = path_exists(reference.value, repo_root)
            if args.debug:
                print(
                    f"DEBUG path {reference.value} line={reference.line} ok={ok}",
                    file=sys.stderr,
                )
            if not ok:
                paths_missing.append(reference)
        elif reference.kind == "symbol":
            symbols_checked += 1
            ok = symbol_exists(reference.value, repo_root)
            if args.debug:
                print(
                    f"DEBUG symbol {reference.value} line={reference.line} ok={ok}",
                    file=sys.stderr,
                )
            if not ok:
                symbols_missing.append(reference)

    for reference in paths_missing:
        print(
            f"{readme_path}:{reference.line}: missing_path={reference.value}",
            file=sys.stderr,
        )
    for reference in symbols_missing:
        print(
            f"{readme_path}:{reference.line}: missing_symbol={reference.value}",
            file=sys.stderr,
        )

    log = {
        "level": "INFO",
        "span": "fcp.cadence.readme_drift",
        "readme_path": str(readme_path),
        "paths_checked": paths_checked,
        "paths_missing": len(paths_missing),
        "symbols_checked": symbols_checked,
        "symbols_missing": len(symbols_missing),
    }
    print(json.dumps(log, sort_keys=True))
    return 1 if paths_missing or symbols_missing else 0


if __name__ == "__main__":
    sys.exit(main())
PY
