#!/usr/bin/env python3
"""
Exception management system for osquery-defense-kit.

Reads YAML exception files from exceptions/ and injects SQL WHERE clauses
into copies of detection queries written to out/queries/.

Usage:
    python3 scripts/exceptions.py [--env ENV] <command>

Commands:
    apply   [--output-dir DIR]   Preprocess SQL → out/queries/ with exceptions injected
    list    [--query QUERY]      Tabular display of all exceptions
    check   [--warn-days N]      Flag expired/expiring-soon exceptions (exit 1 if found)
    report  [--output FILE]      Generate Markdown summary of all exceptions
    add                          Interactive guided prompt to add a new exception
"""

import argparse
import fnmatch
import glob
import os
import re
import shutil
import sys
import textwrap
from datetime import date, datetime, timedelta
from pathlib import Path
from typing import Optional

try:
    import yaml
except ImportError:
    print("ERROR: PyYAML is required. Install with: pip install pyyaml  or  apt install python3-yaml")
    sys.exit(1)

# ---------------------------------------------------------------------------
# Paths (relative to repo root)
# ---------------------------------------------------------------------------

REPO_ROOT = Path(__file__).resolve().parent.parent
EXCEPTIONS_DIR = REPO_ROOT / "exceptions"
ENVIRONMENTS_DIR = REPO_ROOT / "environments"
DEFAULT_OUTPUT_DIR = REPO_ROOT / "out" / "queries"

# Source query directories to copy/process
QUERY_DIRS = ["detection", "policy", "vulnerabilities", "incident_response"]

# ---------------------------------------------------------------------------
# Filename mapping helpers
# ---------------------------------------------------------------------------

def sql_path_to_yaml_path(sql_rel: str) -> Optional[Path]:
    """
    Map a repo-relative SQL path to its exceptions YAML path.

    detection/privesc/1-unexpected-setxid-process.sql
        → exceptions/privesc/unexpected-setxid-process.yaml

    policy/foo/2-bar.sql → exceptions/foo/bar.yaml
    """
    p = Path(sql_rel)
    # Strip leading query-dir prefix (detection/, policy/, etc.)
    parts = p.parts
    if len(parts) < 2:
        return None
    # Drop the first component (detection, policy, …)
    subparts = parts[1:]
    # Strip leading digit prefix from filename: "1-foo.sql" → "foo"
    filename = subparts[-1]
    filename_no_prefix = re.sub(r'^\d+-', '', filename)
    stem = Path(filename_no_prefix).stem  # strip .sql
    yaml_name = stem + ".yaml"
    return EXCEPTIONS_DIR / Path(*subparts[:-1]) / yaml_name


def yaml_path_to_sql_paths(yaml_path: Path) -> list[Path]:
    """
    Reverse-map a YAML path to candidate SQL paths in the repo.
    Returns all matches (there may be multiple with different N- prefixes).
    """
    rel = yaml_path.relative_to(EXCEPTIONS_DIR)
    parts = rel.parts  # e.g. ('privesc', 'unexpected-setxid-process.yaml')
    stem = Path(parts[-1]).stem  # 'unexpected-setxid-process'
    subdir = parts[:-1]          # ('privesc',)

    results = []
    for qdir in QUERY_DIRS:
        search_dir = REPO_ROOT / qdir / Path(*subdir) if subdir else REPO_ROOT / qdir
        if not search_dir.exists():
            continue
        for sql_file in search_dir.glob(f"*-{stem}.sql"):
            results.append(sql_file)
        # Also try without a digit prefix
        direct = search_dir / f"{stem}.sql"
        if direct.exists():
            results.append(direct)
    return results

# ---------------------------------------------------------------------------
# YAML loading / environment profiles
# ---------------------------------------------------------------------------

def load_yaml(path: Path) -> dict:
    with open(path) as f:
        return yaml.safe_load(f) or {}


def load_environment(env_name: str) -> dict:
    """Load environments/<env_name>.yaml, falling back to default."""
    env_file = ENVIRONMENTS_DIR / f"{env_name}.yaml"
    if not env_file.exists():
        # Return a permissive default
        return {
            "name": env_name,
            "include_exceptions": ["**"],
            "query_dirs": QUERY_DIRS,
        }
    return load_yaml(env_file)


def exception_yaml_matches_env(yaml_path: Path, env: dict) -> bool:
    """Return True if yaml_path is covered by the environment's include_exceptions globs."""
    rel = str(yaml_path.relative_to(EXCEPTIONS_DIR))
    patterns = env.get("include_exceptions", ["**"])
    for pat in patterns:
        if fnmatch.fnmatch(rel, pat):
            return True
    return False


def collect_exception_files(env: dict) -> list[Path]:
    """Return all YAML exception files matching the env's include patterns."""
    results = []
    for yaml_path in sorted(EXCEPTIONS_DIR.rglob("*.yaml")):
        if yaml_path.name == "README.md":
            continue
        rel = yaml_path.relative_to(EXCEPTIONS_DIR)
        # Skip _shared files at top level (they're only loaded via include:)
        if rel.parts[0] == "_shared":
            continue
        if exception_yaml_matches_env(yaml_path, env):
            results.append(yaml_path)
    return results


def load_exceptions_for_yaml(yaml_path: Path) -> list[dict]:
    """
    Load exceptions from a YAML file, resolving any include: references.
    Returns a flat list of exception dicts.
    """
    data = load_yaml(yaml_path)
    exceptions = list(data.get("exceptions", []) or [])

    for include_ref in data.get("include", []) or []:
        shared_path = EXCEPTIONS_DIR / include_ref
        if shared_path.exists():
            shared_data = load_yaml(shared_path)
            exceptions.extend(shared_data.get("exceptions", []) or [])
        else:
            print(f"WARNING: include not found: {shared_path}", file=sys.stderr)

    return exceptions


def get_query_path_from_yaml(yaml_data: dict, yaml_path: Path) -> Optional[Path]:
    """Resolve the SQL file this YAML targets."""
    if "query" in yaml_data:
        q = REPO_ROOT / yaml_data["query"]
        if q.exists():
            return q
        return None
    # Try reverse-mapping
    candidates = yaml_path_to_sql_paths(yaml_path)
    return candidates[0] if candidates else None

# ---------------------------------------------------------------------------
# Expiry helpers
# ---------------------------------------------------------------------------

def parse_date(val) -> Optional[date]:
    if val is None:
        return None
    if isinstance(val, date):
        return val
    try:
        return datetime.strptime(str(val), "%Y-%m-%d").date()
    except ValueError:
        return None


def is_expired(exc: dict) -> bool:
    exp = parse_date(exc.get("expires"))
    if exp is None:
        return False
    return exp < date.today()


def days_until_expiry(exc: dict) -> Optional[int]:
    exp = parse_date(exc.get("expires"))
    if exp is None:
        return None
    return (exp - date.today()).days

# ---------------------------------------------------------------------------
# SQL injection logic
# ---------------------------------------------------------------------------

def escape_sql_string(value: str) -> str:
    """Escape single quotes in SQL string literals."""
    return value.replace("'", "''")


def build_clause(exc_type: str, exc: dict) -> Optional[str]:
    """
    Build a single WHERE clause fragment for one exception.
    Returns None for batch types (handled separately) or invalid entries.
    """
    # Batch types are handled in build_clauses_for_exceptions
    return None


def build_clauses_for_exceptions(exceptions: list[dict]) -> list[str]:
    """
    Generate SQL WHERE clause fragments for a list of exceptions,
    batching same-type+field entries into NOT IN (...) lists.
    """
    # Filter out expired
    active = [e for e in exceptions if not is_expired(e)]
    if not active:
        return []

    clauses = []

    # Group by (type, field) for batchable types
    batch_types = {"path_in", "name_in", "exception_key_in", "authority_in"}
    batches: dict[tuple, list[str]] = {}

    for exc in active:
        t = exc.get("type", "")
        field = exc.get("field", "")
        value = str(exc.get("value", ""))
        escaped = escape_sql_string(value)

        if t in batch_types:
            key = (t, field)
            batches.setdefault(key, []).append(escaped)

        elif t == "path_like":
            clauses.append(f"  AND {field} NOT LIKE '{escaped}'")

        elif t == "exception_key_like":
            clauses.append(f"  AND NOT exception_key LIKE '{escaped}'")

        elif t == "not_block":
            conditions = exc.get("conditions", [])
            if conditions:
                inner = "\n    AND ".join(conditions)
                clauses.append(f"  AND NOT (\n    {inner}\n  )")

    # Emit batched NOT IN clauses
    for (t, field), values in batches.items():
        if len(values) == 1:
            clauses.append(f"  AND {field} != '{values[0]}'")
        else:
            vals_str = ",\n    ".join(f"'{v}'" for v in values)
            clauses.append(f"  AND {field} NOT IN (\n    {vals_str}\n  )")

    return clauses


def find_injection_point(sql_lines: list[str]) -> tuple[int, bool]:
    """
    Find the line index before which to inject exception clauses.

    Rules:
    - Find the last GROUP BY / ORDER BY / LIMIT before end
    - If none, inject at the very end
    - Return (line_index, has_where_before_it)

    Returns (index, has_where) where index is the 0-based line to insert before,
    or len(sql_lines) to append at end.
    """
    # Find last GROUP BY / ORDER BY / LIMIT line
    last_clause_idx = None
    for i, line in enumerate(sql_lines):
        stripped = line.strip().upper()
        if stripped.startswith(("GROUP BY", "ORDER BY", "LIMIT")):
            last_clause_idx = i

    inject_at = last_clause_idx if last_clause_idx is not None else len(sql_lines)

    # Check if WHERE appears before the injection point
    has_where = any(
        "WHERE" in sql_lines[i].upper()
        for i in range(inject_at)
    )

    return inject_at, has_where


def inject_exceptions_into_sql(sql: str, clauses: list[str]) -> str:
    """
    Inject exception clauses into SQL at the appropriate point.
    Returns the modified SQL string.
    """
    if not clauses:
        return sql

    lines = sql.splitlines(keepends=True)
    inject_at, has_where = find_injection_point(lines)

    if not has_where:
        # No WHERE clause found before injection point — skip injection
        return sql

    # Build the injection block
    inject_block = "\n".join(clauses) + "\n"

    # Insert before inject_at line (or append)
    if inject_at < len(lines):
        # Insert before the GROUP BY / ORDER BY / LIMIT line
        lines.insert(inject_at, inject_block)
    else:
        # Append at end
        if lines and not lines[-1].endswith("\n"):
            lines[-1] += "\n"
        lines.append(inject_block)

    return "".join(lines)

# ---------------------------------------------------------------------------
# apply command
# ---------------------------------------------------------------------------

def cmd_apply(args, env: dict):
    """Preprocess all SQL files, injecting exceptions, into output_dir."""
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    # Build a mapping: source SQL path → list of exception dicts
    exception_map: dict[Path, list[dict]] = {}

    for yaml_path in collect_exception_files(env):
        data = load_yaml(yaml_path)
        sql_path = get_query_path_from_yaml(data, yaml_path)
        if sql_path is None:
            print(f"WARNING: could not resolve SQL for {yaml_path.relative_to(REPO_ROOT)}", file=sys.stderr)
            continue
        exceptions = load_exceptions_for_yaml(yaml_path)
        if exceptions:
            exception_map.setdefault(sql_path, []).extend(exceptions)

    # Walk all SQL source directories and process each file
    query_dirs = env.get("query_dirs", QUERY_DIRS)
    copied = 0
    injected = 0
    skipped = 0

    for qdir_name in query_dirs:
        qdir = REPO_ROOT / qdir_name
        if not qdir.exists():
            continue
        for sql_file in sorted(qdir.rglob("*.sql")):
            rel = sql_file.relative_to(REPO_ROOT)
            dest = output_dir / rel
            dest.parent.mkdir(parents=True, exist_ok=True)

            sql = sql_file.read_text()
            exceptions_for_file = exception_map.get(sql_file, [])
            active = [e for e in exceptions_for_file if not is_expired(e)]

            if not active:
                shutil.copy2(sql_file, dest)
                copied += 1
                continue

            clauses = build_clauses_for_exceptions(active)
            if not clauses:
                shutil.copy2(sql_file, dest)
                copied += 1
                continue

            modified = inject_exceptions_into_sql(sql, clauses)
            if modified == sql:
                skipped += 1
                print(f"WARNING: Could not inject into {rel} (no WHERE clause?)", file=sys.stderr)
                shutil.copy2(sql_file, dest)
            else:
                dest.write_text(modified)
                injected += 1

    print(f"apply: {injected} files injected, {copied} copied unchanged, {skipped} skipped")
    print(f"Output: {output_dir}")

# ---------------------------------------------------------------------------
# list command
# ---------------------------------------------------------------------------

def all_exceptions_with_context(env: dict) -> list[dict]:
    """Return all exception dicts annotated with source metadata."""
    results = []
    for yaml_path in collect_exception_files(env):
        data = load_yaml(yaml_path)
        sql_path = get_query_path_from_yaml(data, yaml_path)
        query_rel = str(sql_path.relative_to(REPO_ROOT)) if sql_path else "?"
        exceptions = load_exceptions_for_yaml(yaml_path)
        for exc in exceptions:
            results.append({
                **exc,
                "_yaml": str(yaml_path.relative_to(REPO_ROOT)),
                "_query": query_rel,
            })
    return results


def cmd_list(args, env: dict):
    """Print a tabular view of all exceptions."""
    query_filter = getattr(args, "query", None)
    all_exc = all_exceptions_with_context(env)

    if query_filter:
        all_exc = [e for e in all_exc if query_filter in e.get("_query", "")]

    if not all_exc:
        print("No exceptions found.")
        return

    # Columns: type, field/conditions, value, owner, added, expires, status, query
    rows = []
    for exc in all_exc:
        t = exc.get("type", "?")
        if t == "not_block":
            val = " AND ".join(exc.get("conditions", []))
        else:
            val = str(exc.get("value", ""))
        if len(val) > 48:
            val = val[:45] + "..."

        exp = exc.get("expires")
        if exp is None:
            status = ""
        elif is_expired(exc):
            status = "EXPIRED"
        else:
            d = days_until_expiry(exc)
            status = f"exp {d}d" if d is not None else ""

        rows.append((
            t,
            exc.get("field", ""),
            val,
            exc.get("owner", ""),
            str(exc.get("added", "")),
            str(exp or ""),
            status,
            exc.get("_query", ""),
        ))

    headers = ("TYPE", "FIELD", "VALUE", "OWNER", "ADDED", "EXPIRES", "STATUS", "QUERY")
    col_widths = [max(len(h), max((len(r[i]) for r in rows), default=0)) for i, h in enumerate(headers)]

    def fmt_row(row):
        return "  ".join(str(v).ljust(col_widths[i]) for i, v in enumerate(row))

    print(fmt_row(headers))
    print("  ".join("-" * w for w in col_widths))
    for row in rows:
        line = fmt_row(row)
        if row[6] == "EXPIRED":
            line = f"\033[91m{line}\033[0m"  # red
        elif row[6].startswith("exp"):
            line = f"\033[93m{line}\033[0m"  # yellow
        print(line)

    print(f"\n{len(rows)} exception(s) total")

# ---------------------------------------------------------------------------
# check command
# ---------------------------------------------------------------------------

def cmd_check(args, env: dict):
    """Exit 1 if any exceptions are expired or expiring soon."""
    warn_days = getattr(args, "warn_days", 30) or 30
    all_exc = all_exceptions_with_context(env)

    problems = []
    for exc in all_exc:
        if is_expired(exc):
            problems.append(("EXPIRED", exc))
        else:
            d = days_until_expiry(exc)
            if d is not None and d <= warn_days:
                problems.append((f"EXPIRING in {d} days", exc))

    if not problems:
        print(f"check: OK — {len(all_exc)} exception(s), none expired or expiring within {warn_days} days")
        sys.exit(0)

    print(f"check: {len(problems)} problem(s) found:\n")
    for status, exc in problems:
        t = exc.get("type", "?")
        val = exc.get("value", exc.get("conditions", ""))
        print(f"  [{status}] {exc.get('_yaml')} — {t}: {val}")
        print(f"           reason: {exc.get('reason', '?')}")
        print(f"           expires: {exc.get('expires', '?')}")
        print()
    sys.exit(1)

# ---------------------------------------------------------------------------
# report command
# ---------------------------------------------------------------------------

def cmd_report(args, env: dict):
    """Generate a Markdown report of all exceptions."""
    output_file = getattr(args, "output", None)
    all_exc = all_exceptions_with_context(env)

    lines = [
        f"# Exception Report",
        f"",
        f"Generated: {date.today().isoformat()}  ",
        f"Environment: `{env.get('name', 'unknown')}`  ",
        f"Total exceptions: {len(all_exc)}",
        f"",
    ]

    # Group by query
    by_query: dict[str, list[dict]] = {}
    for exc in all_exc:
        q = exc.get("_query", "?")
        by_query.setdefault(q, []).append(exc)

    expired_count = sum(1 for e in all_exc if is_expired(e))
    if expired_count:
        lines.append(f"> **WARNING:** {expired_count} expired exception(s) found.\n")

    for query, exceptions in sorted(by_query.items()):
        lines.append(f"## `{query}`")
        lines.append("")
        lines.append("| Type | Field/Value | Owner | Added | Expires | Status |")
        lines.append("|------|------------|-------|-------|---------|--------|")
        for exc in exceptions:
            t = exc.get("type", "?")
            if t == "not_block":
                val = "; ".join(exc.get("conditions", []))
                field = ""
            else:
                field = exc.get("field", "")
                val = str(exc.get("value", ""))
            if len(val) > 60:
                val = val[:57] + "..."
            exp = exc.get("expires")
            if exp is None:
                status = ""
            elif is_expired(exc):
                status = "**EXPIRED**"
            else:
                d = days_until_expiry(exc)
                status = f"expiring {d}d" if d is not None else ""
            cell = f"`{field}` = `{val}`" if field else f"`{val}`"
            lines.append(
                f"| {t} | {cell} | {exc.get('owner','')} "
                f"| {exc.get('added','')} | {exp or ''} | {status} |"
            )
        lines.append("")

    report = "\n".join(lines)

    if output_file:
        out = Path(output_file)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(report)
        print(f"Report written to {out}")
    else:
        print(report)

# ---------------------------------------------------------------------------
# add command (interactive)
# ---------------------------------------------------------------------------

EXCEPTION_TYPES = [
    ("path_in",          "f.path",         "Exact file path (NOT IN)"),
    ("path_like",        "f.path",         "Glob file path (NOT LIKE)"),
    ("name_in",          "p.name",         "Process name (NOT IN)"),
    ("exception_key_in", "exception_key",  "Composite exception_key (NOT IN)"),
    ("exception_key_like","exception_key", "Composite exception_key pattern (NOT LIKE)"),
    ("not_block",        "",               "Multi-condition block (AND NOT (...))"),
    ("authority_in",     "s.authority",    "macOS code-signing authority (NOT IN)"),
]


def prompt(question: str, default: str = "") -> str:
    if default:
        answer = input(f"{question} [{default}]: ").strip()
        return answer if answer else default
    return input(f"{question}: ").strip()


def cmd_add(args, env: dict):
    """Interactive guided prompt to add a new exception."""
    print("\n=== Add Exception ===\n")

    # Choose query
    all_sqls = []
    for qdir in QUERY_DIRS:
        qdir_path = REPO_ROOT / qdir
        if qdir_path.exists():
            all_sqls.extend(sorted(qdir_path.rglob("*.sql")))

    print("Available query directories:")
    for qdir in QUERY_DIRS:
        if (REPO_ROOT / qdir).exists():
            count = len(list((REPO_ROOT / qdir).rglob("*.sql")))
            print(f"  {qdir}/  ({count} queries)")
    print()

    query_rel = prompt("SQL query path (e.g. detection/privesc/1-unexpected-setxid-process.sql)")
    sql_path = REPO_ROOT / query_rel
    if not sql_path.exists():
        print(f"ERROR: {sql_path} does not exist")
        sys.exit(1)

    # Determine YAML path
    yaml_path = sql_path_to_yaml_path(query_rel)
    if yaml_path is None:
        print("ERROR: Could not determine YAML path for this query")
        sys.exit(1)

    print(f"\nException YAML: {yaml_path.relative_to(REPO_ROOT)}")

    # Choose type
    print("\nException types:")
    for i, (t, field, desc) in enumerate(EXCEPTION_TYPES):
        print(f"  {i+1}. {t:<22} {desc}")
    type_idx = int(prompt("Choose type (number)")) - 1
    exc_type, default_field, _ = EXCEPTION_TYPES[type_idx]

    exc: dict = {"type": exc_type}

    if exc_type == "not_block":
        print("\nEnter conditions (one per line, empty line to finish):")
        conditions = []
        while True:
            c = input("  condition: ").strip()
            if not c:
                break
            conditions.append(c)
        exc["conditions"] = conditions
    else:
        field = prompt("Field", default=default_field)
        value = prompt("Value")
        exc["field"] = field
        exc["value"] = value

    exc["reason"] = prompt("Reason")
    exc["owner"] = prompt("Owner", default=os.environ.get("USER", ""))
    exc["added"] = date.today().isoformat()

    expires_str = prompt("Expires (YYYY-MM-DD, or leave empty for never)", default="")
    exc["expires"] = expires_str if expires_str else None

    # Load or create YAML file
    yaml_path.parent.mkdir(parents=True, exist_ok=True)
    if yaml_path.exists():
        data = load_yaml(yaml_path)
    else:
        data = {"query": query_rel, "exceptions": []}

    if "exceptions" not in data or data["exceptions"] is None:
        data["exceptions"] = []

    data["exceptions"].append(exc)

    # Write back
    with open(yaml_path, "w") as f:
        yaml.dump(data, f, default_flow_style=False, allow_unicode=True, sort_keys=False)

    print(f"\nAdded exception to {yaml_path.relative_to(REPO_ROOT)}")
    print(f"\nRun 'python3 scripts/exceptions.py apply' to regenerate out/queries/")

# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Exception management for osquery-defense-kit",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
            Commands:
              apply   Preprocess SQL → out/queries/ with exceptions injected
              list    Tabular display of all exceptions
              check   Flag expired/expiring-soon exceptions (exit 1 if found)
              report  Generate Markdown summary of all exceptions
              add     Interactive guided prompt to add a new exception
        """),
    )
    parser.add_argument("--env", default="personal", help="Environment profile name (default: personal)")
    subparsers = parser.add_subparsers(dest="command")

    # apply
    p_apply = subparsers.add_parser("apply", help="Inject exceptions into SQL copies")
    p_apply.add_argument("--output-dir", default=str(DEFAULT_OUTPUT_DIR), help="Output directory")

    # list
    p_list = subparsers.add_parser("list", help="List all exceptions")
    p_list.add_argument("--query", help="Filter by query path substring")

    # check
    p_check = subparsers.add_parser("check", help="Check for expired exceptions")
    p_check.add_argument("--warn-days", type=int, default=30, metavar="N",
                         help="Warn if expiring within N days (default: 30)")

    # report
    p_report = subparsers.add_parser("report", help="Generate Markdown report")
    p_report.add_argument("--output", help="Output file (default: stdout)")

    # add
    p_add = subparsers.add_parser("add", help="Interactively add an exception")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    env = load_environment(args.env)

    if args.command == "apply":
        cmd_apply(args, env)
    elif args.command == "list":
        cmd_list(args, env)
    elif args.command == "check":
        cmd_check(args, env)
    elif args.command == "report":
        cmd_report(args, env)
    elif args.command == "add":
        cmd_add(args, env)
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
