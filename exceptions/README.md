# Exception Management

This directory contains YAML exception files that are applied on top of upstream
detection SQL queries without modifying the originals.

## How It Works

A Python preprocessor (`scripts/exceptions.py`) reads YAML files here, injects
exception clauses into copies of the SQL queries, and writes the results to
`out/queries/`. The `make packs-local` target builds packs from `out/queries/`
instead of the original directories — upstream `make packs` is never touched.

## Directory Layout

```
exceptions/
  _shared/               # Reusable exception sets (include: from per-query files)
  c2/                    # Exceptions for detection/c2/ queries
  evasion/               # Exceptions for detection/evasion/ queries
  persistence/           # Exceptions for detection/persistence/ queries
  privesc/               # Exceptions for detection/privesc/ queries
environments/
  personal.yaml          # Default personal workstation profile
  default.yaml           # Minimal profile
```

## Filename Mapping

Exception file paths mirror the SQL paths with:
1. Leading `detection/` (or `policy/` etc.) stripped
2. Leading `N-` digit prefix stripped from the filename
3. `.sql` → `.yaml`

Example:
- `detection/privesc/1-unexpected-setxid-process.sql`
- → `exceptions/privesc/unexpected-setxid-process.yaml`

## Adding an Exception

### Interactive (recommended)

```bash
make exceptions-add
# or
python3 scripts/exceptions.py add
```

### Manual

Create or edit the relevant YAML file. Each exception needs:

```yaml
query: "detection/privesc/1-unexpected-setxid-process.sql"

exceptions:
  - type: path_in          # clause type (see below)
    field: "f.path"        # SQL field reference
    value: "/opt/myapp/helper"
    reason: "My app helper requires setuid"
    owner: "michael"
    added: "2024-01-15"
    expires: null          # or "2025-06-01" to auto-expire
```

## Exception Types

| Type | Generated SQL | Use when |
|------|--------------|----------|
| `path_in` | `AND f.path NOT IN ('value')` | Exact path match |
| `path_like` | `AND f.path NOT LIKE 'value'` | Glob/wildcard path |
| `name_in` | `AND p.name NOT IN ('value')` | Process name match |
| `exception_key_in` | `AND exception_key NOT IN ('value')` | Composite key match |
| `exception_key_like` | `AND NOT exception_key LIKE 'value'` | Composite key pattern |
| `not_block` | `AND NOT (cond1 AND cond2...)` | Multi-condition block |
| `authority_in` | `AND s.authority NOT IN ('value')` | macOS code signing authority |

Multiple exceptions of the same type+field are batched into `NOT IN (...)` lists.

## Shared Exception Sets

Files in `_shared/` have no `query:` field and can be included from per-query files:

```yaml
# exceptions/privesc/unexpected-setxid-process.yaml
query: "detection/privesc/1-unexpected-setxid-process.sql"
include:
  - "_shared/homebrew-paths.yaml"

exceptions:
  - type: path_in
    ...
```

## Checking for Expired Exceptions

```bash
make exceptions-check          # exit 1 if any expired
make exceptions-check WARN=30  # warn if expiring within 30 days
```

## Viewing All Exceptions

```bash
make exceptions-list           # tabular view
make exceptions-report         # full Markdown report → out/exceptions-report.md
```

## Applying Exceptions

```bash
make packs-local               # apply + build packs from out/queries/
# or just apply without building:
python3 scripts/exceptions.py apply --env personal
```
