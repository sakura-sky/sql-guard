# Changelog

All notable changes to `sql-guard` are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0] — 2026-08-17

**Renamed on PyPI to `agent-sql-guard`.** The unqualified name `sql-guard` was
already taken by an unrelated data-quality package, so 0.1.x was never actually
published; this is the first release to reach PyPI. Install with:

```bash
pip install agent-sql-guard
```

**The import is unchanged** — still `from sql_guard import ...`. Only the
dependency spec moves:

```toml
# before (never resolved to this project)
"sql-guard>=0.1.1"
# after
"agent-sql-guard>=0.2.0"
```

The GitHub repository, module and all APIs keep the `sql_guard` name.

Security release. Closes eight PII-denylist bypasses: two found by adversarial
review of a deployed agent, and six more found while fixing those. Every one
was confirmed against 0.1.1 with a reproducing query before being fixed, and
each has a regression test. **Contains breaking behaviour changes** — queries
that 0.1.1 allowed are now denied. That is the point of the release; see
*Upgrading*.

The most severe was not in the original report: `SELECT c FROM tbl AS c`
returned every column of every row, PII included, and the guard auto-executed
it.

### Security
- **PII denylist is now enforced in every query scope, not just the outermost
  select list.** `PiiProjectionRule` called `outermost_projection_names`, so
  any inner scope that renamed a denied column laundered it past the guard.
  All of these returned `confirm` on 0.1.1 and are denied as of 0.2.0:

  ```sql
  WITH c AS (SELECT BillingCity AS city FROM `p.d.t`) SELECT city FROM c
  SELECT x FROM (SELECT BillingCity AS x FROM `p.d.t`)
  SELECT uid FROM `p.d.t` UNION ALL SELECT c FROM (SELECT email AS c FROM `p.d.t`)
  WITH a AS (SELECT email AS e1 FROM `p.d.t`), b AS (SELECT e1 AS e2 FROM a) SELECT e2 FROM b
  ```

  Matching applies to the underlying column names within each scope, so an
  alias never launders a denied column.
- **Denied columns can no longer be used to probe values.** The denylist gated
  projection only, so `WHERE BillingCity = 'Columbus'`, `GROUP BY`, `HAVING`
  and `ORDER BY` references all passed — none return the column, but each
  answers a yes/no question about its value, and enough queries reconstruct it.
  The new `pii_mode` config switch denies *any* reference by default.
- **`SELECT *` is rejected in every scope,** not just the outermost one. Once
  PII checking is all-scope, a star inside a CTE or derived table makes that
  scope's projection list unresolvable, so the guard cannot prove a denied
  column is absent — same rationale as the existing top-level rule.
- **Qualified `t.*` is now caught.** It parses as an `exp.Column` wrapping a
  `Star`, which the previous `isinstance(projection, exp.Star)` check missed,
  so `SELECT t.* FROM tbl t` bypassed the star rule even at the top level.
- **Whole-row references by row-source alias are rejected.** `SELECT c FROM tbl AS c`
  returns every column in the row as a struct — strictly more powerful than the
  `SELECT *` the guard already blocked, and it parsed as an ordinary column
  named `c`, so the denylist had nothing to match. Also covers
  `TO_JSON_STRING(c)`, `ARRAY_AGG(c)`, `STRUCT(c)`, the unaliased
  `SELECT tbl FROM tbl` form, CTE names, derived-table aliases
  (`SELECT d FROM (SELECT ...) AS d`), and `VALUES` / `PIVOT` aliases.
  New `NoUnresolvableColumnsRule`.

  The rule resolves ambiguity from the AST rather than denying on a bare name
  collision, which would have made it unusable: a table contributes only the
  name it is addressable by (an aliased `p.d.status AS s` does not reserve
  `status`), and a CTE or derived table publishes its own output names, so
  `WITH revenue AS (SELECT ..., SUM(x) AS revenue ...) SELECT revenue FROM revenue`
  — a mainstream idiom — is correctly read as a column reference.
- **ClickHouse `COLUMNS('regex')` is rejected.** It expands to many columns but
  parses with no `Star` node at all, so a star check keyed on `exp.Star` alone
  never saw it.
- **`NATURAL JOIN` is rejected.** It joins on whichever columns the tables
  share — a schema fact the guard does not have, so it cannot rule out a denied
  column among them. `JOIN ... USING (...)` remains allowed and is now read.
- **Stars nested inside a wrapping construct are caught.** The star check only
  inspected the projection's root node, so `OBJECT_CONSTRUCT(*)` (Snowflake),
  `COLUMNS(*)` (DuckDB), `* APPLY(f)` (ClickHouse) and `ROW(c.*)` (Trino) all
  passed. It is now a deep walk, with `COUNT(*)` / `COUNT(DISTINCT *)` as the
  explicit carve-out.
- **Column names that never become an `exp.Column` are now read.** sqlglot
  parses several positions as bare `exp.Identifier`, so reference mode's
  `find_all(exp.Column)` sweep missed them: `JOIN ... USING (email)`,
  `... AS g(email)` column aliases, and `STRUCT('x' AS email)` field names.
  `JOIN ... USING (email)` was a working single-query value oracle.
- **Aggregation is no longer a blanket PII exemption.** Every `exp.AggFunc`
  counted as PII-neutralising, so `MAX(email)`, `MIN(email)`,
  `ARRAY_AGG(email)`, `STRING_AGG(email)` and `ANY_VALUE(email)` returned real
  values through `pii_mode="project"`. Only aggregates that reduce to a derived
  statistic (`COUNT`, `COUNTIF`, `SUM`, `AVG`, `APPROX_COUNT_DISTINCT`,
  `STDDEV`, `VARIANCE`) qualify now.

### Added
- `pii_mode` on `SqlGuardConfig` and `SqlGuardConfig.from_settings`, typed as
  `PiiMode = Literal["reference", "project"]`. Defaults to `"reference"`
  (deny any reference to a denied column). `"project"` restores 0.1.1-style
  projection-only checking, still applied across all scopes. An invalid value
  raises `ValueError` rather than silently falling back to a default.
- `NoSelectStarRule` — the all-scope star rule. `NoTopLevelStarRule` remains
  importable as an alias of it.
- `NoUnresolvableColumnsRule` — rejects whole-row table-alias references and
  `NATURAL JOIN`. Added to `default_rules` between the star rule and the PII
  rule.
- AST helpers for custom rules: `all_selects`, `all_projection_names`,
  `all_referenced_column_names`, `has_select_star`, `whole_row_references`.

### Changed
- `default_rules` substitutes `NoSelectStarRule` for `NoTopLevelStarRule`
  (the same object under its new name). Ordering semantics are unchanged: the
  star rule still runs before `PiiProjectionRule`, which now also guarantees a
  star is rejected before the PII check tries to resolve a projection list it
  cannot see.
- `outermost_projection_names` and `has_top_level_select_star` are retained
  and still outermost-only; their docstrings now warn against using them for
  denylist enforcement. `has_top_level_select_star` does now recognise `t.*`.
- **Minimum Python is now 3.11.** The package has imported `enum.StrEnum`
  (3.11+) since 0.1.0 while advertising `requires-python = ">=3.10"`, so
  `import sql_guard` raised `ImportError` on 3.10 and that CI matrix job could
  never have passed. `requires-python`, the classifiers, ruff's
  `target-version`, mypy's `python_version` and the CI matrix now agree on
  3.11. No source change was needed — this documents what the code already
  required.

### Fixed
- `format_cost` no longer wraps `math.floor` in a redundant `int()`
  (`math.floor` already returns an `int`). Behaviour is unchanged; this clears
  a `ruff check` failure.
- `_projection_names` reads `.this` instead of calling sqlglot's untyped
  `unalias()`. Identical result — `unalias` returns `self.this` for an `Alias`
  — but it clears the only `mypy --strict` error in the package.

### Known limits (documented, not fixed)

The denylist matches column names in the SQL text and the guard has no schema,
so these remain out of scope and are now stated explicitly in the README:
PII inside JSON/VARIANT/STRUCT payloads addressed by string literals
(`JSON_VALUE(payload, '$.email')`), re-identification through non-PII columns,
and side channels such as row counts and dry-run byte counts.

Also uncovered: selecting a STRUCT column whole, and `UNNEST` aliases over an
array of structs — both return every field without naming one, and neither is
distinguishable at parse time from the legitimate scalar-array form.

Separately: several entries in `_PII_SAFE_FUNC_KEYS` (`sha256`,
`farm_fingerprint`) match no sqlglot key and never fire, so those spellings of
hashed PII are *denied* rather than treated as neutralised. `md5` does match
via the `TO_HEX(MD5(x))` folding, so that spelling is permitted under
`pii_mode="project"` — the two are inconsistent. Left as-is because the
inconsistency errs toward denial; revisit deliberately when deciding whether
hashed PII is acceptable output.

### Known issues (unfixed, pre-existing)

- `SelectOnlyRule` accepts `exp.Select | exp.Union`, but sqlglot 26.x derives
  `Except` and `Intersect` from `SetOperation` rather than `Union`, so a
  top-level `EXCEPT DISTINCT` / `INTERSECT` is rejected as "Only SELECT
  statements are allowed". Fails closed, so it is an availability bug rather
  than a security one, but it makes the `Except`/`Intersect` branch of
  `outer_selects` dead code for top-level set operations.
- `AllowedTablesRule` runs last, so a query that is both off-allowlist and
  star/PII-violating is always reported as the latter. Telemetry built on
  `decision.reason` will under-count allowlist breaches.

### Upgrading

Queries denied by 0.2.0 that 0.1.1 allowed fall into two groups:

1. **Bypasses** — alias laundering, inner-scope and nested stars, whole-row
   aliases, `NATURAL JOIN`, identifier-only column references, and PII through
   value-preserving aggregates. There is no supported way to re-permit these,
   by design. Whole-row alias references are fixed by qualifying them
   (`SELECT c.col` rather than `SELECT c`).
2. **Denied columns in predicates** — set `pii_mode="project"` to restore the
   old behaviour. Understand that this re-opens the value-probing oracle
   described above; prefer narrowing the denylist or exposing a pre-masked
   view.

The bundled `Q1` identity-resolution query (normalising `email`/`mobile` in a
CTE, projecting only `COUNTIF` aggregates) is denied in **both** modes: the CTE
scope projects the denied columns, and `COUNTIF(email_norm = 'target')` is
itself a value oracle. Aggregates over denied columns are not safe under this
threat model. Move such normalisation into a warehouse view the denylist does
not cover.

## [0.1.1] — 2026-06-19

### Added
- `format_cost(cost_usd)` helper exported from the top-level package.
  Renders sub-cent BigQuery dry-run costs with enough precision to show at
  least two significant figures (`$0.00000019` instead of `$0.00`), keeps
  two decimals for cent-plus costs, and prints negative values as
  `-$0.01` for use as a demo-mode auto threshold.
- `CostCapRule` reason strings (allow / confirm / hard-deny) now render
  costs via `format_cost`, so the trace panel and logs no longer round
  sub-cent estimates to `$0.00`.

### Documentation
- Inline comment on the auto-threshold branch of `CostCapRule` documents
  the `cost_usd <= threshold` semantics and the negative-threshold trick
  for forcing confirm-on-every-query during demos.

## [0.1.0] — 2026-06-03

### Added
- Initial release.
- `SqlGuard` policy engine with `evaluate_static`, `evaluate_cost`, and
  combined `evaluate` entry points.
- Built-in rules: `SelectOnlyRule`, `NoEmbeddedDmlRule`, `NoTopLevelStarRule`,
  `PiiProjectionRule`, `AllowedTablesRule`.
- Pluggable `Rule` protocol and `default_rules(config)` factory — drop in
  custom rules without forking.
- Multi-dialect support via the `dialect` config field (any dialect sqlglot
  understands).
- Pluggable cost models via the `CostModel` protocol —
  `BigQueryOnDemandCost`, `FlatRateCost`, and user-supplied models.
- `PiiDenylist` with exact + substring matching, loadable from a flat JSON.
- `py.typed` marker for downstream mypy / pyright users.
- AST-walk helpers exported for users writing custom rules:
  `outer_selects`, `outermost_projection_names`, `referenced_tables`,
  `has_top_level_select_star`, `format_bytes`.

### Security
- Aliased PII columns (`SELECT email AS x`) are now flagged.
- PII in the right arm of `UNION`/`UNION ALL`/`EXCEPT`/`INTERSECT` is now
  flagged.
- `SELECT * EXCEPT(...)` is rejected — the guard cannot prove the EXCEPT
  list enumerates every PII column.

[Unreleased]: https://github.com/sakura-sky/sql-guard/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/sakura-sky/sql-guard/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/sakura-sky/sql-guard/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/sakura-sky/sql-guard/releases/tag/v0.1.0
