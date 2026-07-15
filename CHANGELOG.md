# Changelog

All notable changes to `sql-guard` are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[Unreleased]: https://github.com/sakura-sky/sql-guard/compare/v0.1.1...HEAD
[0.1.1]: https://github.com/sakura-sky/sql-guard/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/sakura-sky/sql-guard/releases/tag/v0.1.0
