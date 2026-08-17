# sql-guard

**Deterministic policy engine for LLM-generated SQL.**
Multi-dialect (BigQuery, Snowflake, Postgres, Trino, DuckDB, ClickHouse, MySQL, …) via sqlglot.

When an LLM agent writes SQL on a user's behalf, the system prompt is **not a
trust boundary** — prompt injection through user input or tool outputs can
talk a model out of any rule you stated in plain English. `sql-guard` is the
deterministic floor: before the SQL the model produced hits your warehouse,
the guard parses it, runs your policy, and returns an `allow` / `confirm` /
`deny` decision. There is no LLM in the guard path.

```python
from sql_guard import PiiDenylist, SqlGuard, SqlGuardConfig

guard = SqlGuard(SqlGuardConfig.from_settings(
    pii_denylist=PiiDenylist.from_mapping({
        "columns": ["email", "phone_number", "ssn"],
        "substrings": ["address"],
    }),
    allowed_tables=["my-project.analytics.orders"],
    dialect="bigquery",          # or "snowflake", "postgres", "trino", ...
))

decision = guard.evaluate_static(
    "SELECT customer_id, COUNT(*) FROM `my-project.analytics.orders` GROUP BY 1"
)
if decision.denied:
    return decision.reason       # surface to the user; do not call the warehouse
```

## What it enforces (out of the box)

1. **Single SELECT only.** DML, DDL, scripts, multi-statement payloads — all
   rejected. Even if buried in subqueries.
2. **PII column denylist.** By default, *any reference* to a denylisted column
   is rejected — in the select list, `WHERE`, `GROUP BY`, `HAVING`, `ORDER BY`
   or a `JOIN` condition, at any nesting depth. Catches aliased PII
   (`SELECT email AS x`), PII through transforms (`SELECT LOWER(email)`),
   the right arm of a `UNION ALL`, and columns renamed inside a CTE or derived
   table. See [PII modes](#pii-modes).
3. **No `SELECT *` in any scope.** Bare `*`, `* EXCEPT(...)`, `* REPLACE(...)`
   and qualified `t.*` are all rejected, inside CTEs and subqueries as well as
   at the top level — the guard can't prove EXCEPT enumerates every PII column,
   nor what `*` expands to. The check is a deep walk, so stars wrapped in a
   function (`OBJECT_CONSTRUCT(*)`, `COLUMNS(*)`, `* APPLY(f)`) are caught too;
   `COUNT(*)` is the deliberate exception.
4. **Nothing whose columns the guard can't enumerate.** A bare table alias in a
   value position (`SELECT c FROM tbl AS c`) returns the whole row as a struct,
   and `NATURAL JOIN` joins on unknown shared columns. Both are rejected for the
   same reason as `SELECT *`.
5. **Table allowlist.** Only fully-qualified tables you approved can be
   referenced. CTE aliases are excluded.
6. **Cost cap.** Given the bytes-processed figure from a dry-run, the guard
   returns `allow` below your auto threshold, `confirm` in between, and `deny`
   above the hard cap or bytes-billed ceiling.

Every check is a `Rule` you can replace or compose with.

### PII modes

`pii_mode` controls how far the denylist reaches.

| Mode | Denies | Use when |
|---|---|---|
| `"reference"` (default) | Any reference to a denied column, in any clause and any scope. | The agent must not learn PII values at all. |
| `"project"` | Only projections of denied columns — checked in every scope. | Predicate access to PII is a deliberate, accepted trade-off. |

The default is the strict one because projection-only checking leaves the
values reachable. A denied column in a `WHERE` clause never appears in the
output, but the row count still answers a yes/no question about it:

```sql
-- Passes a projection-only guard. Returns 0 or non-zero.
SELECT COUNT(*) FROM `p.d.orders` WHERE billing_city = 'Columbus'
```

Repeat with `LIKE 'a%'`, `> 'm'`, and so on, and the value falls out in a
handful of queries. `GROUP BY`, `HAVING` and `ORDER BY` leak the same way.

**The loosening path.** If your deployment genuinely needs to filter on PII —
segmenting on a hashed identifier, say, or counting non-null contact rows —
set `pii_mode="project"`:

```python
SqlGuardConfig.from_settings(..., pii_mode="project")
```

That re-permits denied columns in predicates while still rejecting every
projection of them, in every scope. Prefer narrowing the denylist, or exposing
a pre-masked warehouse view the denylist doesn't cover, before reaching for it.

Note that "aggregate" is not a safe harbour in either mode. `MAX(email)`,
`ARRAY_AGG(email)` and `STRING_AGG(email)` return real values and are rejected;
only aggregates that reduce to a statistic (`COUNT`, `SUM`, `AVG`, `STDDEV`, …)
are treated as PII-neutralising, and then only under `pii_mode="project"`.

### What the denylist does not cover

The guard matches **column names in the SQL text**. It has no schema, so:

- **PII inside JSON / VARIANT / STRUCT payloads** is not covered.
  `JSON_VALUE(payload, '$.email')` names only `payload`; the field name is a
  string literal the engine resolves. The same applies to selecting a struct
  column whole (`SELECT contact FROM t`) and to `UNNEST` aliases over an array
  of structs (`SELECT s FROM t, UNNEST(t.contacts) AS s`) — both return every
  field without naming one. **Denylist the containing column.**
- **Re-identification through non-PII columns** is out of scope. If `uid` maps
  1:1 to a person, blocking `email` does not prevent correlation with outside
  data.
- **Side channels** — row counts, dry-run byte counts and error messages carry
  bits about denied values even when every direct reference is refused.

These are limits of a parse-level guard, not bugs. Warehouse-side column
security is the durable answer; `sql-guard` is defence in depth.

### Scopes

Denylist and star checks run against **every** `SELECT` scope — CTE bodies,
derived tables, scalar and `IN` subqueries, and each arm of a set operation —
matching on the underlying column names in the scope that names them. An alias
therefore cannot launder a denied column:

```sql
-- Denied: the CTE scope still names billing_city.
WITH c AS (SELECT billing_city AS city FROM `p.d.orders`)
SELECT city FROM c
```

Checking only the outermost select list would see `city` and let it through.
The same applies through derived tables, `UNION` arms, and multi-hop alias
chains (`a AS (...) → b AS (...) → SELECT`).

### The cost-cap rule in detail

Three independent thresholds bound any single query:

| Threshold | Default | Outcome |
|-----------|---------|---------|
| `max_cost_usd_auto` | $0.10 | Auto-execute below; ask-confirmation above. |
| `max_cost_usd_hard` | $20.00 | Refuse even with user confirmation. |
| `max_bytes_billed` | 10 GiB | Hard byte cap. Bypasses the cost model so a pricing-model bug can't paper over an unbounded scan. |

The cost model is a `Protocol` — `BigQueryOnDemandCost($5/TiB)` is the
default; `FlatRateCost(usd_per_byte=...)` and user-supplied implementations
(Snowflake credits, Redshift node-hours) plug straight in. Per-warehouse
billing models stay accurate without forking.

Plus a dry-run-only mode where the guard runs but never lets execution
through — useful for sandboxes or onboarding a new tenant.

## What it deliberately does not do

- It does not call BigQuery / Snowflake / anything. Dry-runs are the caller's
  job; pass `bytes_processed` to `evaluate_cost`. Keeps the guard testable
  without credentials and dialect-agnostic.
- It does not introspect table schemas. If you say "this table is allowed,"
  the guard takes your word for it. This is why `SELECT *` is rejected
  everywhere: without a schema the guard cannot enumerate what `*` returns.
- It does not authorise the user. Identity, IAM, row-level security: not in
  scope. The guard is a *policy* layer, not a *permissions* layer.

## Multi-dialect

`sqlglot` parses every dialect listed below. Pass `dialect="..."` and the
same rule set applies:

| Dialect | Status |
|---|---|
| `bigquery` (default) | Heavy real-world use |
| `snowflake` | Tested |
| `postgres` | Tested |
| `trino` / `presto` | Tested |
| `duckdb` | Tested |
| `clickhouse` | Tested |
| `mysql` | Tested |
| `oracle`, `databricks`, `redshift`, `tsql`, others | Should work — file an issue if not |

## Pluggable rules

A `Rule` is anything with an `evaluate(ctx: RuleContext) -> GuardDecision | None`
method. Return `None` to pass; return a `GuardDecision` (typically a DENY) to
short-circuit.

```python
from dataclasses import dataclass
from sql_guard import GuardDecision, GuardOutcome, RuleContext, SqlGuard, default_rules

@dataclass(frozen=True)
class RequirePartitionFilter:
    column: str

    def evaluate(self, ctx: RuleContext) -> GuardDecision | None:
        sql = ctx.sql.lower()
        if "where" not in sql or self.column.lower() not in sql:
            return GuardDecision(
                outcome=GuardOutcome.DENY,
                reason=f"Queries must filter on {self.column} for partition pruning.",
            )
        return None

guard = SqlGuard(config, rules=[RequirePartitionFilter("order_date"), *default_rules(config)])
```

See `examples/03_custom_rule.py` for a runnable version.

## Pluggable cost models

```python
from sql_guard import BigQueryOnDemandCost, FlatRateCost, SqlGuardConfig

# Default — BigQuery on-demand $5/TiB
SqlGuardConfig.from_settings(..., cost_model=BigQueryOnDemandCost())

# Custom enterprise rate
SqlGuardConfig.from_settings(..., cost_model=BigQueryOnDemandCost(usd_per_tib=3.0))

# Flat-rate (testing or contractual SKUs)
SqlGuardConfig.from_settings(..., cost_model=FlatRateCost(usd_per_byte=1e-9))

# Or your own — anything with `bytes_to_usd(int) -> float` is a CostModel.
```

## How is this different from …

- **NeMo Guardrails / LangChain guardrails / Anthropic Guardrails**: those
  layers sit at the *LLM message* boundary and rely on the model classifying
  its own output. `sql-guard` sits at the *SQL execution* boundary and uses a
  deterministic parser. The two are complementary — guardrails catch
  malicious *intent*, `sql-guard` catches malicious *queries*.
- **LLM-as-judge for SQL**: another LLM call costs tokens and is itself
  vulnerable to prompt injection. `sql-guard` is pure-Python, sub-millisecond,
  and can't be talked out of its rules.
- **Warehouse-side RLS / column-level security**: the right long-term
  answer, but requires coordinated schema work. `sql-guard` gets you
  defence-in-depth today with a config file, not a migration.
- **Hand-rolled regex over generated SQL**: regex over SQL is famously
  brittle. `sql-guard` parses the actual AST.

## Install

```bash
pip install agent-sql-guard            # core: only depends on sqlglot
pip install 'agent-sql-guard[adk]'     # + Google ADK + BigQuery client for the
                                       #   FunctionTool integration
```

The distribution is `agent-sql-guard`; the import is `sql_guard`:

```python
from sql_guard import SqlGuard, SqlGuardConfig
```

The unqualified name `sql-guard` on PyPI is an unrelated data-quality package
by another author.

Python 3.11+ supported.

## License

Apache-2.0.

## See also

- `examples/` — runnable scripts: minimal use, multi-dialect, custom rule.
- `CHANGELOG.md` — semver release notes.
- `CONTRIBUTING.md` — how to add rules / cost models / dialects.
- `SECURITY.md` — disclosure process and threat model.
