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
2. **PII column denylist.** Projections that touch denylisted columns are
   rejected. Catches aliased PII (`SELECT email AS x`), PII through transforms
   (`SELECT LOWER(email)`), and the right arm of a `UNION ALL`.
3. **No top-level `SELECT *`.** Bare `*`, `* EXCEPT(...)`, and `* REPLACE(...)`
   are all rejected — the guard can't prove EXCEPT enumerates every PII column.
4. **Table allowlist.** Only fully-qualified tables you approved can be
   referenced. CTE aliases are excluded.
5. **Cost cap.** Given the bytes-processed figure from a dry-run, the guard
   returns `allow` below your auto threshold, `confirm` in between, and `deny`
   above the hard cap or bytes-billed ceiling.

Every check is a `Rule` you can replace or compose with.

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
  the guard takes your word for it.
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
pip install sql-guard            # core: only depends on sqlglot
pip install 'sql-guard[adk]'     # + Google ADK + BigQuery client for the
                                 #   FunctionTool integration
```

Python 3.10+ supported.

## License

Apache-2.0.

## See also

- `examples/` — runnable scripts: minimal use, multi-dialect, custom rule.
- `CHANGELOG.md` — semver release notes.
- `CONTRIBUTING.md` — how to add rules / cost models / dialects.
- `SECURITY.md` — disclosure process and threat model.
