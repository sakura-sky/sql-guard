# Contributing to sql-guard

Thanks for considering a contribution. The project's goal is to be a **small,
auditable, deterministic** policy layer for LLM-generated SQL. We optimise for
clarity and easy review over feature breadth.

## Ground rules

- The guard must never call out to a network. All decisions are pure-Python
  over a parsed AST.
- Every public-API change ships with tests. PRs without tests are not merged.
- No new runtime dependencies without a strong case. sqlglot is the only
  required dep today; we want to keep that floor low.
- Public surfaces (anything in `__all__`) are covered by semver. Internal
  helpers (`_underscore_prefix`) may change between any two releases.

## Setting up

```bash
git clone https://github.com/seagrass/sql-guard
cd sql-guard
uv venv --python 3.12
source .venv/bin/activate
uv pip install -e ".[dev]"

pytest                  # full unit suite (no network, no GCP)
ruff check .            # lint
mypy src                # type check
```

## Adding a new rule

1. Subclass nothing — implement the `Rule` protocol:

   ```python
   @dataclass(frozen=True)
   class MyRule:
       def evaluate(self, ctx: RuleContext) -> GuardDecision | None:
           ...
   ```

2. Add tests under `tests/`. Cover both the firing case (returns a `DENY`)
   and the non-firing case (returns `None`).
3. If the rule is generally useful, add it to `default_rules(config)` in
   `sql_guard.py` and to `__all__` in `__init__.py`.
4. Update `CHANGELOG.md` under `[Unreleased]`.

## Adding a new cost model

1. Implement the `CostModel` protocol (one method, `bytes_to_usd`).
2. If the model is for a specific warehouse SKU, name it after the SKU:
   `SnowflakeStandardCost`, `RedshiftRA3Cost`, etc.
3. Tests + CHANGELOG.

## Adding dialect-specific behaviour

`sqlglot` handles parsing for every dialect. If a rule needs dialect-specific
logic (e.g. Snowflake's `QUALIFY` clause), check `ctx.config.dialect` inside
the rule rather than branching at the orchestrator level.

## Commit conventions

We follow [Conventional Commits](https://www.conventionalcommits.org/). The
prefixes we use are:

- `feat:` — new public API.
- `fix:` — bug fix.
- `security:` — guard tightening / closing a bypass.
- `perf:` — speedup with no behavioural change.
- `docs:` — README / CHANGELOG / docstrings only.
- `test:` — tests only.
- `refactor:` — non-functional internal cleanup.
- `build:` / `ci:` — packaging / CI infra.

Mark breaking changes with `!` after the type — `feat!: rename foo to bar`.

## Reporting bugs

GitHub issues are fine for non-security bugs. Include:

1. The exact SQL that triggered the issue.
2. The dialect.
3. The `SqlGuardConfig` you constructed.
4. What you expected, what happened, what the `GuardDecision` said.

For security reports, see `SECURITY.md`.

## Releasing (maintainers)

1. Bump `__version__` in `src/sql_guard/__init__.py` and in `pyproject.toml`.
2. Move `CHANGELOG.md` `[Unreleased]` notes under a new versioned heading.
3. Tag: `git tag v0.x.y && git push --tags`.
4. The release workflow publishes to PyPI on tag push.
