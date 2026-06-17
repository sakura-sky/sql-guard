# Security Policy

`sql-guard` is a security-adjacent package — its job is to keep PII out of
LLM-driven SQL workloads and to bound the cost of queries. Bugs in this code
can have data-disclosure or cost-overrun consequences, so we treat security
reports as P0.

## Reporting a vulnerability

**Please do not file public issues for security bugs.** Use one of:

- Email: `security@<your-org>.example` (replace with the maintainer's address
  before publishing).
- GitHub Security Advisory: open a draft advisory at
  <https://github.com/seagrass/sql-guard/security/advisories/new>.

Include:

1. The exact SQL that exposed the issue.
2. The `SqlGuardConfig` (especially `dialect`, `pii_denylist`,
   `allowed_tables`).
3. The `GuardDecision` you got vs. the one you expected.
4. The version of `sql-guard` you reproduced against.
5. Optional: a minimal Python repro under 30 lines.

We aim to acknowledge within 3 business days and to ship a fix or mitigation
guidance within 14 days for clear vulnerabilities.

## Scope

In scope:

- Bypasses of the PII denylist (any SQL that projects a denylisted column but
  the guard does not deny).
- Bypasses of the table allowlist.
- DML / DDL accepted by the guard.
- Cost-cap bypasses (queries that exceed `max_cost_usd_hard` or
  `max_bytes_billed` but receive `ALLOW` or `CONFIRM`).
- Parser crashes that take down the host process instead of returning a
  `DENY`.

Out of scope:

- LLM prompt injection that doesn't end in a bypass. The guard's contract is
  about the SQL it receives, not about what the model was told.
- Bugs in `sqlglot` itself — please report those upstream at
  <https://github.com/tobymao/sqlglot>. We will mitigate downstream when we
  can.
- Issues that only manifest with a `rules=[]` custom rule list. If you opt
  out of the defaults, the defaults can't protect you.

## Threat model

`sql-guard` assumes:

- The LLM is **untrusted**. Any string it produces can be adversarial.
- User questions are **untrusted**. They can contain prompt-injection payloads.
- The `SqlGuardConfig` (denylist, allowlist, thresholds) is **trusted**. It's
  authored by the operator, not the LLM.
- The host process's identity (BigQuery / Snowflake creds) is the same
  whether the guard runs or not — the guard does not authenticate or
  authorise the user.

The guard is **one** of multiple layers an operator should run. A complete
defence-in-depth stack also includes IAM-level row/column policies, audit
logging, and warehouse-side maximum-bytes-billed enforcement.
