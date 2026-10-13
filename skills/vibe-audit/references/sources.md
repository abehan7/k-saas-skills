# vibe-audit — sources and dated facts

Facts that change over time live here, not in SKILL.md. Each line says when it was last checked against the primary source.

| Fact | Source | Last verified |
|---|---|---|
| UpGuard found **16,326** Supabase databases with publicly readable tables; over half showed signs of personal data (reported 2026-09-26). Cause: misconfigured access controls, public keys treated as secret. | [Cybernews](https://cybernews.com/news/16000-supabase-databases-exposed/) | 2026-10-14 |
| Moltbook (2026-02-02): a Supabase key in client-side JavaScript + no RLS exposed ~1.5M API tokens, 35K emails, ~4.75M records; read **and write** access. | [Wiz](https://wiz.io/blog/exposed-moltbook-database-reveals-millions-of-api-keys) | 2026-10-14 |
| Supabase: new `public` tables are no longer auto-exposed to the Data API — default for new projects from 2026-05-30, for **all existing projects from 2026-10-30**. Exposed tables need explicit `GRANT`s; RLS is unchanged and still required. | [Supabase changelog](https://supabase.com/changelog/45329-breaking-change-tables-not-exposed-to-data-and-graphql-api-automatically.md) | 2026-10-14 |
| Toss Payments keys: client keys `test_gck`/`live_gck`, `test_ck`/`live_ck` (browser OK); secret keys `test_gsk`/`live_gsk`, `test_sk`/`live_sk` (server only); mixing test/live → `INVALID_API_KEY`. | [Toss docs — API 키](https://docs.tosspayments.com/reference/using-api/api-keys) | 2026-10-14 |
| CVE-2025-48757 (Lovable): insufficient RLS let unauthenticated attackers read/write tables (CVSS 9.3). | [Superblocks write-up](https://www.superblocks.com/blog/lovable-rls-breach) | from research notes — re-check |
| Escape scanned 5,600+ vibe-coded apps: 2,000+ vulnerabilities, 400+ exposed secrets. | research notes (vendor study) | from research notes — re-check |

Security-vendor statistics come from companies that sell scanning — say "보안 업체 스캔 결과" when quoting them.
