# Changelog

## 0.1.0 — Day 1 · vibe-audit

- `vibe-audit`: pre-launch security audit that probes instead of advising — bundle/env secret scan (Stripe, Toss, Supabase service_role & sb_secret_, AI keys, public-prefixed secrets), anon-key RLS probe + SQL checks (RLS off, views without security_invoker, public buckets), two-user IDOR probe, rate-limit probe, 주민등록번호/phone scan in logs, Korean `audit-report.md` with CI exit code.
