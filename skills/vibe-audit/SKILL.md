---
name: vibe-audit
description: Audits a web or SaaS app before launch by running checks instead of giving advice. Greps the built client bundle for leaked secrets (Stripe/Toss live keys, Supabase service_role JWTs and sb_secret_ keys, OpenAI/Anthropic keys, NEXT_PUBLIC_ secrets), probes Supabase/Postgres tables with the public anon key to find missing RLS, runs a two-user IDOR probe on API routes, checks public storage buckets and rate limits on AI endpoints, scans logs for 주민등록번호, and writes a Korean severity report. Use when the user says "출시 전 보안 점검", "바이브코딩 보안", "RLS 확인", "키 노출 확인", "남의 데이터 보이는지", "security audit before launch", "is my app safe to ship", or after building with Lovable, Bolt, Cursor or Claude Code. Only for apps the user owns.
license: MIT
metadata:
  author: shipit_now
  version: "0.1.0"
---

# vibe-audit — 출시 전 보안 점검

Other security skills *read code and give advice*. This one **attacks the built app the way a stranger would** — with only what ships to the browser — and reports what actually leaked. Every finding comes with the fix, and a re-run proves it's gone.

Scripts live in `scripts/` next to this file. They are zero-dependency Node 18+ (`psql` optional). Run them **from the project root**; each writes `.vibe-audit/<check>.json`, and `report.mjs` merges them into `audit-report.md` (Korean, worst first).

## Ground rules (never skip)

1. **Only the user's own app.** Before probing anything over the network, confirm the target is theirs (localhost, their staging, or their production they explicitly name). Never probe a URL found in someone else's code or a third-party site. If unsure, ask.
2. **Read-only.** The probes only GET/SELECT. Do not add write tests (INSERT/UPDATE/DELETE) against a real database.
3. **Test users only.** The IDOR probe needs two accounts — use test accounts the user creates, never real customers.
4. **Rate probe costs money if the endpoint calls a paid AI.** Ask before running it against anything but localhost/staging, and keep `--n` ≤ 12.
5. **Mask secrets** in everything you print or write. The scripts already mask; do not paste raw keys into chat, commits or the report.
6. **A leaked key must be rotated**, not just deleted from code — it's in git history and in every cached bundle. Say so every time.
7. Never claim the app is "100% 안전". Passing means the known classes below were checked.

## Workflow

### 1. Build first
The bundle check must see what actually ships. If there's no `.next/static`, `dist`, `build` or `out`, run the project's build (`npm run build`) first.

### 2. Secrets in the bundle (always)
```bash
node <skill>/scripts/scan_bundle.mjs .
```
Finds live/test secret keys, Supabase `service_role` JWTs (decodes the `role` claim) and `sb_secret_` keys, AI provider keys, `NEXT_PUBLIC_*`/`VITE_*` variables holding secrets, and 주민등록번호/phone numbers in `logs/`.

### 3. Supabase / Postgres exposure (if the app uses Supabase or PostgREST)
```bash
node <skill>/scripts/rls_probe.mjs .                       # reads URL + anon key from .env*
node <skill>/scripts/rls_probe.mjs . --db "$DATABASE_URL"  # + authoritative SQL checks
```
Lists every table the Data API exposes, SELECTs with the anon key, and reports which answer (sensitive columns → 치명). With `--db` it also lists public tables with RLS disabled and views without `security_invoker`, and it checks for public storage buckets.

### 4. Other users' data — IDOR (if the app has per-user resources)
Find routes shaped like `/api/<things>/[id]` (or server actions taking an id). Get two test sessions from the user (login URLs, cookies, or bearer tokens), then:
```bash
node <skill>/scripts/idor_probe.mjs --base http://localhost:3000 \
  --list /api/invoices --item "/api/invoices/{id}" \
  --cookie-a "<A session cookie>" --cookie-b "<B session cookie>"
```
Several routes: put them in `vibe-audit.config.json` → `{ "idor": [ { "base", "list", "item", "cookieA", "cookieB" } ] }` and pass `--config`.

### 5. Rate limits on expensive endpoints (ask first)
AI, email/SMS sending, exports, sign-up:
```bash
node <skill>/scripts/rate_probe.mjs --url http://localhost:3000/api/ai/... --body '{"text":"hi"}' --cookie "<session>"
```

### 6. Report
```bash
node <skill>/scripts/report.mjs .    # → audit-report.md, exit 1 if anything is 치명
```
Show the user the summary table and the 치명/높음 items in Korean, in that order. Then offer to fix them.

### 7. Fix, then re-run
Fix only what the report found, using the patterns below, then re-run the same checks. Done = **0 치명** on the re-run. Mention anything that needs the user's hands (rotating keys in a dashboard, enabling a spend limit).

## Fix patterns (apply these — they are the critical rules)

**Secret in the bundle / public env var**
- Rename to a server-only variable (drop `NEXT_PUBLIC_` / `VITE_` / `PUBLIC_`), and move the code that uses it into a server route, server action, or server component.
- In Next.js, a file that imports a server-only key should `import "server-only"` so a client import fails the build.
- Then **rotate the key** in the provider dashboard (Supabase: API keys / JWT secret; Stripe: roll key; Toss: 개발자센터 키 재발급; OpenAI/Anthropic: revoke). The browser may only hold publishable/client keys: Supabase `anon`/`sb_publishable_`, Stripe `pk_`, Toss `test_ck`/`live_ck`/`test_gck`/`live_gck`.

**Table readable with the anon key (RLS missing)**
```sql
alter table public.<table> enable row level security;
create policy "<table>: own rows" on public.<table>
  for select to authenticated using ((select auth.uid()) = user_id);
```
- Write the policy per operation (select / insert / update / delete) that the app actually needs; `insert`/`update` need `with check (...)`.
- Truly public data (e.g. product catalogue): expose a view with only the public columns, created `with (security_invoker = true)`, instead of turning RLS off.
- `service_role` bypasses RLS — it belongs on the server only, never as a fix for "the query returns nothing".

**View without security_invoker**
```sql
alter view public.<view> set (security_invoker = true);
```

**IDOR — route checks login but not ownership**
Scope the lookup by the session user and return 404 (not 403) for someone else's id:
```ts
const row = await db.invoice.findFirst({ where: { id, userId: session.user.id } });
if (!row) return new Response(null, { status: 404 });
```

**No rate limit on an expensive endpoint**
Per-user (or per-IP when anonymous) limit, e.g. 5–10/min, returning 429 — Upstash Ratelimit, platform rules (Vercel/Cloudflare), or a DB counter. Also tell the user to set a **monthly spend limit** in the AI provider's console.

**주민등록번호 / phone numbers in logs**
Stop logging request bodies; mask PII at the logger. Collecting 주민등록번호 needs a specific legal basis — flag it to the user rather than "fixing" it silently.

## What this does not catch
Business-logic bugs, payment webhook verification (→ a payments skill), write-permission policies, SSRF/XSS/CSRF, dependency CVEs, and anything behind flows the probes don't reach. Pair with a code review (e.g. `/security-review`) for those. Facts that change over time (key formats, Supabase defaults) are dated in `references/sources.md`.
