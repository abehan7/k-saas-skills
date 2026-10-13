#!/usr/bin/env node
/**
 * Check 2 — can a stranger read your tables with the public key?
 *
 *   node rls_probe.mjs [projectDir] [--url https://xxx.supabase.co] [--key <anon or publishable key>]
 *                      [--db postgres://…] [--out .vibe-audit]
 *
 * Uses ONLY the key that ships to every browser (anon / publishable), exactly
 * like an attacker would: lists the tables the Data API exposes, SELECTs a few
 * rows from each, and reports which ones answer. Read-only — it never writes.
 * With --db (or DATABASE_URL) it also asks Postgres directly which public
 * tables have RLS off and which views run with the owner's rights.
 */
import path from "node:path";
import { execFileSync } from "node:child_process";
import { parseArgs, mask, readEnvFiles, pickEnv, writeResult, printFindings, tryFetch, OWN_APP_WARNING } from "./lib.mjs";

const args = parseArgs();
const root = path.resolve(args._[0] ?? ".");
const outDir = path.resolve(root, args.out ?? ".vibe-audit");
const fileEnv = readEnvFiles(root);

const url = (args.url ?? pickEnv(fileEnv, "SUPABASE_URL", "NEXT_PUBLIC_SUPABASE_URL", "VITE_SUPABASE_URL", "PUBLIC_SUPABASE_URL", "EXPO_PUBLIC_SUPABASE_URL"))?.replace(/\/+$/, "");
const key = args.key ?? pickEnv(fileEnv, "SUPABASE_ANON_KEY", "NEXT_PUBLIC_SUPABASE_ANON_KEY", "NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY", "VITE_SUPABASE_ANON_KEY", "PUBLIC_SUPABASE_ANON_KEY", "EXPO_PUBLIC_SUPABASE_ANON_KEY");
const dbUrl = args.db ?? pickEnv(fileEnv, "DATABASE_URL", "SUPABASE_DB_URL", "DIRECT_URL");

console.log(OWN_APP_WARNING);
const findings = [];
const notes = [];

if (!url || !key) {
  notes.push("Supabase URL 또는 anon/publishable 키를 못 찾았어요. --url, --key 로 넘기거나 .env.local에 NEXT_PUBLIC_SUPABASE_URL / NEXT_PUBLIC_SUPABASE_ANON_KEY 를 두세요. (Supabase를 안 쓰면 이 점검은 건너뛰어도 됩니다.)");
} else {
  const headers = { apikey: key, Authorization: `Bearer ${key}`, Accept: "application/openapi+json, application/json" };

  // Hosted Supabase serves the Data API at /rest/v1/; a bare PostgREST serves it at /.
  let base = null;
  let spec = null;
  for (const candidate of [`${url}/rest/v1/`, `${url}/`]) {
    const r = await tryFetch(candidate, { headers });
    if (r.ok && r.status === 200 && r.json && (r.json.paths || r.json.definitions)) {
      base = candidate;
      spec = r.json;
      break;
    }
  }

  if (!spec) {
    notes.push(`Data API 스펙을 읽지 못했어요 (${url}). URL·키를 확인하세요. 키가 맞는데 401이면 정상적으로 막혀 있는 거예요.`);
  } else {
    const tables = Object.keys(spec.paths ?? {})
      .map((p) => p.replace(/^\//, ""))
      .filter((p) => p && !p.startsWith("rpc/"));
    if (!tables.length) {
      notes.push("Data API에 노출된 테이블이 없어요. Supabase는 새 테이블을 기본으로 노출하지 않아요 (새 프로젝트 2026-05-30~, 기존 프로젝트 2026-10-30~). GRANT로 노출한 테이블만 점검 대상이고, 노출했다면 RLS는 여전히 필수예요.");
    }
    for (const t of tables) {
      const r = await tryFetch(`${base}${encodeURIComponent(t)}?select=*&limit=3`, {
        headers: { ...headers, Accept: "application/json", Prefer: "count=exact" },
      });
      if (!r.ok) continue;
      const total = Number(r.headers.get("content-range")?.split("/")[1]);
      const rows = Array.isArray(r.json) ? r.json : [];
      if (r.status === 200 && rows.length) {
        const cols = Object.keys(rows[0]);
        const sensitive = cols.filter((c) => /(email|phone|tel|name|이름|address|birth|ssn|rrn|token|password|card|account|ip)/i.test(c));
        findings.push({
          severity: sensitive.length ? "critical" : "high",
          title: `로그인 없이 공개 키만으로 '${t}' 이(가) 읽힘 (${Number.isFinite(total) ? `${total}행` : `${rows.length}행 이상`})`,
          where: `${base}${t}`,
          evidence: `컬럼: ${cols.join(", ")}${sensitive.length ? ` · 민감 컬럼: ${sensitive.join(", ")}` : ""} · 예시값: ${mask(JSON.stringify(rows[0]))}`,
          fix: `RLS를 켜고 정책을 추가하세요:\n  alter table public.${t} enable row level security;\n  create policy "${t}: 본인 것만" on public.${t} for select to authenticated using ((select auth.uid()) = user_id);\n공개용 테이블이 맞다면 공개 컬럼만 가진 view(security_invoker=true)로 분리하세요.`,
        });
      } else if (r.status === 200) {
        notes.push(`'${t}': 공개 키로 조회 시 0행 (RLS로 막혔거나 비어 있음)`);
      }
    }
  }

  // Storage: public buckets are readable by URL without any key.
  const b = await tryFetch(`${url}/storage/v1/bucket`, { headers });
  if (b.ok && b.status === 200 && Array.isArray(b.json)) {
    for (const bucket of b.json.filter((x) => x.public)) {
      findings.push({
        severity: "medium",
        title: `공개(public) 스토리지 버킷: ${bucket.name}`,
        where: `${url}/storage/v1/object/public/${bucket.name}/…`,
        evidence: "URL만 알면 누구나 파일을 받을 수 있어요",
        fix: "프로필 사진처럼 공개가 맞다면 그대로 두세요. 영수증·신분증·계약서라면 private 버킷 + signed URL로 바꾸세요.",
      });
    }
  }
}

// Direct SQL checks — the authoritative answer, if a connection string is available.
if (dbUrl) {
  const psql = (sql) =>
    execFileSync("psql", [dbUrl, "-At", "-c", sql], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"], timeout: 15000 })
      .trim()
      .split("\n")
      .filter(Boolean);
  try {
    for (const t of psql(
      "select c.relname from pg_class c join pg_namespace n on n.oid = c.relnamespace where c.relkind in ('r','p') and n.nspname = 'public' and not c.relrowsecurity order by 1",
    )) {
      findings.push({
        severity: "high",
        title: `RLS가 꺼진 테이블: public.${t}`,
        where: "postgres (pg_class.relrowsecurity = false)",
        evidence: "anon/authenticated 역할에 권한이 있으면 Data API로 그대로 노출됩니다",
        fix: `alter table public.${t} enable row level security;  -- 그리고 필요한 정책을 추가`,
      });
    }
    for (const v of psql(
      "select c.relname from pg_class c join pg_namespace n on n.oid = c.relnamespace where c.relkind = 'v' and n.nspname = 'public' and not coalesce(c.reloptions::text like '%security_invoker=true%', false) order by 1",
    )) {
      findings.push({
        severity: "medium",
        title: `security_invoker 없이 만든 view: public.${v}`,
        where: "postgres (view reloptions)",
        evidence: "view가 만든 사람(소유자) 권한으로 실행돼 테이블의 RLS를 우회할 수 있어요",
        fix: `alter view public.${v} set (security_invoker = true);`,
      });
    }
  } catch (e) {
    notes.push(`SQL 점검을 못 했어요 (psql 필요, 연결 문자열 확인): ${String(e.stderr || e.message).split("\n")[0]}`);
  }
} else {
  notes.push("DATABASE_URL이 없어 SQL 점검(RLS 꺼진 테이블 목록)은 건너뛰었어요. --db 로 넘기면 더 정확합니다.");
}

const file = writeResult(outDir, "rls", { target: url ?? null, findings, notes });
printFindings("RLS·공개 키 점검", findings);
for (const n of notes) console.log("  ℹ️ " + n);
console.log(`  → ${path.relative(process.cwd(), file)}`);
