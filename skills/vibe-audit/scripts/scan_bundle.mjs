#!/usr/bin/env node
/**
 * Check 1 — secrets in what the browser downloads.
 *
 *   node scan_bundle.mjs [projectDir] [--out .vibe-audit] [--logs logs]
 *
 * Scans the BUILT client output (.next/static, dist, build, out, …) — not the
 * source — because that is what an attacker gets. Also reads .env files for
 * public-prefixed variables that hold secrets, and (Korea extra) scans the
 * bundle and log folders for 주민등록번호- and 휴대폰-shaped strings.
 */
import fs from "node:fs";
import path from "node:path";
import { parseArgs, mask, jwtPayload, readEnvFiles, writeResult, printFindings } from "./lib.mjs";

const args = parseArgs();
const root = path.resolve(args._[0] ?? ".");
const outDir = path.resolve(root, args.out ?? ".vibe-audit");

const BUILD_DIRS = [".next/static", "dist", "build", "out", ".output/public", ".vercel/output/static", ".svelte-kit/output/client"];
const TEXT_EXT = /\.(m?js|cjs|css|html?|json|map|txt|svg)$/i;
const MAX_BYTES = 8 * 1024 * 1024;

// Ordered: the first pattern that matches a value wins.
const PATTERNS = [
  { id: "stripe-live-secret", re: /\b(?:sk|rk)_live_[A-Za-z0-9]{16,}\b/g, severity: "critical", title: "Stripe 라이브 시크릿 키가 번들에 있음", fix: "시크릿 키는 서버(API 라우트/서버 액션)에서만 쓰고, 즉시 Stripe 대시보드에서 키를 재발급(롤)하세요." },
  { id: "stripe-test-secret", re: /\bsk_test_[A-Za-z0-9]{16,}\b/g, severity: "medium", title: "Stripe 테스트 시크릿 키가 번들에 있음", fix: "테스트 키라도 시크릿은 서버에만 두세요. 같은 코드가 라이브 키로 배포되는 순간 사고가 납니다." },
  { id: "toss-live-secret", re: /\blive_g?sk_[A-Za-z0-9]{10,}\b/g, severity: "critical", title: "토스페이먼츠 라이브 시크릿 키가 번들에 있음", fix: "시크릿 키는 결제 승인 API를 부르는 서버에서만 쓰세요. 개발자센터에서 키를 재발급하세요(기존 키는 재발급 후에도 일정 기간 유효할 수 있어요)." },
  { id: "toss-test-secret", re: /\btest_g?sk_[A-Za-z0-9]{10,}\b/g, severity: "medium", title: "토스페이먼츠 테스트 시크릿 키가 번들에 있음", fix: "클라이언트에는 클라이언트 키(…_ck_ / …_gck_)만 두세요." },
  { id: "supabase-secret", re: /\bsb_secret_[A-Za-z0-9_-]{16,}\b/g, severity: "critical", title: "Supabase 시크릿(sb_secret_) 키가 번들에 있음", fix: "시크릿 키는 RLS를 무시합니다. 서버에서만 쓰고 대시보드에서 즉시 폐기·재발급하세요." },
  { id: "anthropic-key", re: /\bsk-ant-[A-Za-z0-9_-]{20,}\b/g, severity: "critical", title: "Anthropic API 키가 번들에 있음", fix: "AI 호출은 서버 라우트로 옮기고 키를 콘솔에서 폐기하세요. 누구나 내 요금으로 호출할 수 있어요." },
  { id: "openai-key", re: /\bsk-(?:proj|svcacct|admin)-[A-Za-z0-9_-]{20,}\b|\bsk-[A-Za-z0-9]{40,}\b/g, severity: "critical", title: "OpenAI API 키가 번들에 있음", fix: "AI 호출은 서버 라우트로 옮기고 키를 폐기하세요." },
  { id: "aws-key", re: /\bAKIA[0-9A-Z]{16}\b/g, severity: "critical", title: "AWS 액세스 키가 번들에 있음", fix: "IAM에서 키를 비활성화하고, 업로드는 서버가 발급한 presigned URL로 바꾸세요." },
  { id: "github-token", re: /\b(?:ghp|gho|ghs)_[A-Za-z0-9]{30,}\b|\bgithub_pat_[A-Za-z0-9_]{40,}\b/g, severity: "critical", title: "GitHub 토큰이 번들에 있음", fix: "토큰을 폐기하고 서버 쪽으로 옮기세요." },
  { id: "private-key", re: /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/g, severity: "critical", title: "개인키(PRIVATE KEY)가 번들에 있음", fix: "키를 폐기·재발급하고 서버 환경변수로만 두세요." },
  { id: "google-api-key", re: /\bAIza[0-9A-Za-z_-]{35}\b/g, severity: "low", title: "Google API 키가 번들에 있음 (지도 등 공개용일 수 있음)", fix: "공개용이라면 콘솔에서 HTTP 리퍼러·API 제한을 걸어 두세요. Gemini 키라면 서버로 옮기세요." },
];
const JWT_RE = /\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g;

// Korea extra: 주민등록번호 (YYMMDD-Gxxxxxx with a real date and gender digit 1–4) and 휴대폰 번호.
// The dash is required: without it, 13-digit millisecond timestamps (1712121234567) look like one.
const RRN_RE = /\b(\d{2})(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])-([1-4])\d{6}\b/g;
const PHONE_RE = /\b01[016789]-?\d{3,4}-?\d{4}\b/g;

const findings = [];
const seen = new Set();
const add = (f) => {
  const key = `${f.id}|${f.value}|${f.where.split(":")[0]}`;
  if (seen.has(key)) return;
  seen.add(key);
  findings.push(f);
};

const walk = (dir, cb) => {
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    const p = path.join(dir, e.name);
    if (e.isDirectory()) {
      if (e.name === "node_modules" || e.name === "cache") continue;
      walk(p, cb);
    } else cb(p);
  }
};

const lineOf = (text, idx) => text.slice(0, idx).split("\n").length;

const scanText = (file, text, { secrets = true, pii = true, phones = false } = {}) => {
  const rel = path.relative(root, file);
  if (secrets) {
    for (const p of PATTERNS) {
      for (const m of text.matchAll(p.re)) {
        add({ id: p.id, value: m[0], severity: p.severity, title: p.title, where: `${rel}:${lineOf(text, m.index)}`, evidence: mask(m[0]), fix: p.fix });
      }
    }
    for (const m of text.matchAll(JWT_RE)) {
      const claims = jwtPayload(m[0]);
      if (!claims) continue;
      if (claims.role === "service_role" || claims.role === "supabase_admin") {
        add({ id: "supabase-service-role-jwt", value: m[0], severity: "critical", title: "Supabase service_role 키(JWT)가 번들에 있음 — RLS를 완전히 무시합니다", where: `${rel}:${lineOf(text, m.index)}`, evidence: `${mask(m[0])} · role=${claims.role}`, fix: "service_role 키는 서버에서만. 클라이언트는 anon/publishable 키 + RLS 정책으로 접근하세요. 노출됐다면 JWT 시크릿(또는 키)을 즉시 교체하세요." });
      } else if (claims.role === "anon") {
        add({ id: "supabase-anon-jwt", value: m[0], severity: "info", title: "Supabase anon 키가 번들에 있음 (정상 — 대신 RLS가 필수)", where: `${rel}:${lineOf(text, m.index)}`, evidence: `${mask(m[0])} · role=anon`, fix: "anon 키는 공개돼도 되는 키예요. 그래서 모든 테이블에 RLS가 켜져 있어야 합니다 → rls_probe로 확인." });
      }
    }
  }
  if (pii) {
    for (const m of text.matchAll(RRN_RE)) {
      add({ id: "kr-rrn", value: m[0], severity: "high", title: "주민등록번호 형태의 문자열 발견", where: `${rel}:${lineOf(text, m.index)}`, evidence: `${m[0].slice(0, 6)}-*******`, fix: "주민등록번호는 법령 근거 없이 수집·저장할 수 없어요. 로그·번들에서 제거하고 수집 경로를 확인하세요." });
    }
    if (phones) for (const m of text.matchAll(PHONE_RE)) {
      add({ id: "kr-phone", value: m[0], severity: "low", title: "휴대폰 번호 형태의 문자열 발견", where: `${rel}:${lineOf(text, m.index)}`, evidence: m[0].replace(/\d{4}$/, "****"), fix: "고객센터 번호라면 무시하세요. 사용자 번호가 로그·번들에 찍힌다면 마스킹하세요." });
    }
  }
};

// 1. Built client output.
const buildDirs = BUILD_DIRS.map((d) => path.join(root, d)).filter((d) => fs.existsSync(d));
let scanned = 0;
for (const dir of buildDirs) {
  walk(dir, (file) => {
    if (!TEXT_EXT.test(file)) return;
    const st = fs.statSync(file);
    if (st.size > MAX_BYTES) return;
    scanned++;
    scanText(file, fs.readFileSync(file, "utf8"));
  });
}
const notes = [];
if (!buildDirs.length) {
  notes.push("빌드 결과물을 못 찾았어요 (.next/static, dist, build …). 먼저 `npm run build` 후 다시 실행하세요 — 소스가 아니라 배포되는 파일을 봐야 정확합니다.");
}

// 2. Public-prefixed env vars that hold secrets (they get inlined into the bundle).
const PUBLIC_PREFIX = /^(NEXT_PUBLIC_|VITE_|PUBLIC_|EXPO_PUBLIC_|REACT_APP_|NUXT_PUBLIC_)/;
const SECRET_NAME = /(SECRET|SERVICE_ROLE|PRIVATE|PASSWORD|_SK$|_SK_|ADMIN_KEY|WEBHOOK)/i;
const env = readEnvFiles(root);
for (const [name, value] of Object.entries(env)) {
  if (!PUBLIC_PREFIX.test(name)) continue;
  const claims = value.startsWith("eyJ") ? jwtPayload(value) : null;
  const leakedByValue = PATTERNS.find((p) => p.severity === "critical" && new RegExp(p.re.source).test(value)) || claims?.role === "service_role";
  if (leakedByValue || SECRET_NAME.test(name)) {
    add({ id: "public-env-secret", value: name, severity: leakedByValue ? "critical" : "high", title: `공개 접두사 환경변수에 비밀값: ${name}`, where: ".env*", evidence: `${name}=${mask(value)}${claims?.role ? ` · role=${claims.role}` : ""}`, fix: `${name.replace(PUBLIC_PREFIX, "")} 처럼 접두사를 빼서 서버 전용으로 만들고, 이 값을 쓰는 코드를 서버 라우트로 옮기세요. 이미 배포됐다면 키를 재발급하세요.` });
  }
}

// 3. Korea extra: log folders (PII only).
const logDirs = [args.logs, "logs", "log"].filter(Boolean).map((d) => path.join(root, d)).filter((d) => fs.existsSync(d));
for (const dir of logDirs) {
  walk(dir, (file) => {
    if (!/\.(log|txt|json)$/i.test(file) || fs.statSync(file).size > MAX_BYTES) return;
    scanText(file, fs.readFileSync(file, "utf8"), { secrets: true, pii: true, phones: true });
  });
}

const clean = findings.map(({ value, ...f }) => f);
const file = writeResult(outDir, "bundle", { target: root, scannedFiles: scanned, buildDirs: buildDirs.map((d) => path.relative(root, d)), findings: clean, notes });
printFindings(`번들·환경변수 스캔 · 파일 ${scanned}개`, clean);
for (const n of notes) console.log("  ℹ️ " + n);
console.log(`  → ${path.relative(process.cwd(), file)}`);
