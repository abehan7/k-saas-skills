#!/usr/bin/env node
/**
 * Check 4 — does an expensive endpoint (AI, email, SMS, export) have a rate limit?
 *
 *   node rate_probe.mjs --url http://localhost:3000/api/ai/summarize --method POST \
 *        --body '{"text":"hi"}' [--n 12] [--login /api/demo-login?user=a | --cookie … | --header "Authorization: Bearer …"]
 *
 * Sends a short burst (default 12, max 30) and expects at least one 429.
 * Every request is a real call: if the endpoint calls a paid AI API, this
 * costs money — run it on dev/staging, or on an endpoint stubbed for tests.
 */
import path from "node:path";
import { parseArgs, writeResult, printFindings, tryFetch, OWN_APP_WARNING } from "./lib.mjs";

const args = parseArgs();
const outDir = path.resolve(args.out ?? ".vibe-audit");
if (!args.url) {
  console.error("usage: node rate_probe.mjs --url <endpoint> [--method POST] [--body '{…}'] [--n 12] [--login <path>|--cookie …|--header …]");
  process.exit(1);
}
const n = Math.min(30, Number(args.n ?? 12));
const method = (args.method ?? "POST").toUpperCase();
console.log(OWN_APP_WARNING);
console.log(`💸 요청 ${n}번을 실제로 보냅니다. 유료 AI를 부르는 엔드포인트라면 비용이 생길 수 있어요 — 개발/스테이징에서 실행하세요.`);

const headers = { "Content-Type": "application/json" };
if (args.header) {
  const i = args.header.indexOf(":");
  headers[args.header.slice(0, i).trim()] = args.header.slice(i + 1).trim();
}
if (args.cookie) headers.Cookie = args.cookie;
if (args.login) {
  const r = await tryFetch(new URL(args.login, args.url).toString());
  const set = r.ok ? r.headers.getSetCookie?.() ?? [] : [];
  if (set.length) headers.Cookie = set.map((c) => c.split(";")[0]).join("; ");
}

const statuses = [];
const started = Date.now();
const queue = Array.from({ length: n }, (_, i) => i);
const worker = async () => {
  while (queue.length) {
    queue.shift();
    const r = await tryFetch(args.url, { method, headers, body: method === "GET" ? undefined : args.body ?? "{}" });
    statuses.push(r.ok ? r.status : 0);
  }
};
await Promise.all(Array.from({ length: 4 }, worker));
const secs = ((Date.now() - started) / 1000).toFixed(1);

const tally = statuses.reduce((m, s) => ((m[s] = (m[s] ?? 0) + 1), m), {});
const limited = (tally[429] ?? 0) > 0;
const allOk = statuses.every((s) => s >= 200 && s < 300);
const findings = [];
if (!limited && allOk) {
  findings.push({
    severity: "high",
    title: `레이트 리밋 없음: ${n}번 연속 요청이 전부 성공 (${secs}초)`,
    where: `${method} ${args.url}`,
    evidence: `응답: ${JSON.stringify(tally)}`,
    fix: "사용자(또는 IP)별 한도를 거세요. 예: 1분에 10회 초과 시 429.\n  Upstash Ratelimit, Vercel/Cloudflare 규칙, 또는 DB 카운터로도 충분합니다.\n그리고 AI 제공사 콘솔에 월 사용 한도(spend limit)를 꼭 설정하세요 — 키가 새면 이게 마지막 방어선이에요.",
  });
}
const notes = [limited ? `429 응답 확인 ✅ (${JSON.stringify(tally)})` : !allOk ? `일부 요청이 실패했어요: ${JSON.stringify(tally)} — 인증·본문 형식을 확인하세요.` : null].filter(Boolean);

const file = writeResult(outDir, "rate", { target: `${method} ${args.url}`, findings, notes });
printFindings("레이트 리밋 점검", findings);
for (const x of notes) console.log("  ℹ️ " + x);
console.log(`  → ${path.relative(process.cwd(), file)}`);
