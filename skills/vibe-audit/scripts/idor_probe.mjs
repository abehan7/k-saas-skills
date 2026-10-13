#!/usr/bin/env node
/**
 * Check 3 — can user B open user A's things? (IDOR / broken object-level auth)
 *
 *   node idor_probe.mjs --base http://localhost:3000 \
 *        --list /api/invoices --item "/api/invoices/{id}" \
 *        --login-a "/api/demo-login?user=a" --login-b "/api/demo-login?user=b"
 *   # or pass sessions directly:
 *        --cookie-a "sb-access-token=…" --cookie-b "…"   |   --header-a "Authorization: Bearer …" --header-b "…"
 *   # several routes at once: --config vibe-audit.config.json  ({ "idor": [ {base,list,item,loginA,loginB,…} ] })
 *
 * Reads A's own list with A's session, then requests each of those IDs as B
 * and as nobody. Anything but 401/403/404 for B is a finding. GET only.
 */
import fs from "node:fs";
import path from "node:path";
import { parseArgs, writeResult, printFindings, tryFetch, OWN_APP_WARNING } from "./lib.mjs";

const args = parseArgs();
const outDir = path.resolve(args.out ?? ".vibe-audit");
const MAX_IDS = Number(args.max ?? 5);

const targets = args.config
  ? JSON.parse(fs.readFileSync(args.config, "utf8")).idor ?? []
  : [{ base: args.base, list: args.list, item: args.item, loginA: args["login-a"], loginB: args["login-b"], cookieA: args["cookie-a"], cookieB: args["cookie-b"], headerA: args["header-a"], headerB: args["header-b"], ids: args.ids }];

if (!targets.length || !targets[0].base || !targets[0].item) {
  console.error('usage: node idor_probe.mjs --base <url> --item "/api/thing/{id}" [--list /api/things] (--login-a <path> --login-b <path> | --cookie-a … --cookie-b … | --header-a … --header-b …)');
  process.exit(1);
}
console.log(OWN_APP_WARNING);

/** Turns a login URL / cookie / header option into request headers for that user. */
const session = async (base, { login, cookie, header }) => {
  if (header) {
    const i = header.indexOf(":");
    return { [header.slice(0, i).trim()]: header.slice(i + 1).trim() };
  }
  if (cookie) return { Cookie: cookie };
  if (login) {
    const r = await tryFetch(new URL(login, base).toString());
    const set = r.ok ? r.headers.getSetCookie?.() ?? [r.headers.get("set-cookie")].filter(Boolean) : [];
    if (!set.length) throw new Error(`로그인 응답에 쿠키가 없어요: ${login}`);
    return { Cookie: set.map((c) => c.split(";")[0]).join("; ") };
  }
  throw new Error("사용자 세션이 필요해요 (--login-a/b, --cookie-a/b, 또는 --header-a/b)");
};

const idsFrom = (json) => {
  const arr = Array.isArray(json) ? json : json?.data ?? json?.items ?? json?.results ?? [];
  return arr.map((x) => x?.id ?? x?.uuid ?? x?.slug).filter((v) => v != null).map(String);
};

const findings = [];
const notes = [];
for (const t of targets) {
  try {
    const asA = await session(t.base, { login: t.loginA, cookie: t.cookieA, header: t.headerA });
    const asB = await session(t.base, { login: t.loginB, cookie: t.cookieB, header: t.headerB });

    let ids = t.ids ? String(t.ids).split(",") : [];
    if (!ids.length && t.list) {
      const r = await tryFetch(new URL(t.list, t.base).toString(), { headers: asA });
      ids = r.ok && r.status === 200 ? idsFrom(r.json) : [];
      if (!ids.length) notes.push(`A의 목록(${t.list})에서 id를 못 찾았어요 (status ${r.status ?? r.error}). --ids 로 직접 넘길 수 있어요.`);
    }
    ids = ids.slice(0, MAX_IDS);

    const leakedToB = [];
    const leakedToAnon = [];
    let sample = "";
    for (const id of ids) {
      const route = t.item.replace("{id}", encodeURIComponent(id));
      const u = new URL(route, t.base).toString();
      const own = await tryFetch(u, { headers: asA });
      const asOther = await tryFetch(u, { headers: asB });
      const anon = await tryFetch(u);
      if (own.ok && own.status !== 200) notes.push(`A 본인도 ${route} 를 못 열었어요 (status ${own.status}) — 경로 패턴을 확인하세요.`);
      if (asOther.ok && asOther.status >= 200 && asOther.status < 300) {
        leakedToB.push(id);
        sample ||= asOther.text.slice(0, 90).replace(/\s+/g, " ");
      }
      if (anon.ok && anon.status >= 200 && anon.status < 300) leakedToAnon.push(id);
    }
    if (leakedToB.length) {
      findings.push({
        severity: "critical",
        title: `다른 사용자(B)가 A의 데이터 ${leakedToB.length}건을 열람: ${t.item}`,
        where: t.item.replace("{id}", leakedToB[0]),
        evidence: `B 세션으로 열린 id: ${leakedToB.join(", ")} · 응답 예시: ${sample}…`,
        fix: "라우트에서 '로그인했는지'만 보지 말고 '이 리소스의 주인인지'를 확인하세요:\n  const row = await db.invoice.findFirst({ where: { id, userId: session.userId } });\n  if (!row) return new Response(null, { status: 404 });\nSupabase라면 RLS 정책 (auth.uid() = user_id) 으로 DB에서 막는 게 가장 확실합니다.",
      });
    }
    if (leakedToAnon.length) {
      findings.push({
        severity: "critical",
        title: `로그인 없이 열람 가능 (${leakedToAnon.length}건): ${t.item}`,
        where: t.item.replace("{id}", leakedToAnon[0]),
        evidence: `세션 없이 열린 id: ${leakedToAnon.join(", ")}`,
        fix: "이 라우트 맨 앞에서 세션을 확인하고 없으면 401을 돌려주세요.",
      });
    }
    if (ids.length && !findings.some((f) => f.title.includes(t.item))) notes.push(`${t.item}: B·비로그인 모두 막힘 ✅ (id ${ids.length}개 확인)`);
  } catch (e) {
    notes.push(`${t.item}: 점검 실패 — ${e.message}`);
  }
}

const file = writeResult(outDir, "idor", { target: targets.map((t) => t.base + t.item), findings, notes });
printFindings("남의 데이터 열람(IDOR) 점검", findings);
for (const n of notes) console.log("  ℹ️ " + n);
console.log(`  → ${path.relative(process.cwd(), file)}`);
