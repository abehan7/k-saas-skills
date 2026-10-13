#!/usr/bin/env node
/**
 * Merges .vibe-audit/*.json into one Korean report, worst first.
 *
 *   node report.mjs [projectDir] [--out .vibe-audit]   →   <projectDir>/audit-report.md
 *
 * Exits 1 when anything critical is open, so it can gate a deploy in CI.
 */
import fs from "node:fs";
import path from "node:path";
import { parseArgs, SEVERITY, SEVERITY_KO } from "./lib.mjs";

const args = parseArgs();
const root = path.resolve(args._[0] ?? ".");
const outDir = path.resolve(root, args.out ?? ".vibe-audit");
const LABEL = { bundle: "번들·환경변수", rls: "RLS·공개 키", idor: "남의 데이터 열람", rate: "레이트 리밋" };

if (!fs.existsSync(outDir)) {
  console.error(`${outDir} 가 없어요. 먼저 점검 스크립트를 실행하세요.`);
  process.exit(2);
}
const results = fs
  .readdirSync(outDir)
  .filter((f) => f.endsWith(".json"))
  .map((f) => JSON.parse(fs.readFileSync(path.join(outDir, f), "utf8")));

const all = results.flatMap((r) => r.findings.map((f) => ({ ...f, check: r.check })));
all.sort((a, b) => SEVERITY.indexOf(a.severity) - SEVERITY.indexOf(b.severity));
const count = (s) => all.filter((f) => f.severity === s).length;

const lines = [];
lines.push(`# 출시 전 보안 점검 리포트`, "");
lines.push(`- 점검 시각: ${new Date().toLocaleString("ko-KR", { timeZone: "Asia/Seoul" })}`);
lines.push(`- 대상: \`${path.basename(root)}\``);
lines.push(`- 실행한 점검: ${results.map((r) => LABEL[r.check] ?? r.check).join(", ")}`);
lines.push("");
lines.push(`| ${SEVERITY.map((s) => SEVERITY_KO[s]).join(" | ")} |`);
lines.push(`|${SEVERITY.map(() => "---").join("|")}|`);
lines.push(`| ${SEVERITY.map((s) => count(s)).join(" | ")} |`);
lines.push("");
lines.push(count("critical") ? `**🔴 치명 ${count("critical")}건 — 이 상태로 출시하면 안 돼요.**` : "**🟢 치명적인 문제는 발견되지 않았어요.**", "");

let n = 0;
for (const sev of SEVERITY) {
  const group = all.filter((f) => f.severity === sev);
  if (!group.length) continue;
  lines.push(`## ${SEVERITY_KO[sev]} (${group.length})`, "");
  for (const f of group) {
    n++;
    lines.push(`### ${n}. ${f.title}`);
    lines.push(`- 점검: ${LABEL[f.check] ?? f.check}${f.where ? ` · 위치: \`${f.where}\`` : ""}`);
    if (f.evidence) lines.push(`- 근거: ${f.evidence}`);
    if (f.fix) lines.push(`- 고치는 법:`, "", "```", f.fix, "```");
    lines.push("");
  }
}

const notes = results.flatMap((r) => (r.notes ?? []).map((x) => `- [${LABEL[r.check] ?? r.check}] ${x}`));
if (notes.length) lines.push("## 참고", "", ...notes, "");

lines.push(
  "## 이 점검이 잡지 못하는 것",
  "",
  "- 알려진 유형(키 노출, RLS 누락, 남의 데이터 열람, 레이트 리밋)만 직접 찔러봅니다. 통과했다고 '보안 100%'가 아니에요.",
  "- 비즈니스 로직 결함, 결제 웹훅 검증, 쓰기(INSERT/UPDATE) 권한, SSRF·XSS 같은 유형은 별도 점검이 필요해요.",
  "- 키가 한 번이라도 배포·커밋됐다면, 코드에서 지우는 것만으로는 부족해요 — 반드시 재발급하세요.",
  "",
  "> 본인이 소유한 서비스에만 실행하세요. 법률·보안 자문을 대신하지 않습니다.",
);

const file = path.join(root, "audit-report.md");
fs.writeFileSync(file, lines.join("\n") + "\n");
console.log(`\n📄 ${path.relative(process.cwd(), file)} — 치명 ${count("critical")} · 높음 ${count("high")} · 보통 ${count("medium")} · 낮음 ${count("low")} · 참고 ${count("info")}`);
process.exit(count("critical") ? 1 : 0);
