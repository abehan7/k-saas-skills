// Shared helpers for the vibe-audit checks. Zero dependencies — Node 18+ only.
import fs from "node:fs";
import path from "node:path";

export const SEVERITY = ["critical", "high", "medium", "low", "info"];
export const SEVERITY_KO = { critical: "치명", high: "높음", medium: "보통", low: "낮음", info: "참고" };

/** --flag value / --flag=value / --bool  →  { flag: value }; positional args in _ */
export const parseArgs = (argv = process.argv.slice(2)) => {
  const out = { _: [] };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (!a.startsWith("--")) {
      out._.push(a);
      continue;
    }
    const eq = a.indexOf("=");
    if (eq > 0) out[a.slice(2, eq)] = a.slice(eq + 1);
    else if (argv[i + 1] && !argv[i + 1].startsWith("--")) out[a.slice(2)] = argv[++i];
    else out[a.slice(2)] = true;
  }
  return out;
};

/** Shows enough of a secret to recognise it, never enough to use it. */
export const mask = (s) => {
  const v = String(s);
  if (v.length <= 10) return v.slice(0, 2) + "…";
  return v.slice(0, 8) + "…" + v.slice(-2) + ` (${v.length}자)`;
};

/** Reads KEY=VALUE pairs from the project's .env files (later files win), without touching process.env. */
export const readEnvFiles = (dir) => {
  const env = {};
  for (const name of [".env", ".env.development", ".env.production", ".env.local"]) {
    const f = path.join(dir, name);
    if (!fs.existsSync(f)) continue;
    for (const line of fs.readFileSync(f, "utf8").split("\n")) {
      const m = line.match(/^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)\s*$/);
      if (m) env[m[1]] = m[2].replace(/^["']|["']$/g, "");
    }
  }
  return env;
};

/** First defined value among the names, from process.env then the project's .env files. */
export const pickEnv = (fileEnv, ...names) => {
  for (const n of names) if (process.env[n]) return process.env[n];
  for (const n of names) if (fileEnv[n]) return fileEnv[n];
  return undefined;
};

/** Decodes a JWT payload (no verification — we only read the claims). */
export const jwtPayload = (token) => {
  try {
    const part = token.split(".")[1];
    return JSON.parse(Buffer.from(part.replace(/-/g, "+").replace(/_/g, "/"), "base64").toString("utf8"));
  } catch {
    return null;
  }
};

/** Writes .vibe-audit/<check>.json and returns its path. */
export const writeResult = (outDir, check, result) => {
  fs.mkdirSync(outDir, { recursive: true });
  const file = path.join(outDir, `${check}.json`);
  fs.writeFileSync(file, JSON.stringify({ check, ranAt: new Date().toISOString(), ...result }, null, 2));
  return file;
};

/** One-line console summary per finding, worst first. */
export const printFindings = (label, findings) => {
  const sorted = [...findings].sort((a, b) => SEVERITY.indexOf(a.severity) - SEVERITY.indexOf(b.severity));
  const counts = SEVERITY.map((s) => [s, sorted.filter((f) => f.severity === s).length]).filter(([, n]) => n);
  console.log(`\n[${label}] ${counts.length ? counts.map(([s, n]) => `${SEVERITY_KO[s]} ${n}`).join(" · ") : "발견 없음 ✅"}`);
  for (const f of sorted) console.log(`  ${icon(f.severity)} ${SEVERITY_KO[f.severity]} — ${f.title}${f.where ? `  (${f.where})` : ""}`);
};

const icon = (s) => ({ critical: "🔴", high: "🟠", medium: "🟡", low: "⚪", info: "🔵" })[s];

/** fetch with a timeout; never throws — returns { ok:false, error } instead. */
export const tryFetch = async (url, init = {}, ms = 8000) => {
  const ctl = new AbortController();
  const t = setTimeout(() => ctl.abort(), ms);
  try {
    const res = await fetch(url, { ...init, signal: ctl.signal, redirect: "manual" });
    const text = await res.text();
    let json = null;
    try {
      json = JSON.parse(text);
    } catch {}
    return { ok: true, status: res.status, headers: res.headers, text, json };
  } catch (e) {
    return { ok: false, error: e.name === "AbortError" ? "시간 초과" : e.message };
  } finally {
    clearTimeout(t);
  }
};

export const OWN_APP_WARNING =
  "⚠️ 본인이 소유하고 점검 권한이 있는 서비스에만 실행하세요. 남의 서비스를 찔러보는 건 불법일 수 있어요.";
