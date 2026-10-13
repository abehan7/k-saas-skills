# k-saas-skills

**The last mile of shipping a SaaS in Korea — as checks that actually probe your app, not advice.**
Security, payments, login, legal notices and launch checks, released one skill a day by [@shipit_now](https://www.instagram.com/shipit_now/).

```bash
# Claude Code
/plugin marketplace add abehan7/k-saas-skills
/plugin install k-saas@shipit

# Cursor, Codex, Gemini CLI and other agents
npx skills add abehan7/k-saas-skills
```

| Day | Skill | Use it when | Status |
|---|---|---|---|
| 1 | [`vibe-audit`](skills/vibe-audit/SKILL.md) | Before launch: probe for leaked keys in the bundle, tables readable with the anon key, IDOR between users, missing rate limits — Korean severity report | ✅ released |
| 2–7 | `prod-guard`, `toss-payments-flow`, `kakao-naver-login`, `kr-privacy-docs`, `pg-review-ready`, `kr-launch-check` | Coming one per day | soon |

Try it on the deliberately vulnerable demo app: [k-saas-demo](https://github.com/abehan7/k-saas-demo).

**Only run these on services you own.** They check known classes of problems — passing is not "100% secure". Unofficial; not affiliated with Toss Payments, Kakao, Naver or Supabase. Not legal, tax or security advice. MIT licensed.
