# k-saas-skills

**한국에서 SaaS 출시할 때 막히는 마지막 1마일을, 조언 대신 직접 찔러보는 검사로.**
보안 · 결제 · 로그인 · 법적 고지 · 런칭 점검 스킬을 하루에 하나씩 공개합니다. (by [@shipit_now](https://www.instagram.com/shipit_now/))

```bash
# Claude Code
/plugin marketplace add abehan7/k-saas-skills
/plugin install k-saas@shipit

# Cursor · Codex · Gemini CLI 등 다른 에이전트
npx skills add abehan7/k-saas-skills
```

업데이트: `/plugin marketplace update shipit` · `npx skills update -y`

## 스킬

| Day | 스킬 | 이럴 때 쓰세요 | 상태 |
|---|---|---|---|
| 1 | [`vibe-audit`](skills/vibe-audit/SKILL.md) | 출시 전에 키 노출 · RLS 누락 · 남의 데이터 열람 · 레이트 리밋을 **직접 찔러보고** 한국어 리포트로 | ✅ 공개 |
| 2 | `prod-guard` | AI 에이전트가 운영 DB를 지우기 전에 막기 | 곧 공개 |
| 3 | `toss-payments-flow` | 토스페이먼츠 결제 · 웹훅 · 자동결제를 AI가 틀리는 곳까지 | 곧 공개 |
| 4 | `kakao-naver-login` | 카카오 · 네이버 로그인의 한국형 함정 | 곧 공개 |
| 5 | `kr-privacy-docs` | 코드가 실제로 수집하는 항목으로 개인정보처리방침 초안 | 곧 공개 |
| 6 | `pg-review-ready` | 카드사 · PG 심사 한 번에 통과하는 사업자 정보 · 환불 고지 | 곧 공개 |
| 7 | `kr-launch-check` | 한 번에 돌리는 한국형 런칭 D-day 점검 | 곧 공개 |

## vibe-audit — 출시 전 보안 점검

에이전트에게 이렇게 말하세요: **"출시 전 보안 점검해줘"**

| 점검 | 실제로 하는 일 |
|---|---|
| 번들 · 환경변수 | 빌드 결과물(`.next/static`, `dist` …)에서 Stripe/토스 시크릿, Supabase `service_role`, AI 키, `NEXT_PUBLIC_` 비밀값을 찾아요 |
| RLS · 공개 키 | 브라우저에 공개되는 anon 키만으로 모든 테이블을 조회해 봐요. SQL로 RLS 꺼진 테이블 · security_invoker 없는 view도 |
| 남의 데이터 열람 | 테스트 유저 A·B로 A의 영수증을 B가 열 수 있는지 확인 |
| 레이트 리밋 | AI 같은 비싼 엔드포인트에 짧게 연속 요청 → 429가 오는지 |
| 개인정보 (한국) | 로그 · 번들에 주민등록번호 · 휴대폰 번호 형태가 찍히는지 |

결과는 `audit-report.md`(치명 → 참고 순)로 나오고, 치명이 있으면 종료 코드 1 → CI에서 배포를 막을 수 있어요.

**직접 해보기:** 일부러 구멍 6개를 낸 데모 앱 [k-saas-demo](https://github.com/abehan7/k-saas-demo)에서 돌려 보세요. `main`은 치명 4건 · 높음 4건, `fixed` 브랜치는 0건이 나와요.

## 면책 / 주의

- **본인이 소유하고 점검 권한이 있는 서비스에만** 실행하세요. 남의 서비스를 찔러보는 건 불법일 수 있어요.
- 알려진 유형만 검사해요. 통과했다고 "보안 100%"가 아니에요.
- 토스페이먼츠 · 카카오 · 네이버 · Supabase와 무관한 **비공식** 프로젝트예요.
- 법률 · 세무 · 보안 자문을 대신하지 않아요.
- 키가 한 번이라도 노출됐다면 코드에서 지우는 걸로 끝이 아니에요 — 반드시 재발급하세요.

## 기여

이슈와 PR 환영해요. 오탐(멀쩡한데 걸린 것)과 미탐(놓친 것) 제보가 특히 도움이 돼요.

[English](README.en.md) · [MIT License](LICENSE) · [Changelog](CHANGELOG.md)
