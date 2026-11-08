# SENTINEL Free-First SaaS and Identity Implementation Plan

> **For agentic workers:** Use the host's available task-by-task implementation workflow. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Turn SENTINEL into a secure Free Early Access, multi-tenant Security Operations SaaS with Personal/Company workspaces, human and machine identities, and a future subscription catalogue that cannot charge users during launch.

**Architecture:** Supabase Auth owns human identities; Vercel Functions provide same-origin session/BFF endpoints; FastAPI remains the operational control plane and validates JWTs plus workspace membership. PostgreSQL tenant ownership, query filters, composite foreign keys and RLS enforce isolation. A central plan/entitlement resolver gives every new workspace Free Early Access while future paid tiers remain non-purchasable previews.

**Tech Stack:** React 19 + TypeScript + Vite 8, Vercel Node.js Functions, Supabase Auth/PostgreSQL, FastAPI + SQLAlchemy/Alembic, Redis, Cloudflare DNS/Turnstile/Workers/Email Routing, transactional SMTP provider, GitHub Actions.

## Global Constraints

- New human accounts and workspaces default to `free_early_access`.
- `BILLING_ENABLED=false`; no checkout, card capture, invoice generation, payment SDK, paid-plan purchase or automatic conversion is allowed in this release.
- Future plan prices are preview values only: Pro $29/month, Team $99/month, Business $299/month and Enterprise custom. Every response/UI must mark them not purchasable.
- Every currently shipped core security module is available in Free Early Access. Fair-use usage limits protect shared compute; they do not hide product features.
- Personal Free limits: 10 assets, 20 completed assessments per UTC calendar month, 1 human seat, 2 machine identities and 30-day evidence retention.
- Company Free limits: 25 assets, 50 completed assessments per UTC calendar month, 5 human seats, 3 machine identities and 30-day evidence retention.
- The future plan capacity previews are not active entitlements: Pro 100 assets/300 assessments/3 seats/10 machine identities/90-day retention; Team 500/1,500/15/30/180; Business 2,000/8,000/50/100/365; Enterprise negotiated.
- Plan IDs, tenant IDs, role claims and feature flags sent by the browser are never authorization inputs.
- Human identities and machine/service identities are separate. No self-signup path can create an administrator machine identity.
- Google/GitHub provider identities may be linked only after proving control of both identities; email equality alone is not sufficient when either email is unverified.
- Company domain ownership is established with a DNS TXT challenge; an email domain or company name alone never grants membership in an existing tenant.
- Keep the existing `X-API-Key` service integration during migration. Do not silently grant its global legacy key access to all tenants.
- Preserve existing network-safety, authorized-target, rate-limit, Redis, worker-lease, audit-integrity and container hardening.
- Keep `SENTINEL_ALLOWED_DOMAINS=sentinel.invalid` until a separately approved authorized target is supplied.
- No production signup becomes available until cross-tenant negative tests and migration reconciliation pass.
- No service key, SMTP credential, Turnstile secret, Supabase service-role key or worker secret may appear in Vite assets, client metadata, logs or Git.

---

## Task 1: Public Free-First plan catalogue

**Files:**
- Create: `backend/app/plans.py`
- Modify: `backend/app/main.py` — public `GET /api/v1/plans` endpoint
- Test: `backend/tests/test_plans.py`
- Modify: `docs/cloud-deployment.md` — document public plan endpoint and `BILLING_ENABLED=false`

**Interfaces:**
- `get_public_plan_catalog(workspace_type: str | None = None) -> dict`
- `GET /api/v1/plans?workspace_type=personal|company` returns version, launch mode, billing state, default plan code and plan entries.
- Existing `require_api_key` dependency is not applied to this read-only public endpoint. The existing global API rate limiter remains in force.

- [ ] **Step 1: Add the focused failing test**

  Add unittest cases asserting:
  - The default plan is `free_early_access`.
  - Billing and checkout are false.
  - Free is active, $0, default, and purchasable=false (there is no purchase action even for Free).
  - Pro/Team/Business/Enterprise are preview-only and purchasable=false.
  - Personal and Company limits differ exactly as declared in the design.
  - All currently shipped core feature codes are enabled on Free.
  - Unknown workspace type raises a deterministic ValueError; omitted type returns both quota profiles.
  - Returned plan data is JSON-serializable and immutable source data is not mutated by callers.

- [ ] **Step 2: Verify the relevant failure**

  Run: `cd backend && python -m unittest tests.test_plans -v`

  Expected: import or missing-symbol failures for `app.plans.get_public_plan_catalog`; the failure must be caused by the absent implementation.

- [ ] **Step 3: Implement the minimum behaviour**

  - Add immutable catalogue structures in `backend/app/plans.py`.
  - Keep plan codes stable and public prices integer cents.
  - Add `billing_enabled=False`, `checkout_enabled=False`, `launch_mode=free_early_access`.
  - Expose only static public plan metadata; do not query tenant data or create subscription rows.
  - Add the read-only public endpoint with strict workspace_type validation.
  - Preserve existing request middleware and API rate limiting.

- [ ] **Step 4: Verify the focused pass**

  Run: `cd backend && python -m unittest tests.test_plans -v`

  Expected: all focused plan catalogue tests pass.

- [ ] **Step 5: Run affected integration check**

  Run: `cd backend && python -m pytest -q`

  Expected: all existing API, authorization and security tests remain green; test client can GET `/api/v1/plans` without an API key and receives 200; `/api/v1/overview` still requires its API key.

- [ ] **Step 6: Commit the passing deliverable**

  `feat: expose Free Early Access plan catalogue`

## Task 2: Tenant foundation review and safe merge sequence

**Files:**
- Review existing: `backend/alembic/versions/0008_tenant_registry_and_ownership.py` on Draft PR #43
- Review existing: `docs/superpowers/specs/2026-11-07-sentinel-tenant-isolation-design.md` on Draft PR #42
- Review existing: `docs/superpowers/plans/2026-11-07-sentinel-tenant-isolation-implementation-plan.md` on Draft PR #42
- Create/modify only after review: a main-based tenant-foundation branch and focused PostgreSQL migration tests.

**Interfaces:**
- Tenant identity is server-generated and UUID-based.
- Each existing operational row is assigned to one deterministic `legacy-default` tenant before non-null constraints.
- `tenant_id` is never accepted from ordinary resource create/update payloads.

- [ ] **Step 1: Add populated-database migration fixtures**

  Verify migration behavior for duplicate hostnames in different future tenants, orphan assessment/job/remediation references, ad-hoc assessments, audit hash-chain rows and existing API credentials. Assert all old rows remain attributable to the legacy tenant after migration.

- [ ] **Step 2: Run the migration review**

  Run: `cd backend && pytest -q tests/test_migrations.py`

  Expected: existing migration tests remain green; the new fixture demonstrates any missing migration rule before code changes.

- [ ] **Step 3: Port or rebase only reviewed tenant work**

  PR #42 is design-only and PR #43 is schema-foundation-only; both are stacked on the unmerged 0.23 feature chain. Do not retarget/merge them wholesale into main. Create a main-based port with only reviewed tenant design and schema changes, preserving unrelated feature branches.

- [ ] **Step 4: Add tenant registry and membership schema**

  Add tenants, human profiles, memberships, company domain verification challenges and subscription foreign-key anchors as additive migrations. Backfill all existing assets, assessments, jobs, remediations, audit events and credentials to the legacy tenant. Keep legacy bootstrap service credentials explicitly bound to that tenant only.

- [ ] **Step 5: Verify the focused pass**

  Run: `cd backend && pytest -q tests/test_migrations.py tests/test_postgres_job_queue.py`

  Expected: upgrade/downgrade and populated legacy backfill pass; downgrade refuses to delete tenants created after migration.

- [ ] **Step 6: Commit the passing deliverable**

  `feat: add tenant registry and legacy ownership foundation`

## Task 3: Human identity, profile and personal workspace provisioning

**Files:**
- Create: `backend/app/identity.py` (verified JWT/issuer helpers)
- Create: `backend/app/routes/identity.py`
- Create: `backend/tests/test_identity.py`
- Modify: `backend/app/auth.py` — distinct HumanPrincipal and MachinePrincipal; keep ApiPrincipal behavior during transition
- Modify: `backend/app/main.py` — mount identity router
- Create: `frontend/src/auth/supabase.ts` (browser-safe client factory, no secret key)
- Create: `frontend/src/auth/AuthProvider.tsx`
- Create: `frontend/src/pages/AuthPage.tsx`
- Create: `frontend/src/pages/ProfileSetupPage.tsx`
- Modify: `frontend/src/app.tsx` — route public auth vs protected console
- Modify: `frontend/package.json` and lockfile — pin compatible Supabase packages

**Interfaces:**
- `GET /api/v1/identity/session` validates the signed Supabase access token and returns user/profile plus authorized memberships.
- `POST /api/v1/identity/profile` accepts first name, last name, username and optional use-case only; user ID/email come from the verified JWT.
- `POST /api/v1/identity/workspaces/personal` creates one personal workspace and one owner membership atomically/idempotently.
- Supabase Auth remains the source of credentials and provider identities; FastAPI never stores human passwords.

- [ ] Add tests rejecting expired token, wrong issuer/audience, bad signature, missing subject, inactive profile, duplicate username and repeated personal workspace creation.
- [ ] Verify the failures before implementing JWT and identity routes.
- [ ] Validate Supabase asymmetric JWT signatures via the project's JWKS endpoint; pin accepted algorithms and issuer/audience; do not trust user_metadata for authorization.
- [ ] Create server-owned profile data, personal tenant and owner membership in one transaction. If the transaction fails, no partial workspace is retained.
- [ ] Verify email is confirmed before human session is allowed to access operational resources.
- [ ] Run identity, auth and all backend tests.
- [ ] Commit: `feat: add verified human identity and personal workspace`

## Task 4: Company onboarding, membership and domain proof

**Files:**
- Create: `backend/app/routes/organizations.py`
- Create: `backend/app/services/domain_verification.py`
- Create: `backend/tests/test_organizations.py`
- Create: `frontend/src/pages/CompanyOnboardingPage.tsx`
- Create: `frontend/src/pages/WorkspaceInvitePage.tsx`
- Modify: `backend/app/models.py` and Alembic migration for company profile/domain challenge tables

**Interfaces:**
- `POST /api/v1/organizations` creates a new isolated company tenant from validated company profile fields.
- `POST /api/v1/organizations/{tenant_id}/domains/challenges` creates a one-time DNS TXT challenge for a tenant owner.
- `POST /api/v1/organizations/{tenant_id}/domains/verify` verifies the challenge against authoritative DNS and marks the domain verified.
- `POST /api/v1/organizations/{tenant_id}/invitations` invites a human email to a named membership role; invite acceptance requires authenticated matching verified email and active challenge.
- Company domain alone never auto-joins employees to existing organizations.

- [ ] Add cross-tenant invitation and forged-domain tests before implementation.
- [ ] Verify missing, expired, replayed and wrong DNS challenge tokens fail closed.
- [ ] Implement one-time challenge with expiry, constant-time token comparison, bounded DNS lookups and audit event.
- [ ] Implement membership invitation/acceptance with least-privilege default role.
- [ ] Run organization and tenant-isolation tests.
- [ ] Commit: `feat: add verified company workspaces and invitations`

## Task 5: Google/GitHub OAuth and secure browser sessions

**Files:**
- Create: `frontend/api/auth/callback.ts` (Vercel Node Function, PKCE code exchange)
- Create: `frontend/api/auth/session.ts`
- Create: `frontend/api/auth/logout.ts`
- Create: `frontend/api/auth/csrf.ts`
- Create: `frontend/src/auth/oauth.ts`
- Modify: `frontend/src/auth/AuthProvider.tsx`
- Create: `frontend/tests/auth-session.test.ts`
- Modify: Vercel project environment/redirect configuration documentation.

**Interfaces:**
- Browser-to-BFF calls remain same-origin.
- OAuth provider callbacks exchange a single-use PKCE code and set Secure, HttpOnly, SameSite cookies.
- Session endpoint returns only a public user/profile/membership snapshot, never refresh tokens.
- CSRF token is bound to session and required on state-changing cookie-authenticated requests.
- Google and GitHub OAuth provider secrets remain in Supabase Auth provider configuration, not Vite.

- [ ] Add PKCE, state/nonce, CSRF, secure-cookie and logout-revocation tests.
- [ ] Verify callback rejects expired/replayed code, wrong redirect URI and state mismatch.
- [ ] Add Vercel Functions and cookie handling using current Supabase server-side guidance.
- [ ] Configure exact production and preview redirect allow-list values; no wildcard production redirect.
- [ ] Run frontend auth/session tests and Vercel preview smoke test.
- [ ] Commit: `feat: add Google and GitHub OAuth BFF sessions`

## Task 6: Machine identity and workspace-bound service credentials

**Files:**
- Create: `backend/app/routes/machine_identities.py`
- Create: `backend/tests/test_machine_identities.py`
- Modify: `backend/app/models.py` and Alembic migration for service identities
- Modify: existing API credential route/service and `backend/app/auth.py`

**Interfaces:**
- `POST /api/v1/workspaces/{tenant_id}/machine-identities` requires tenant owner/admin membership and creates a service principal.
- `POST /api/v1/machine-identities/{id}/credentials` returns a random credential once; only its hash is stored.
- MachinePrincipal includes tenant_id, machine_identity_id, role, permission set, scoped asset IDs, expiry and credential ID.
- Existing `X-API-Key` header remains accepted for machine credentials; human JWTs use a separate bearer/session path.

- [ ] Add tests for human credential rejection, cross-tenant credential lookup, revoked/expired credential, asset-scope escalation and one-time raw secret disclosure.
- [ ] Verify failing tests first.
- [ ] Add owner-created machine identity and tenant-bound credential lifecycle.
- [ ] Verify secret hash storage, rotation overlap, audit attribution and per-credential quotas.
- [ ] Run all auth, credential and tenant tests.
- [ ] Commit: `feat: add tenant-owned machine identities`

## Task 7: Subscription and Free Early Access entitlements

**Files:**
- Create: `backend/app/subscriptions.py` (central plan resolver)
- Create: `backend/app/routes/subscriptions.py`
- Create: `backend/tests/test_subscriptions.py`
- Modify: `backend/app/models.py` and Alembic migration for plan/subscription/usage records
- Create: `frontend/src/pages/PlansPage.tsx`
- Modify: `frontend/src/app.tsx` navigation and account workspace
- Modify: `frontend/src/styles.css` pricing and plan state styling

**Interfaces:**
- `GET /api/v1/plans` is public and read-only; returns current Free plus preview tiers.
- `GET /api/v1/workspaces/{tenant_id}/subscription` requires verified membership and returns current plan/status/usage.
- `GET /api/v1/workspaces/{tenant_id}/entitlements` returns the server-calculated entitlement snapshot.
- `subscriptions.resolve_entitlements(tenant, plan, launch_mode=True)` grants every currently shipped core module during Free Early Access and applies workspace-specific usage ceilings.
- Plan or quota values in request payloads are ignored; server catalogue and counters are authoritative.

- [ ] Add tests for default Free assignment, all shipped feature codes enabled, preview plans not purchasable, no billing side effects, quota ceilings, UTC reset, idempotent counter increments and concurrent reservation.
- [ ] Verify tests fail before implementing the resolver.
- [ ] Add idempotent subscription creation and transactional usage ledger. Preserve historical usage and never delete evidence when a quota is reached.
- [ ] Add quota enforcement before assets/assessment jobs/machine identity creation. Reject excess with 429 or 409 and a machine-readable code plus reset time; never silently downgrade or truncate.
- [ ] Keep checkout/payment routes absent until a separately approved billing release.
- [ ] Run backend and PostgreSQL concurrency tests.
- [ ] Commit: `feat: add Free Early Access subscriptions and entitlements`

## Task 8: Email delivery, verification, recovery and anti-bot controls

**Files:**
- Create: `backend/app/services/email_templates.py` or approved Supabase Auth email templates
- Create: `frontend/api/auth/turnstile.ts` (server verification boundary)
- Create: `frontend/src/components/TurnstileGate.tsx`
- Create: `frontend/tests/turnstile.test.ts`
- Modify: Supabase Auth project configuration through approved management settings only after secrets/DNS are available.
- Modify: Cloudflare DNS only with exact provider-generated records.

**Interfaces:**
- Supabase Auth uses custom SMTP on `auth.toolixaai.com`.
- Auth flows include confirmation, password recovery, secure email change, invite and security alert.
- Turnstile token is verified server-side using the secret; missing, expired, hostname-mismatched or replayed tokens are rejected.
- Inbound `support@`, `security@`, `abuse@`, `admin@`, `alerts@` routes only after the receiving inbox is confirmed; routing and transactional sending remain separate.

- [ ] Add tests for invalid/expired/missing Turnstile tokens and safe provider failures.
- [ ] Verify red tests first.
- [ ] Add templates and sending provider adapter; keep credentials encrypted and absent from client bundles/logs.
- [ ] Configure provider DNS from exact generated SPF/DKIM records; preserve root MX records.
- [ ] Enable custom SMTP only after provider/domain test delivery and redirect allow-list verification.
- [ ] Run integration tests using a test inbox; confirm no real customer mail is sent by CI.
- [ ] Commit: `feat: secure transactional auth email and bot checks`

## Task 9: Frontend signup, login and workspace experience

**Files:**
- Create: `frontend/src/pages/SignUpPage.tsx`
- Create: `frontend/src/pages/SignInPage.tsx`
- Create: `frontend/src/pages/EmailVerificationPage.tsx`
- Create: `frontend/src/pages/PasswordRecoveryPage.tsx`
- Create: `frontend/src/pages/WorkspacePickerPage.tsx`
- Create: `frontend/src/pages/AccountSettingsPage.tsx`
- Create: `frontend/src/pages/CompanyOnboardingPage.tsx`
- Modify: `frontend/src/app.tsx`, `frontend/src/styles.css`
- Add focused React component tests.

**Interfaces:**
- Public routes: landing, plans, signup, signin, email confirmation result, password recovery.
- Protected route: /app and workspace settings.
- Signup asks Personal/Company first; fields are conditionally displayed.
- Google and GitHub buttons start OAuth via same-origin BFF.
- API-key login remains available only under service/integration access during migration, not as the main human login.
- UI shows the active workspace and server-derived plan and usage; no fake metrics.

- [ ] Add component tests for validation, provider errors, pending verification, session expiration and workspace switch denial.
- [ ] Verify test failures before implementation.
- [ ] Implement accessible, responsive auth and workspace UI with reduced-motion behavior.
- [ ] Preserve existing animated SENTINEL SVG and console functions; do not rewrite unrelated operational views.
- [ ] Run `npm ci && npm audit --audit-level=moderate && npm run build`.
- [ ] Commit: `feat: add personal and company SaaS onboarding UI`

## Task 10: Security verification and guarded launch

**Files:**
- Create: `backend/tests/test_tenant_negative_access.py`
- Create: `backend/tests/test_subscription_abuse.py`
- Create: `backend/tests/test_oidc_token_validation.py`
- Modify: `.github/workflows/ci.yml` only where focused test steps are needed.
- Modify: `docs/cloud-deployment.md` with exact configuration and rollback.

**Interfaces:**
- Security matrix covers 2 tenants, 2 human users, 1 service principal and deliberately overlapping asset names/IDs.
- Signup feature flag remains off until all tests and production provider settings are reviewed.
- `SENTINEL_ALLOWED_DOMAINS=sentinel.invalid` remains enforced.

- [ ] Verify cross-tenant read/write/list/aggregate/export/job/audit attempts all fail.
- [ ] Verify deleted/revoked memberships take effect on next request.
- [ ] Verify user metadata cannot grant admin, owner or billing permissions.
- [ ] Verify payment preview routes cannot create charges and billing remains disabled.
- [ ] Verify no secret, session token or PII appears in frontend bundle, logs or audit details.
- [ ] Run full backend tests, PostgreSQL migration/negative tests, frontend tests/build, CodeQL, dependency review, Trivy and production-like browser UAT.
- [ ] Keep public signup disabled until independent review signs off.
- [ ] Commit: `test: gate Free Early Access launch on tenant security`

## Release and rollback rules

- Ship each independently testable task through a short-lived branch and Pull Request.
- Merge only when exact-head CI, CodeQL, dependency/supply-chain and review gates pass.
- Vercel and Render deploy from protected `main` only after checks pass.
- Database migrations are additive, rehearsed on a populated snapshot and reversible where possible; destructive downgrade refuses to drop customer-created tenant data.
- If identity or tenant enforcement fails, disable signup via feature flag and keep existing service API-key integration operating. Do not fall back to a global cross-tenant admin key.

## Explicitly unresolved operational inputs

- Google OAuth Client ID/Secret and GitHub OAuth App credentials must be generated in their provider dashboards before those buttons can be enabled.
- Resend (or another SMTP provider) account and verified sender domain are required before public email verification can be sent.
- The exact receiving Gmail address spelling must be confirmed before creating Cloudflare inbound forwarding rules.
- Cloudflare Turnstile site and secret keys must be created before public signup can be enabled.
- Vercel production plan upgrade is not part of this plan; Free hosting remains subject to its current commercial-use restrictions and resource limits.
