# SENTINEL Free-First SaaS Product and Identity Architecture

**Status:** approved product direction; implementation is staged and not yet a claim of production multi-tenancy  
**Date:** 2026-11-09  
**Target:** 300 monthly active users for the first public operating target

## 1. Product decision

SENTINEL is a multi-tenant Security Operations SaaS. The launch model is **Free Early Access**:

- Every new human account is assigned the `free_early_access` plan by default.
- Personal and Company workspaces can use every currently shipped core security module without a paid feature gate.
- Checkout, subscription charging, invoices, card collection and paid-plan enforcement are disabled.
- Future plan prices are catalogue previews only and must never create a payment intent or entitlement change.
- Fair-use limits protect shared infrastructure and assessment capacity. These are usage ceilings, not feature paywalls.
- Existing API-key integrations remain supported during the human-identity rollout.
- No production customer data is migrated or exposed until tenant isolation is fully enforced and independently tested.

The first operating target is 300 monthly active human users. This is a planning target, not a capacity guarantee. Concurrent assessments, workload duration, database load and email throughput must be load-tested before claiming scale.

## 2. Workspace and identity types

Keep workspace type separate from identity type.

### Workspace types

1. **Personal workspace** — created automatically for a new human user. The owner is the registering human.
2. **Company workspace** — created by a human registrant. Company metadata and ownership/domain verification are collected; the person who registers becomes the initial workspace owner only after email verification and successful workspace creation.

A human can belong to multiple workspaces and switch active workspace only after the server verifies an active membership. A company domain or email address alone never grants membership in an existing organization.

### Human identity

A person signs up through one of:
- Email + password with mandatory email verification.
- Google OAuth.
- GitHub OAuth.

Store given name, family name and a unique username in a server-owned profile. A primary use case is optional. Do not add a user-editable "I am a human" checkbox as proof of personhood. Apply server-verified Cloudflare Turnstile to public signup and other abuse-sensitive anonymous flows.

Provider identities must be linked only after authenticating the existing SENTINEL account and verifying the new provider identity. Do not automatically merge accounts merely because two providers return an unverified or ambiguous email.

### Company registration

Required fields:
- Company legal/display name.
- Company type: sole proprietor, partnership, private limited/LLC, public corporation, non-profit/NGO, government, or other.
- Industry: technology/software, banking/fintech, healthcare, manufacturing/industrial, energy/utilities, telecom, retail/e-commerce, professional services, education, government, or other.
- Employee range: 1, 2–10, 11–50, 51–200, 201–1,000, 1,001–5,000, 5,001+.
- Country.
- Official website and primary company domain.
- Registering contact's first name, last name, username, verified work email and job title.

Optional fields:
- Department, phone, registration number, tax/VAT number and billing contact.
- A registration number or corporate document is not required for ordinary signup. Stronger verification may be requested for enterprise features or risk-based review.

A newly registered company receives a new isolated workspace, not access to an existing workspace sharing that domain. Domain ownership requires a DNS TXT challenge before the domain can be treated as verified. Invitations or an approved domain-join policy are required for other employees.

### Machine / AI identity

A machine identity is a **workspace-owned service principal**, never a public human signup option.

- A human workspace owner/admin creates it.
- It belongs to exactly one tenant.
- It has an owner, purpose, permissions, scoped assets, quotas, expiry/rotation metadata and audit attribution.
- Credentials are high-entropy opaque API keys stored only as hashes; the raw secret is shown once.
- Revocation and expiry are enforced on every request.
- Human and machine authentication paths are distinct.
- A machine cannot create another workspace, elevate itself to a human role, or grant itself broader scope.

## 3. Free-first plan catalogue

### Current launch policy

The only selectable and active plan at launch is **Free Early Access — $0/month**. All currently shipped core security modules are available to both Personal and Company workspaces. No feature is withheld based on a future paid tier.

Fair-use limits are applied by workspace type:

| Resource | Personal Free Early Access | Company Free Early Access |
|---|---:|---:|
| Registered assets | 10 | 25 |
| Completed assessments | 20 / calendar month | 50 / calendar month |
| Human seats | 1 | 5 |
| Machine identities | 2 | 3 |
| Evidence retention | 30 days | 30 days |
| Core security modules | All currently shipped modules | All currently shipped modules |
| Billing/checkout | Disabled | Disabled |

A quota response must state the resource, current usage, limit and reset time. Quota counters use the workspace time zone policy (UTC for the first release) and must be updated transactionally/idempotently. Usage caps may pause new work but must not delete existing evidence or bypass asset authorization.

### Future catalogue previews — not for sale

These are proposed list prices for later review. They are not active subscriptions, not checkout offers and not a promise of future features or pricing.

| Preview tier | Proposed list price | Planned audience |
|---|---:|---|
| Free | $0/month | Early access; active now |
| Pro | $29/month | Independent security professionals and small teams |
| Team | $99/month | Collaborative security teams |
| Business | $299/month | Growing organizations with formal operations |
| Enterprise | Custom | Large/regulated organizations with negotiated requirements |

Preview plan capacity targets:
- Pro: 100 assets, 300 assessments/month, 3 human seats, 10 machine identities, 90-day evidence retention.
- Team: 500 assets, 1,500 assessments/month, 15 human seats, 30 machine identities, 180-day evidence retention.
- Business: 2,000 assets, 8,000 assessments/month, 50 human seats, 100 machine identities, 365-day evidence retention.
- Enterprise: negotiated limits and support terms; no automated quote or entitlement until contract controls exist.

The launch-mode entitlement resolver grants all currently shipped core feature codes regardless of preview tier. Future plan comparisons are informational only. Paid entitlements remain disabled until an owner-controlled billing rollout is explicitly approved.

### Billing safety invariants

- Global `BILLING_ENABLED=false` in every current deployment.
- No Stripe/payment SDK, checkout route, card collection or payment secret is required for launch.
- A plan preview can never mutate the active subscription.
- New personal and company workspaces receive `free_early_access`.
- No free-trial expiration or surprise upgrade.
- No automatic paid conversion.
- If billing configuration is missing or invalid, the system remains Free; it never grants a paid entitlement.
- When billing is introduced later, it must be a separate reviewed release with webhook signature verification, idempotency, audit events, cancellation and grace-period rules.

## 4. Subscription and entitlement domain model

After the tenant registry is in place, add:

- `plan_catalog`: stable plan code, version, display metadata, price preview, currency, billing interval, availability and public visibility.
- `plan_entitlements`: plan/version to feature-code and limit mapping.
- `workspace_subscriptions`: one active subscription per workspace, current plan code, state, source, billing identifiers (nullable), period dates (nullable), created/updated timestamps.
- `usage_periods` or a ledger/counter table: workspace, metric code, UTC period start/end, used amount, idempotency key.
- Optional `billing_events` later; never create a payment event without a real verified provider webhook.

The subscription schema is a capability model, not a reason to turn billing on. The initial row is `free_early_access` with provider `none`, no payment customer ID and no checkout session.

## 5. Identity, session and API architecture

Use Supabase Auth as the human identity provider and Vercel Functions as a same-origin Backend-for-Frontend (BFF) for browser sessions. FastAPI remains the operational control plane.

- Use Authorization Code + PKCE for email confirmation and OAuth callbacks.
- Configure Google and GitHub as separate Supabase OAuth providers.
- Verify issuer, audience, signature, expiry, state/nonce/PKCE and key rotation.
- Use secure, HttpOnly, SameSite cookies for the BFF session; rotate on login and privilege changes; protect state-changing requests with CSRF validation.
- Do not place service-role keys, SMTP secrets, worker secrets or bootstrap API keys in Vite/browser environment variables.
- FastAPI verifies Supabase JWTs using the configured issuer/JWKS and accepted algorithm/audience. It must reject unsigned tokens, wrong issuer/audience, expiry and key/algorithm confusion.
- Resolve tenant and role from server-side membership records. User-editable metadata is never authorization input.
- Keep legacy `X-API-Key` service access operating while tenant-bound service credentials are introduced. Do not silently reinterpret a legacy global key as tenant-wide production access.

## 6. Tenant data isolation

No public human signup is enabled until this release gate is met:

- All tenant-owned rows have a non-null tenant ID.
- Legacy records are deterministically assigned to a migration-owned legacy tenant.
- Tenant memberships and machine credentials are bound to exactly one tenant.
- Every read/write/aggregate/export/audit/worker action is scoped server-side before pagination or serialization.
- Composite foreign keys prevent cross-tenant asset/assessment relationships.
- PostgreSQL RLS is defense in depth, with transaction-local tenant context.
- Negative tests demonstrate Tenant A cannot read, change, enumerate, count, export or infer Tenant B resources.
- Missing context fails closed.
- Pooled database connections cannot retain a prior request's tenant setting.

The existing Draft PR #42 (design) and #43 (tenant registry/ownership schema) are inputs, not completed isolation. Their branch dependencies and exact-head CI must be reviewed before merge. Schema columns alone do not authorize public signup.

## 7. SMTP and domain email

Use a dedicated sending subdomain, e.g. `auth.toolixaai.com`, for authentication mail. Keep incoming support forwarding on the root domain separate.

- Cloudflare Email Routing handles inbound `support@`, `security@`, `abuse@`, `admin@` and `alerts@` mail to a verified receiving inbox.
- Email Routing is not a hosted mailbox and does not send outbound replies from those addresses by itself.
- Use a transactional email provider supporting SMTP for Supabase Auth (recommended initial evaluation: Resend Free, subject to account/domain verification and then-current limits).
- Configure Supabase custom SMTP only after the sender domain is verified and exact DKIM/SPF/DMARC records are returned by the provider.
- Keep the provider API/SMTP secret only in Supabase/Render secret storage.
- Use separate authentication sender `noreply@auth.toolixaai.com`; do not mix marketing messages with authentication email.
- Email verification, password reset, secure email change, invitation and account security notification templates are required.
- Do not alter root-domain MX records that may affect the user's existing Gmail or other mail service.

## 8. Security and product boundaries

- Keep `SENTINEL_ALLOWED_DOMAINS=sentinel.invalid` until explicit target authorization is approved. Signup or payment never authorizes a scan target.
- Assessment scope, DNS resolution safety, no redirects, request/body bounds, worker leases, audit integrity and existing rate limits remain mandatory.
- Turnstile siteverify is performed server-side; an unchecked client-side widget is not accepted.
- Machine identity is not a human signup class.
- Company email domain is not a substitute for company workspace invitation or TXT ownership proof.
- Do not claim SOC 2, ISO 27001 or other certification.
- Keep public plan catalogue read-only and no-store only where appropriate; no private tenant data is exposed by it.
- Use accessible motion preferences; no false "live scan" or synthetic telemetry in the UI.

## 9. Release stages

1. Public Free Early Access plan catalogue and product pricing preview.
2. Tenant registry and verified ownership migration.
3. Supabase human identity, profile, personal workspace and membership.
4. Company onboarding, DNS domain verification and invitation lifecycle.
5. FastAPI JWT validation and tenant-scoped resource access.
6. Vercel BFF, signup/login/OAuth/session recovery UI.
7. Machine identities and tenant-bound credentials.
8. Quotas and subscription/entitlement persistence (billing remains disabled).
9. Custom SMTP, email templates, Turnstile and abuse protections.
10. Negative cross-tenant, OAuth, session, quota, worker and migration tests.
11. Gradual public launch for the 300-MAU target, with monitoring and rollback.

## 10. Acceptance criteria

- New personal/company workspaces default to `free_early_access`.
- No user can be charged and no payment provider is called.
- The public plans API clearly labels preview plans and proposed prices as not purchasable.
- All currently shipped core feature entitlements are available on Free Early Access.
- Usage limits are server-enforced and cannot be bypassed with client-supplied plan or tenant IDs.
- Email, Google and GitHub paths follow email verification and secure account-linking rules.
- Company memberships require invitation or verified-domain policy; domain similarity alone grants no access.
- Machine credentials are owner-created, one-time visible and revocable.
- Cross-tenant tests and migration reconciliation pass before signup is enabled.
