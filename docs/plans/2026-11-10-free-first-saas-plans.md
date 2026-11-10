# SENTINEL Free-First SaaS Plan Catalog Implementation Plan

> **For agentic workers:** Use the host's available task-by-task implementation workflow. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the public SENTINEL plan catalog accurately describe a Free Early Access SaaS launch where every currently shipped core security capability is available to Personal and Company workspaces without subscription-based feature gates or quota enforcement, while future paid tiers remain non-purchasable previews.

**Architecture:** Keep the existing FastAPI public `GET /api/v1/plans` endpoint as the single source of truth. Add a structured feature catalog that maps only to capabilities already implemented in the current `main` branch, preserve the current plan codes and preview prices, and render the full included-feature list in the existing React Plans & Access view. Billing, checkout, entitlement enforcement and payment-provider integrations remain disabled.

**Tech Stack:** FastAPI, Python, Pydantic-compatible JSON responses, pytest, Ruff, React 19, TypeScript, Vite, GitHub Actions.

## Global Constraints

- Every new Personal or Company workspace continues to default to `free_early_access`.
- All currently shipped core security modules are included in Free Early Access.
- No product feature is gated by payment during Free Early Access.
- Subscription usage ceilings are informational planning targets only; no account-level quota enforcement is introduced by this change.
- Platform safety controls remain mandatory for every user: authorized-domain scope, API-key authorization, request-body limits, abuse/rate limiting, queue capacity, credential expiry/revocation and security audit controls.
- Future plan prices are proposals only. Pro remains $29/month, Team $99/month, Business $299/month and Enterprise custom in the preview catalogue; none is purchasable.
- `BILLING_ENABLED` and `CHECKOUT_ENABLED` remain false. No payment provider, checkout route, webhook secret, paid resource, paid upgrade or production billing setting is created.
- Only features already implemented on `main` may be marked `available`. OIDC/SSO, MFA, complete tenant isolation, SCIM, external SIEM integrations and immutable external evidence storage remain roadmap items until their implementation and release gates pass.
- Preserve existing API paths, plan codes, current API-key authentication, scope restrictions, audit behavior, worker settings, database schema and deployment configuration.
- Work on a feature branch; do not push implementation changes directly to `main`.

---

### Task 1: Expand the tested public Free feature catalogue

**Files:**
- Modify: `backend/app/plans.py`
- Modify: `backend/tests/test_plans.py`

**Interfaces:**
- Consumes: `get_public_plan_catalog(workspace_type: str | None = None) -> dict[str, Any]`
- Produces: `feature_catalog` in the existing `GET /api/v1/plans` JSON response. Each entry contains `code`, `name`, `category`, `description` and `status="available"`. The Free plan's `feature_codes` contains every available catalogue code.

- [ ] **Step 1: Add focused failing tests**

Add assertions that:
1. `catalog["feature_catalog"]` exists and is non-empty.
2. The exact current capability codes cover asset inventory, authorized assessments, DNS/TLS posture, security-header analysis, assessment jobs, scheduled jobs, findings, remediation, control mapping, audit integrity, CSV exports, security event monitoring, secret scanning, API credential lifecycle, role-based access control, shared rate limiting and signed alert webhooks.
3. Every feature marked `available` appears in the Free plan's `feature_codes`.
4. Personal and Company catalog responses expose the same available feature set.
5. Free Early Access has no subscription quota enforcement and no checkout.
6. Preview plans remain non-purchasable and preserve their existing proposed prices.

- [ ] **Step 2: Verify the relevant failure**

Run from `backend/`: `python -m pytest tests/test_plans.py -q`.

Expected: the new feature-catalogue assertions fail because the existing response does not include `feature_catalog`; the existing plan tests continue to pass.

- [ ] **Step 3: Implement the minimum backend behavior**

Add a defensive-copy feature catalogue in `backend/app/plans.py`. Keep existing plan identifiers, price proposals, personal/company planning capacities and the public endpoint unchanged. Populate the catalogue only with capabilities confirmed in the existing README and current backend implementation. Include a clear launch notice that all shipped core modules are free, billing is disabled and fair-use targets are not enforced as subscription quotas. Do not add future roadmap capabilities to the available list.

- [ ] **Step 4: Verify the focused pass**

Run: `python -m pytest tests/test_plans.py -q`.

Expected: every plan test passes, including exact feature coverage and defensive-copy behavior.

- [ ] **Step 5: Run affected backend integration checks**

Run: `python -m pytest -q`, `ruff format --check app tests alembic`, and `ruff check app tests alembic` from `backend/`.

Expected: all tests pass and Ruff reports no formatting or lint errors.

- [ ] **Step 6: Commit the passing deliverable**

```bash
git add backend/app/plans.py backend/tests/test_plans.py
git commit -m "feat: publish complete free launch feature catalogue"
```

### Task 2: Render Free access and future plan previews clearly

**Files:**
- Modify: `frontend/src/app.tsx`
- Modify: `frontend/src/styles.css`

**Interfaces:**
- Consumes: `PublicPlanCatalog.feature_catalog` and each plan's `feature_codes`.
- Produces: the existing Plans & Access view with a complete included-feature list for Free Early Access, an explicit no-subscription-quota/no-checkout message, and future paid tiers clearly labeled as previews.

- [ ] **Step 1: Add a focused frontend contract check**

Update the plan response TypeScript types and component so the Free card renders the feature catalogue entries whose codes are in `feature_codes`; render each preview plan's proposed future status without any purchase button or checkout action. The current rendered Free message must state that all shipped modules are free and product quota enforcement is off.

- [ ] **Step 2: Verify the relevant failure**

Run: `npm run build` from `frontend/` after the type contract is added but before the component is updated.

Expected: TypeScript reports the missing catalogue type usage until the component and response type are updated.

- [ ] **Step 3: Implement the minimum UI behavior**

Keep the existing navigation, API fetch, dark visual system, responsive card layout and no-demo-data behavior. Add concise, readable feature rows or chips and a small launch-policy note. Do not add inert purchase buttons, payment forms or fake subscription status.

- [ ] **Step 4: Verify the focused pass**

Run: `npm run build` from `frontend/`.

Expected: TypeScript compilation and Vite production build complete successfully.

- [ ] **Step 5: Run the repository frontend checks**

Run: `npm ci && npm run build` from `frontend/`, and run the existing Cloudflare worker tests using `node --test ../deploy/cloudflare/worker-tick/worker.test.mjs`.

Expected: lockfile install, frontend build and existing worker tests pass.

- [ ] **Step 6: Commit the passing deliverable**

```bash
git add frontend/src/app.tsx frontend/src/styles.css
git commit -m "feat: show free launch modules and future plan previews"
```

### Task 3: Document the launch and billing boundary

**Files:**
- Create: `docs/plans/2026-11-10-free-first-saas-plans.md`

**Interfaces:**
- Consumes: the public plan catalogue contract and the security boundaries above.
- Produces: an operator-facing record of the launch model, proposed future pricing, non-enforced planning capacity, and explicit activation gates for later billing.

- [ ] **Step 1: Add assertions to the plan document checklist**

Document the exact Free-first policy, preview prices, current feature inclusion, operational safety controls, and the conditions required before billing or quotas may be activated.

- [ ] **Step 2: Verify the document against source**

Compare plan codes, prices, feature identifiers and enforcement flags with `backend/app/plans.py` and `backend/tests/test_plans.py`.

Expected: every documented current value matches the implementation and no roadmap item is described as available.

- [ ] **Step 3: Commit the documentation**

```bash
git add docs/plans/2026-11-10-free-first-saas-plans.md
git commit -m "docs: define free-first saas launch policy"
```

### Release gate

- [ ] Backend unit tests, Ruff checks, frontend production build, worker tests, CI, CodeQL and Supply-chain Security pass on the exact PR head.
- [ ] Inspect the rendered Plans & Access view at desktop and mobile widths.
- [ ] Verify `GET /api/v1/plans` without authentication returns the Free plan as default, every shipped feature, preview-only paid tiers and `billing_enabled=false`.
- [ ] Verify no checkout or payment route is introduced and no existing security guard is weakened.
- [ ] Merge only after the exact PR head passes all required checks. Production deployment occurs through the existing GitHub `main` auto-deploy workflow.
