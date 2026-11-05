# DNS lookup budget and incomplete-evidence policy

SENTINEL DNS posture checks use a shared monotonic deadline rather than granting each record lookup a fresh timeout.

## Why this matters

A sequence of independent DNS lookups can multiply worst-case latency. It can also create misleading findings: a resolver timeout is not evidence that SPF, DMARC or CAA is absent.

## Implemented behavior

- The DNS posture inspection receives a bounded timeout from the assessment workflow.
- Every lookup receives only the remaining time from one monotonic deadline.
- NXDOMAIN and NoAnswer are treated as completed negative answers for the queried record type.
- Resolver timeout and NoNameservers are treated as incomplete evidence.
- Missing-record findings are suppressed when that specific lookup did not complete.
- The result records an overall completion flag and the list of incomplete checks.
- One DNS_POSTURE_INCOMPLETE finding explains that the assessment should be repeated after resolver health is restored.
- CAA lookup walks parent DNS labels while staying inside the same deadline, avoiding false missing findings when a parent policy applies.

This is a bounded passive lookup policy, not a DNSSEC validation service. Resolver-level DNSSEC validation and infrastructure egress policy remain separate controls.
