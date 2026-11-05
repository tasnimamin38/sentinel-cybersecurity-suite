# SENTINEL Defensive Security Platform — Design

Date: 2026-11-05
Status: Initial implementation baseline

## Intent

Build a private, extensible platform for authorized security posture management, with a usable operator console and a modular backend. The immediate goal is a real, testable foundation rather than a feature mockup.

## Goals

- Assess only explicitly allowlisted DNS hostnames.
- Provide safe HTTPS-header, TLS-certificate and DNS email-authentication posture checks.
- Normalize findings with severity and recommendations.
- Persist assessment history and audit events.
- Provide a responsive dashboard with API-key connection.
- Support Docker and CI from the first commit.

## Non-goals

- Exploitation, credential attacks, stealth, persistence, lateral movement, destructive scanning, arbitrary IP scanning, or unauthorized testing.
- Claiming regulatory certification or production readiness from an initial MVP.

## Approaches considered

1. Single-script scanner: fastest, but poor separation, auditability and maintainability.
2. Modular API + operator console + relational persistence: selected because it supports testing, safe policy enforcement, extension points and enterprise deployment evolution.
3. Microservices and distributed worker fleet immediately: rejected for v0.1 because it adds operational overhead before workload and tenancy requirements are known.

## Selected defaults

- Python 3.11+ / FastAPI / SQLAlchemy for the service.
- React + TypeScript + Vite for the console.
- PostgreSQL in Docker Compose, SQLite for quick local tests.
- Explicit API-key authentication for the single-operator MVP.
- Domain allowlist, public-address check, HTTPS-only, redirects disabled, bounded timeouts.
- All third-party targets must be covered by written authorization.

## Constraints and builder calls

DNS lookup and connection currently are separate calls; a production egress proxy/firewall with DNS pinning is required to address DNS-rebinding races. Enterprise identity, multi-tenancy, durable workers, migration management and immutable log storage are planned upgrades, not current claims.