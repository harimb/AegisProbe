# AegisProbe

A self-hosted web application security scanner. Point it at an app **you own or are
authorized to test**, and it discovers the app's endpoints, runs OWASP-aligned
passive checks, and (optionally) drives an [OWASP ZAP](https://www.zaproxy.org/)
active scan — then shows the findings in a report with charts, filtering,
pagination, a live progress log, and JSON/Excel export.

> ⚠️ **Only scan systems you are authorized to test.** Every scan is gated by a
> host allowlist and a per-scan authorization confirmation.

## Features

- **Endpoint discovery** — same-origin crawl (jsoup) plus any OpenAPI document the
  target exposes (`/v3/api-docs`), streamed live as it runs.
- **Passive checks** (OWASP Top 10 aligned) — missing security headers (CSP,
  X-Content-Type-Options, clickjacking, HSTS), insecure cookie flags, reflected
  input, exposed `/actuator` endpoints, stack-trace leaks, cleartext HTTP.
- **Active scan (optional)** — spiders and actively scans the target with OWASP ZAP
  running in a container, mapping ZAP alerts into the same report.
- **Deduplicated findings** — one row per issue type (with a count), so a large
  crawl doesn't repeat the same finding for every similar URL.
- **Report UI** — severity donut + OWASP-category chart, a color-coded, filterable,
  paginated findings table, a live activity log, and **JSON / Excel (.xlsx)** export.
- **Scan management** — multi-select bulk delete, cancel-and-delete running scans,
  and view a completed scan's activity log.
- **Auth** — form-based login/registration (Spring Security, bcrypt).

## Tech stack

Java 25 · Spring Boot 4.1 · Spring Security · Spring Data JPA · PostgreSQL + Flyway ·
Thymeleaf · Apache POI · jsoup · OWASP ZAP · Testcontainers.

## Getting started

### Prerequisites

- JDK 25
- Docker (for PostgreSQL, ZAP, and the Testcontainers-based tests)

### Run it

Spring Boot's Docker Compose support starts PostgreSQL automatically, so you can just
run the app:

```bash
./mvnw spring-boot:run
```

Then open <http://localhost:8080>, register an account, log in, and open
**Security scan**.

To run the whole thing (app + database) in Docker:

```bash
docker compose --profile app up --build
```

### Active scanning with OWASP ZAP

The active scan needs ZAP running. Start it with the `scanner` profile, then tick
**"Also run an active scan"** on the scan form:

```bash
docker compose --profile scanner up -d zap
```

## Configuration

Set via `application.properties` or environment variables:

| Property | Default | Purpose |
|---|---|---|
| `scanner.allowed-hosts` | `localhost,127.0.0.1,::1` | Hosts a scan may target |
| `scanner.sample-endpoints` | `25` | Max endpoints the per-URL checks probe |
| `scanner.openapi.path` | `/v3/api-docs` | Where to look for an OpenAPI doc |
| `scanner.zap.base-url` | `http://localhost:8090` | ZAP daemon API |
| `scanner.zap.target-host-override` | `host.docker.internal` | Lets ZAP (in a container) reach a `localhost` target |

The database credentials in `compose.yaml` are local-development defaults — supply
real values via environment variables for any deployed environment.

## Testing

```bash
./mvnw test
```

Tests use Testcontainers, so Docker must be running.

## Project structure

```
com.aegisprobe
├── scanner
│   ├── domain       JPA entities (Scan, Finding) + enums
│   ├── repository   Spring Data repositories
│   ├── service      discovery, checks, ZAP, dedup, progress, export
│   ├── web          ScanController
│   └── config
└── user             auth (entity, repository, service, controller)
```
