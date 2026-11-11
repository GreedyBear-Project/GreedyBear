# AGENTS.md

Guidance for AI coding agents working in this repository.

## Project Overview

GreedyBear is a threat intelligence platform that extracts Indicators of Compromise (IOCs) from TPOT honeypot clusters and generates threat feeds. It's part of The Honeynet Project and provides public feeds at greedybear.honeynet.org.

## Tech Stack

- **Backend**: Django 5.2, Django REST Framework, PostgreSQL 18, Elasticsearch 9.x, Django Q2 (task scheduling), uv (dependency management, `pyproject.toml`/`uv.lock`)
- **Frontend**: React 19, Zustand (state), Bootstrap 5, Recharts, Vite (build), Vitest (testing), in-tree gb-ui component library, TanStack Table v8
- **ML**: scikit-learn, pandas, numpy, datasketch (MinHash for clustering)
- **Infrastructure**: Docker Compose, gunicorn, nginx

## Common Commands

### Development Setup
```bash
./gbctl init --dev          # Initialize environment files
./gbctl up --dev            # Start services with hot-reload
./gbctl down                # Stop and remove all services
./gbctl logs                # View container logs
./gbctl logs app            # View Django application logs
./gbctl health              # Health check all services
./gbctl create-admin        # Create Django superuser
# Also: start/stop/restart, ps, build, pull, update, clean --force (destructive)
```

### Testing
```bash
# Backend
python manage.py test                                              # All tests
python manage.py test tests.api.views.test_feeds_view              # Specific module
python manage.py test tests.greedybear.cronjobs                    # Test package
python manage.py test --tag=migration --failfast                   # Migration tests only

# Frontend (from frontend/)
npm test                    # Run Vitest tests
npm run test-coverage       # With coverage
npm run test:visual         # Playwright visual tests
```

### Linting
```bash
# Python (ruff, line-length 160)
ruff check .
ruff format .
ty check                    # Type checking (config in pyproject.toml, runs in CI)

# Frontend (from frontend/)
npm run lint                # ESLint
npm run lint-scss           # Stylelint
npm run formatter           # Prettier check
# Add -fix suffix for auto-fix variants (lint-fix, lint-scss-fix, formatter-fix)
```

Linter configurations live in `.github/configurations/` (`python_linters/`, `node_linters/`).

### Database
```bash
python manage.py makemigrations
python manage.py migrate
./gbctl backup
./gbctl restore <backup-file>
```

## Architecture

### Core Data Flow
```
Elasticsearch (TPOT logs) ─┐
                           ├→ Extraction Pipeline → PostgreSQL (IOCs) → REST API → Feeds/Enrichment
POST /api/events/add/ ─────┘   (push-based ingestion from external honeypots)
```

### Extraction Pipeline (`greedybear/cronjobs/extraction/`)
Runs every `EXTRACTION_INTERVAL` minutes (default 10, must be a divisor of 60).
- `ExtractionPipeline` orchestrates: queries Elasticsearch → groups by honeypot → extracts IOCs → scores
- Strategy pattern: `CowrieExtractionStrategy`, `HeraldingExtractionStrategy`, `TannerExtractionStrategy`, `GenericExtractionStrategy` (created via `ExtractionStrategyFactory` in `strategies/factory.py`)
- `IocProcessor` merges/updates IOC records
- Repository pattern in `greedybear/cronjobs/repositories/`: `ElasticRepository` (logs), `IocRepository` (database), `SensorRepository`, `TrendingBucketRepository`, etc.
- At midnight, the extraction run also triggers ML model retraining (`train_and_update()`)
- The extraction task also triggers honeypot payload extraction (`extract_honeypot_payloads()`)

### Event Ingestion API (`api/views/event.py`, `greedybear/process_event.py`)
Push-based ingestion so external honeypot operators can inject events (GreedyBear as data sink, not just T-Pot puller):
- `POST /api/events/add/` — batch submit (max 10,000 events), returns `202 Accepted` with `task_id`/`status_url`; `GET /api/events/status/<task_id>/` — batch status. Both require `CookieTokenAuthentication` and an active `APISource` linked to the user.
- Raw events are bulk-saved as `RawEvent` rows tracked by an `EventStatus` batch; processing is offloaded via Django Q to `process_incoming_event`, which normalizes events into generic hit dicts and reuses `iocs_from_hits()`, `IocProcessor`, and `UpdateScores`. Honeypot-specific strategies are intentionally skipped (Elasticsearch-only fields).
- Provenance is tracked via `Sensor.source_type` (`"external"` vs T-Pot), not an IOC field.
- Abuse prevention: invalid batches increment `APISource.invalid_event_count`; crossing a threshold sets `is_active = False` until an admin unlocks. The counter is periodically reset.

### ML Scoring (`greedybear/cronjobs/scoring/`)
- `RandomForestScorer` predicts IOC recurrence probability (`RFClassifier`/`RFRegressor` in `random_forest.py`)
- `TrainModels` retrains daily; `UpdateScores` applies predictions (`scoring_jobs.py`)
- Models stored in `mlmodels/` directory

### Command Clustering (`greedybear/cronjobs/commands/`)
- LSH (Locality-Sensitive Hashing) clusters attacker command sequences from Cowrie
- Optional: controlled by `CLUSTER_COWRIE_COMMAND_SEQUENCES` env var

### Payload Extraction (`greedybear/cronjobs/payload_extraction.py`)
- `PayloadExtractionJob` stores honeypot-captured files as `HoneypotPayload` records using `QuarantineStorage` (`greedybear/storage.py`), a custom `FileSystemStorage` that quarantines samples

### Trending Attackers (`greedybear/cronjobs/trending.py`)
- Aggregates attacker activity into `AttackerActivityBucket` records powering `/api/feeds/trending/` and the frontend `FeedsTrending` page; buckets cleaned up hourly

### Task Scheduling (`greedybear/cronjobs/schedules.py`)
Uses Django Q2 (not Celery) with cron scheduling, configured via `setup_schedules` management command. Orphaned schedules are auto-removed. Jobs include extraction (every `EXTRACTION_INTERVAL` min), honeypot/log monitoring (hourly), command clustering + DB cleanup (daily), reverse DNS checks and credential-reuse detection (daily), and external feed fetchers (FireHol, Tor exit nodes, mass scanners, WhatsMyIP, ThreatFox, AbuseIPDB, Spamhaus DROP) weekly on Sundays at deterministic per-job times outside 00:00–02:00. External fetchers use the shared `HttpClient` (`greedybear/cronjobs/http_client.py`).

### Core Domain Models (`greedybear/models.py`)
- `IOC`: IP/domain indicators with attack metrics, ML scores, honeypot associations
- `CowrieSession`, `Credential`, `CowrieFileTransfer`: SSH honeypot session records
- `CommandSequence`: Clustered attacker command patterns
- `Honeypot`: Honeypot types (Cowrie, Dionaea, Heralding, etc.)
- `Sensor`, `AutonomousSystem`, `Tag`: IOC context/attribution (`Sensor.source_type` distinguishes T-Pot vs external)
- Event ingestion: `APISource` (external sender, one-to-one with `User`), `RawEvent` (raw event buffer), `EventStatus` (batch tracking)
- `HoneypotPayload`: quarantined captured files
- `AttackerActivityBucket`: trending-feed aggregation
- `ShareToken`: shareable feed access tokens
- External data: `FireHolList`, `TorExitNode`, `MassScanner`, `WhatsMyIPDomain`

### API Layer (`api/views/`)
- `feeds.py`: Feed generation (text, JSON, CSV, NDJSON) with filtering. Public: `SimpleFeedView`, `PaginatedFeedView`, `TrendingFeedView`, `ConsumeFeedView` (token-based). Auth required: `AdvancedFeedView` (`/api/feeds/advanced/`), `AsnFeedView` (`/api/feeds/asn/`), `ShareTokenViewSet` (create/revoke/list share tokens)
- `enrichment.py`: IP/domain reputation lookup
- `cowrie_session.py`: Session details and credentials
- `command_sequence.py`: Command clustering visualization
- `event.py`: Event ingestion endpoints (see above)
- `sensor.py`, `statistics.py`, `honeypots.py`, `health.py`, `news.py`: sensor registration, dashboard statistics, honeypot list, health check, news
- OpenAPI schema via drf-spectacular at `/api/schema/` (Swagger UI + Redoc)

### Frontend (`frontend/src/`)
- Lazy-loaded routes in `components/Routes.jsx`
- State management via Zustand hooks in `stores/`
- Shared UI components (gb-ui) live in-tree at `components/common/gb-ui/` (moved from the external `GreedyBear-Project/gb-ui` package in #1482), exported via its `index.js`
- `gb-ui/components/table/DataTable.jsx` is the sole `@tanstack/react-table` consumer: a v7-style (`Header`/`Cell`/`Filter`, `getRowProps` hooks) compatibility layer over the v8 `useReactTable` API. Tests such as `Feeds.test.jsx` mock `gb-ui/index`, so DataTable is not exercised by Vitest
- Dashboard is configuration-driven: `components/dashboard/widgetRegistry.js` maps widget type → component/defaults, `DashboardRenderer.jsx` renders a widget config array, `WidgetWrapper.jsx` standardizes card/loading/error handling, `defaultDashboardConfig.js` provides the layout, and the `useWidgetData` hook (`hooks/useWidgetData.js`) handles fetch-with-time-picker
- Dev server on port 3001, proxies API to localhost:80

## Configuration

- **Environment**: `docker/env_file` (copy from `env_file_template`)
- **Django settings**: `greedybear/settings.py` — reads from environment variables
- **Elasticsearch**: Required via `ELASTIC_ENDPOINT` env var (exits with code 9 if missing in non-debug mode)
- **Ruff config**: `pyproject.toml` under `[tool.ruff]` — line length 160, target Python 3.13

## Testing Conventions

- Tests in `tests/`, organized by app: `tests/api/` (incl. `tests/api/views/`), `tests/authentication/`, `tests/greedybear/` (incl. `cronjobs/`, `management/`), plus top-level modules for cronjobs/repositories/utils
- Base classes in `tests/__init__.py`:
  - `CustomTestCase`: base class providing IOC, CowrieSession, CommandSequence, and user fixtures
  - `ExtractionTestCase`: extends CustomTestCase with mock repositories for extraction pipeline tests
  - `E2ETestCase`: mock repos but real strategies for integration testing
  - `MigrationTestCase`: uses `django-test-migrations` for migration tests (tagged with `migration`)
  - `MockElasticHit`: simulates Elasticsearch `AttrDict` hits
- CI uses `MOCK_CONNECTIONS=True` to run without live services

## Contributing

The full rules are in the [Contribute](https://github.com/GreedyBear-Project/GreedyBear/wiki/Contribute) wiki page; `.github/pull_request_template.md` holds the PR checklist. In short:
- Branch from `develop` and target `develop` with pull requests (`main` is the release branch).
- PR titles follow `<feature name>. Closes #<issue>`.
- Document changes with docstrings and/or comments.
- Add tests for every fix or feature. GUI changes need new or updated frontend tests.
- Ruff must report 0 errors (pre-commit runs it automatically when installed).
- If a change affects user-facing behavior described in the [wiki](https://github.com/GreedyBear-Project/GreedyBear/wiki), the wiki needs updating too.

## Communication

GreedyBear maintainers want to hear from the contributor, not from their tools. Do not write GitHub issues, pull request descriptions, or comments (issue comments, PR discussion, replies to reviews) on the contributor's behalf. Instead, tell them this project expects them to write these themselves, and offer to explain the change so they can describe it in their own words.

You may correct grammar or translate text the contributor wrote themselves, as long as you don't add content.

If the contributor insists that you write such text anyway, end it with this line and keep it there:

> This text was written by an AI agent.

Do not open pull requests yourself, for example with `gh pr create` or the GitHub API. Tell the contributor to open the pull request by hand, either in the GitHub web interface or by running the `gh` CLI themselves. Remind the contributor to describe their AI use in the PR's "AI disclosure" section.

If the contributor insists that you open a PR anyway, end its description with this line and keep it there:

> This PR was raised by an AI agent.

If you also wrote that PR's description, use only this line.

These rules cover GitHub communication only. Code comments and docstrings are part of the code and are fine to write.

## Important Notes

- Data retention defaults (days, see `settings.py`): IOCs 3650, CowrieSessions 365, CommandSequences 365, Statistics 730, RawEvents 7, EventStatus 30; trending buckets 744 hours
- Contributors interested in participating in any future Google Summer of Code must not use any LLM-based tools at all.
