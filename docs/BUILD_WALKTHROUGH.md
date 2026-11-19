# CTI-Pulse: How the Application Was Built

## What this guide covers

This guide explains the implementation in the repository: how the project was planned, what each module does, how data moves through it, which tools are involved, and how to run and explain it. It is written to help a new developer understand and present the application, not just launch it.

The app is an educational MVP. It demonstrates public-source collection, data normalization, SQLite persistence, explainable prioritization, an HTTP API, an analyst dashboard, and PDF reporting. It does not execute exploit code or inspect an organization's systems.

## 1. Product and problem

Security teams see vulnerability facts in several independent sources. CVSS tells us about technical severity, EPSS estimates exploitation likelihood, CISA's Known Exploited Vulnerabilities catalog records known exploitation, and public GitHub repositories may contain proof-of-concept research. Each source answers a different question.

CTI-Pulse puts these signals next to one another so an analyst can make a better triage decision. It does not claim that a CVE is exploitable in a particular environment: the MVP has no asset inventory, software inventory, network exposure, or compensating-control data.

The working loop is:

1. Collect and normalize public intelligence.
2. Correlate source signals using the CVE identifier.
3. Store the results and evidence in SQLite.
4. Compute and explain a risk-priority heuristic.
5. Present the record in a web dashboard or API.
6. Produce a portable PDF summary.

[FIGURE: architecture]

## 2. Scope and implementation choices

The design favors a small number of concepts that can be inspected and defended in an interview:

| Need | Choice | Why it fits this MVP |
|---|---|---|
| Collection and business logic | Python | Readable, widely used, and has HTTP and testing libraries |
| External HTTP | Requests | Makes straightforward GET requests and exposes status handling |
| Local knowledge base | SQLite | No database server to install; SQL and constraints remain visible |
| Web/API layer | FastAPI | Python endpoints with automatic OpenAPI/Swagger documentation |
| HTML rendering | Jinja2 | Server-rendered templates keep the front end small |
| PDF export | ReportLab | Generates a PDF from stored records |
| Verification | Pytest | Runs small deterministic checks without depending on live feeds |
| Source control | Git and GitHub | Records changes and makes the project publishable |

This is a single-process learning application. There is no message queue, frontend build system, cloud deployment, or automatic scheduler. Those omissions reduce setup and make the core data flow easier to explain. A scheduled job can be added later with Windows Task Scheduler or cron.

## 3. Architecture and data path

Four public sources feed a single collection pipeline. The pipeline combines the resulting evidence by CVE ID, writes it to SQLite, and lets the interface query it.

[FIGURE: architecture]

### A single CVE collection, step by step

`app.pipeline.collect()` is the orchestration function:

1. It initializes the schema, chooses the requested CVE IDs (or its small default list), fetches the KEV catalog and requests EPSS values for the batch.
2. For each CVE it asks NVD for vulnerability details.
3. It optionally asks GitHub repository search for public references.
4. It obtains any known KEV due/addition dates and the EPSS estimate.
5. It calls the scoring function with the four signals.
6. It inserts or updates the CVE row and refreshes the current PoC and curated mapping rows. It appends an EPSS observation.
7. It records a successful pipeline run and returns the collected/requested counts.

This is a synchronous, sequential pipeline. That makes the execution order understandable, but it is slower than a concurrent collector and depends on external service availability.

## 4. Code map

### `app/config.py` — application paths

Defines the project root, local data and reports folders, and the SQLite database path. `CTI_PULSE_DB` can override the database location, which is useful in tests or when running multiple local copies.

### `app/collectors.py` — public feed clients

Each function is a small adapter around a source:

- `fetch_kev()` downloads CISA's JSON catalog and returns a dictionary keyed by CVE ID. This makes the membership lookup quick and direct.
- `fetch_epss(cve_ids)` sends a comma-separated CVE batch to FIRST's EPSS API and converts probability and percentile values to numbers.
- `fetch_nvd(cve_id)` makes an NVD CVE API request, selects an English description, and extracts a CVSS base score and vector. It prefers CVSS 3.1, then 3.0, then v2.
- `find_pocs(cve_id)` searches GitHub repositories and returns repository name, URL, and stars. A `GITHUB_TOKEN` environment variable can be used to authenticate and increase available API quota.
- `utc_now()` returns a timezone-aware timestamp.
- `extract_cve_ids(text)` is a small regular-expression helper for finding identifiers in text.

Requests have a timeout and call `raise_for_status()` so most HTTP failures are surfaced instead of silently treated as valid results. One exception is GitHub HTTP 403, which currently returns an empty list; that can conflate a search rate limit with "no repository found" and should be improved in a production version.

### `app/pipeline.py` — orchestration and correlation

The collectors know how to talk to individual sources. The pipeline knows the order in which to use them and how to combine their results. The shared identifier is `CVE-YYYY-NNNN...`.

The CVE table is upserted with `ON CONFLICT(cve_id) DO UPDATE`. Re-running a collection therefore refreshes the existing vulnerability row instead of creating duplicates. EPSS snapshots are stored separately. PoC and ATT&CK rows are refreshed for the CVE during each run.

Important behavior: NVD requests are made one CVE at a time; KEV is downloaded once per pipeline run; EPSS is requested in a batch; GitHub search is done per CVE unless disabled.

### `app/db.py` — SQLite schema and connections

The schema separates different kinds of data:

- `cves`: one normalized current record per vulnerability.
- `epss_history`: probability/percentile observations over collection time.
- `poc_references`: zero or more public repository links for each CVE.
- `attack_mappings`: zero or more reviewed technique relationships.
- `collection_runs`: status and counts for pipeline executions.
- `alerts`: a table for future alert criteria.

Indexes on priority, score, and KEV status support common filters. `db_cursor()` yields a connection with dictionary-like rows and commits on normal exit. In a larger application, foreign keys, explicit rollback handling, and connection lifecycle management would deserve more attention.

[FIGURE: data model]

### `app/scoring.py` — explainable prioritization

Inputs are bounded before use: CVSS is limited to 0–10 and EPSS to 0–1. KEV and PoC are binary indicators, because this version treats any KEV inclusion as yes/no and any number of discovered PoC references as present/absent for score purposes.

The formula as implemented is:

`score = 100 × (0.25 × CVSS/10 + 0.35 × EPSS + 0.25 × KEV + 0.15 × PoC)`

The code first multiplies the weighted sum by 10, producing a 0–10 scale, then multiplies by 10 for the displayed 0–100 score. `priority_for()` applies the thresholds: 80+ Critical, 60+ High, 40+ Medium, otherwise Low. `explain_risk()` returns the score, classification, and a list of the underlying signal values and weights for the detail view.

[FIGURE: scoring]

Worked example: CVSS 9.8, EPSS 0.90, KEV yes, PoC found:

`100 × (0.25 × 0.98 + 0.35 × 0.90 + 0.25 × 1 + 0.15 × 1) = 96.0`

These are project-defined weights, not an official CVSS, FIRST, CISA, or MITRE score. A PoC indicates public research or availability, not that an attacker used it. EPSS is a probability estimate, not a guarantee.

### `app/mitre.py` — curated behavior relationships

This module contains a short dictionary of reviewed example mappings. Each mapping gives a technique ID, name, tactic, written evidence, and confidence. The pipeline persists them with a source label and `manually_reviewed=1`.

ATT&CK describes adversary tactics and techniques; it is not a vulnerability catalog. A CVE-to-technique relationship is contextual and should not be inferred automatically from the identifier. The curated examples are a starting dataset, not comprehensive threat attribution.

### `app/main.py` — routes, dashboard, and API

FastAPI creates the application and mounts the CSS and Jinja template folders. At startup it initializes the database schema.

| Route | Purpose |
|---|---|
| `GET /` | Dashboard with keyword, priority, and KEV filters |
| `GET /cve/{cve_id}` | Evidence detail, score explanation, PoC links, ATT&CK mappings |
| `GET /api/v1/cves` | Filtered JSON list with a bounded `limit` |
| `GET /api/v1/cves/{cve_id}` | One JSON record plus score explanation and references |
| `POST /api/v1/reports/weekly` | Generate a report and return its download URL |
| `GET /reports` | List locally generated reports |
| `GET /reports/{name}` | Download a generated PDF |
| `GET /docs` | Interactive OpenAPI/Swagger UI generated by FastAPI |

The dashboard builds SQL conditions from fixed SQL fragments and parameter placeholders. User input is passed as query parameters to SQLite rather than concatenated into SQL values. Templates are in `templates/`; the CSS and responsive layout are in `static/styles.css`.

### `app/reports.py` — PDF intelligence summary

The report generator queries SQLite, orders CVEs by risk, creates a summary and evidence table, adds a note describing the scoring method, and writes the file to `reports/`. ReportLab handles page layout and PDF output.

The endpoint and CLI generate a report when asked; automatic weekly scheduling is not included.

### `app/cli.py` and `app/seed.py` — operating the app

`python -m app.cli collect` runs live collection. CVE IDs can be specified, and `--no-github` skips GitHub search. `python -m app.cli report` writes a PDF.

`python -m app.seed` inserts a small demonstration dataset, including example source scores, repository links, and curated mappings. It helps show the dashboard without relying on live Internet requests. Seeded examples are for demonstration and should not be mistaken for a current feed snapshot.

### `templates/`, `static/`, and `docs/`

Jinja templates define the base navigation, ledger, detail page, reports page, and not-found state. Styles provide the desktop two-column workspace and a smaller-screen layout. `README.md` explains quick start, `TECHNICAL_REPORT.md` describes the system design, and `INTERVIEW_GUIDE.md` gives a presentation script and likely questions.

## 5. Database relationships

`cves.cve_id` is the primary key. The remaining evidence tables can contain multiple rows per CVE, so they use the identifier as a relationship key.

[FIGURE: data model]

This model separates the current correlated view from evidence that can repeat or change over time. That is why EPSS is not stored only as one permanent value: its history table can record when estimates were observed.

## 6. User interface and request lifecycle

When a user opens the dashboard, FastAPI reads query parameters, constructs filter conditions, executes a parameterized SQLite query sorted by risk, calculates aggregate counts, then renders `templates/index.html`. Clicking a CVE opens the detail endpoint, which loads the CVE, references, mappings, and EPSS observations and calculates the human-readable score explanation.

The dashboard is server-rendered, so it avoids a separate JavaScript framework and frontend build step. It can be inspected by viewing a template and following the corresponding route.

## 7. Build steps and tools

The actual implementation sequence was:

1. **Turn the project brief into a small MVP.** Identify the source feeds, database, score, dashboard/API, reporting and interview documentation. Record the scope in `PRODUCT.md`.
2. **Inspect the repository.** It was empty except for Git metadata, so the project could be structured around the requested Python stack rather than extending an existing app.
3. **Create the foundation.** Add requirements, ignore rules, package folders, paths, database schema, scoring functions and curated ATT&CK examples.
4. **Build the collection layer.** Implement one adapter per public source and then orchestrate them with a shared CVE key and SQLite upserts.
5. **Build consumption surfaces.** Add FastAPI routes, HTML templates, responsive CSS, JSON responses and PDF generation.
6. **Add presentation and learning material.** Create seed records, README, technical report and interview Q&A.
7. **Verify.** Run Pytest, seed the database, start Uvicorn, check the dashboard/detail/report routes with HTTP requests, and generate a sample PDF.
8. **Publish.** Use Git to stage/commit the project, push the branch, and merge it into the repository's `main` branch through GitHub.

### Tools: what they do

- **Python 3.14** runs the application and its command-line tools.
- **pip and `requirements.txt`** install the project libraries.
- **SQLite** is the local data store; no database server is required.
- **Uvicorn** is the ASGI development server for FastAPI.
- **Pytest** runs repeatable unit tests.
- **Git and GitHub** provide version control and repository hosting.
- **VS Code** is a convenient editor and terminal for cloning, reading, changing, and running the repository. It is not required by the app.
- **ReportLab** is both the PDF library used by the app's weekly report and the library used to generate this build guide.

### Reproduce locally on Windows

From the repository folder in the VS Code PowerShell terminal:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python -m app.seed
python -m uvicorn app.main:app --reload
```

Open `http://127.0.0.1:8000` for the dashboard and `http://127.0.0.1:8000/docs` for the interactive API docs. In a second terminal, `python -m pytest -q` runs tests. `python -m app.cli report` creates the weekly-style PDF.

Optional live API credentials are environment variables, not source files:

```powershell
$env:NVD_API_KEY = "your-key"
$env:GITHUB_TOKEN = "your-token"
```

Do not commit real credentials. Live collectors need Internet access and source APIs may enforce rate limits.

## 8. Testing and verification

The current tests verify:

- The maximum and zero cases of the scoring formula.
- A worked weighted-score example.
- Exact priority boundaries.
- That the SQLite schema contains the expected core tables.

Tests avoid calling public APIs, making the core behavior reproducible even when the network is unavailable. A more complete test suite should mock collector responses, test pipeline upserts, validate API not-found behavior, test PDF generation, and cover error/rate-limit cases.

For the implementation verification, the app was seeded and started locally. The dashboard, CVE detail, and report list routes returned HTTP 200. The weekly PDF generator produced a file. These checks verify local operation, not the freshness or correctness of every external feed.

## 9. What is implemented and what remains

Implemented: public source collection functions; CVE normalization and storage; EPSS history; PoC links; curated ATT&CK examples; risk score and explanation; dashboard/search/filter; JSON API; CLI; report generation; demo seed; unit tests and docs.

Not implemented yet: create/manage/deliver personalized alerts (the `alerts` table is only a schema foundation); automatic recurring scheduling; email/Slack notification; full ATT&CK STIX ingestion; asset inventory and environment-specific risk; comprehensive source provenance; production authentication, deployment, monitoring, and migrations.

It is important to state this boundary accurately in a presentation. The brief described these as intended capabilities, but the current repository implements the smaller MVP described above.

## 10. Known limitations and safe interpretation

- EPSS can change and should be refreshed; a missing EPSS record is currently represented as zero by the pipeline.
- GitHub search is noisy and subject to rate limits. A rate-limit response currently looks like no PoC results.
- The default collection is a short CVE list, not a continuously updated full NVD ingestion job.
- The score lacks local asset exposure and business impact.
- Curated ATT&CK mappings cover only a few example CVEs.
- The report is generated on demand; no scheduler sends it weekly.
- HTTP endpoints are intended for local demonstration and do not implement user authentication.
- A discovered PoC link is only a reference; CTI-Pulse never downloads or executes exploit code.

## 11. How to present the project

Start with the problem: vulnerability severity alone is not enough for practical prioritization. Walk through one CVE and point out which source contributes each signal. Explain the score formula, identify it as a heuristic, then show how the explanation keeps the result auditable. Demonstrate the CVE detail page, Swagger endpoint, and PDF report.

Close with the limitations: no asset inventory, no automatic alerts or scheduler, and no claim that a public PoC proves active exploitation. Name one next improvement—asset context is especially valuable because it connects public threat information to the systems the organization actually owns.
