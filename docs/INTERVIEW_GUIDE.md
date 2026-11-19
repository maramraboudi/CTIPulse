# CTI-Pulse Interview Guide

## Opening in 30 seconds

"CTI-Pulse is a small threat-intelligence platform that collects CVE data from NVD, exploitation status from CISA KEV, probability from EPSS, and public PoC evidence from GitHub. It normalizes these sources in SQLite, produces an explainable risk score, stores curated MITRE ATT&CK mappings, and exposes an analyst dashboard and API."

## Frequently asked questions

### What is cyber threat intelligence?

Threat intelligence is evidence-based information about threats that an organization can use to make decisions. It is not just a list of vulnerabilities: useful intelligence adds context, relevance, and confidence.

### What is a CVE?

A CVE is a public identifier for a known vulnerability. It provides a stable name such as `CVE-2021-44228`; it does not itself prove exploitation.

### What is CVSS?

CVSS scores vulnerability characteristics and severity from 0 to 10. It does not measure EPSS exploitation probability or whether an organization is exposed.

### What is EPSS?

EPSS predicts the probability that a vulnerability will be exploited over a 30-day period. An EPSS score of 0.90 is an estimated 90% likelihood according to the model; it is not a 90% chance for one specific system.

### What is CISA KEV?

CISA KEV is a catalog of vulnerabilities known to be or have been used in exploitation. Inclusion is strong evidence of real-world relevance, but KEV is not a complete inventory of exploitation.

### What is a PoC?

A proof of concept demonstrates that exploit behavior can be reproduced. It provides technical evidence but does not prove in-the-wild exploitation or that an incident occurred.

### Why use SQLite?

SQLite is serverless, local, SQL-based, and appropriate for a single-user MVP. It avoids infrastructure complexity while preserving a transparent schema.

### Why use FastAPI?

FastAPI provides typed Python endpoints, automatic interactive Swagger documentation, and strong performance for a small API. It also lets the dashboard and JSON API share the same application.

### How does normalization work?

Each external source uses its own JSON format. Collectors extract only common fields and store them under the CVE identifier. Source-specific values remain in dedicated fields or tables.

### How does duplicate detection work?

SQLite uses `cve_id` as the primary key. The pipeline uses upserts for the CVE record and insert-or-replace behavior for current PoC and mapping evidence.

### Explain the risk formula.

The formula combines 25% CVSS, 35% EPSS, 25% CISA KEV, and 15% public PoC evidence. It is multiplied by 100 and classified into Critical, High, Medium, or Low.

### Why is EPSS weighted highest?

EPSS is the only continuous exploitation-likelihood signal in the MVP. The weights are a documented heuristic, not a claim that EPSS should always outweigh severity.

### What are its limitations?

It lacks asset inventory, internet exposure, version deployment, compensating controls, and observed incident telemetry. A PoC is not exploitation, EPSS is probabilistic, and a KEV omission is not proof of safety.

### How is MITRE ATT&CK used?

The project stores manually reviewed mappings from selected CVEs to ATT&CK techniques. The mapping includes evidence and confidence so the relationship can be challenged. ATT&CK describes behavior; it does not establish attacker attribution.

### What is a tactic and technique?

A tactic is an adversary goal, such as Initial Access. A technique describes how an adversary may achieve it, such as Exploit Public-Facing Application (`T1190`).

### How would you improve it?

I would add asset inventory and exposure context, record sources and provenance, add alerts, schedule collection, cache API calls, build tests with fixtures, and eventually introduce PostgreSQL or a queue only when scale or concurrency requires it.

## Practical scenarios

### Medium CVSS, high EPSS, in KEV

Explain that severity alone can be moderate, but confirmed exploitation and high probability justify urgent prioritization.

### High CVSS, no EPSS, no KEV

Explain that the flaw is severe, but the lack of exploitation evidence may lower the priority relative to its technical severity.

### PoC only

Explain that the public PoC matters because exploit research is available, but it does not prove that exploitation is occurring.

### Unmapped CVE

Explain that the absence of a mapping means CTI-Pulse has no analyst-reviewed relationship; it does not prove there is no ATT&CK relevance.

## 3-day study plan

**Day 1:** Understand API JSON, SQLite schema, CVE/CVSS/EPSS/KEV/PoC concepts, and run live collection.

**Day 2:** Trace one CVE through normalization, scoring, ATT&CK mapping, API, and dashboard.

**Day 3:** Practice the 30-second pitch, 10 technical questions, 3 scenarios, limitations, and one realistic improvement.
