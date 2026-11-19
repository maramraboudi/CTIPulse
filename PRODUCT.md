# Product

<!-- impeccable:product-schema 1 -->

## Platform

web

## Users

Cybersecurity students and junior threat intelligence or SOC analysts who need to understand, demonstrate, and investigate vulnerability intelligence during training or interviews.

## Product Purpose

CTI-Pulse collects public vulnerability and exploitation signals, correlates them into a common SQLite knowledge base, explains a transparent risk score, and helps analysts search, investigate, alert on, and report relevant threats.

## Positioning

An intentionally small, explainable CTI pipeline: it combines CVSS, EPSS, CISA KEV, public PoC evidence, and curated MITRE ATT&CK mappings without hiding the source data or presenting a black-box model.

## Operating Context

The application runs locally on a laptop or in a simple Python environment. Analysts use a FastAPI dashboard and REST API; collection can be run manually or scheduled by cron. It is designed for interview demonstrations and small-team learning rather than enterprise-scale ingestion.

## Capabilities and Constraints

- Collect NVD, CISA KEV, FIRST EPSS, and public GitHub PoC references.
- Store normalized records in SQLite.
- Calculate an explainable 0-100 risk score.
- Search CVEs and filter by priority, KEV status, and PoC evidence.
- Map selected vulnerabilities to analyst-reviewed MITRE ATT&CK techniques.
- Generate alerts and weekly PDF or HTML reports.
- Preserved source evidence and timestamps must remain visible.
- This is not an exploitation tool and does not claim that PoC evidence proves real-world compromise.
- GitHub and NVD rate limits apply to live collection.

## Brand Commitments

The repository and interface use the CTI-Pulse name. The tone is clear, credible, non-alarmist, and educational.

## Evidence on Hand

The attached three-day implementation brief defines the MVP, scoring formula, source responsibilities, and interview learning objectives. No existing UI or design system is present.

## Product Principles

- Preserve source facts; a score is an analysis aid, not ground truth.
- Make decisions explainable from visible signals.
- Prefer small, understandable components over enterprise infrastructure.
- Separate automatic discovery from analyst-reviewed ATT&CK mapping.
- Keep the system useful for learning and interview defense.

## Accessibility & Inclusion

Use semantic HTML, visible keyboard focus, readable contrast, labeled controls, and responsive layouts. No product-specific accessibility standard is established beyond a practical WCAG-aligned implementation.
