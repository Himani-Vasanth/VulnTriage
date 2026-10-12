---
title: VulnTriage
emoji: 🛡️
colorFrom: blue
colorTo: green
sdk: docker
app_port: 7860
pinned: false
---

# VulnTriage

Machine learning model that predicts which software vulnerabilities (CVEs) are
likely to be actively exploited, trained on the public CVE corpus and labeled
with CISA's Known Exploited Vulnerabilities (KEV) catalog. Benchmarked against
CVSS-only prioritization with a time-based train/test split (no future data
leakage).

- Single CVE scoring with explainability (which words drove the risk score)
- Batch backlog triage: rank a list of vulnerabilities by exploit likelihood
