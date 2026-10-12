# VulnTriage — Dataset Report (Part 1)

## Sources
- CVE records: CVEProject/cvelistV5, GitHub -- `https://codeload.github.com/CVEProject/cvelistV5/zip/refs/heads/main`
- Exploited labels: CISA KEV catalog -- `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`
- NVD's legacy JSON data feeds were deprecated 2023-12-15; the two sources above are the current official bulk sources.

## Totals (before trimming)
- Published CVE records parsed: **380,164**
- Confirmed exploited (in KEV): **1,728** (0.45% true base rate)
- Heavily imbalanced: fewer than 1 in 100 CVEs are ever confirmed exploited. Accuracy is not a useful metric here -- see model_report.md for recall-at-budget and PR-AUC instead.

## Dataset trimming (training set only)
The full corpus is heavy to fit a model on directly. Only the training split is
trimmed -- the test set stays at full, real size, since recall-at-budget only
means something against a realistic CVE stream.

Within the training years (<=2022), every exploited CVE is kept
(1,034 of them) and the non-exploited majority is
randomly downsampled to 25,000 rows (seed=42).

This raises the *training* set's positive rate to **3.97%**,
well above the **0.45%** true rate. The *test* set's rate stays
realistic (0.473%).

- Training rows before trimming: 191,956
- Training rows after trimming: 26,034 (86% reduction)
- Test rows: 68,771 (unchanged)

## Label leakage found and removed
716 CVE descriptions (0.19%) contained phrases like
"exploited in the wild", added to the record *after* exploitation was confirmed
(187 of those are indeed labeled exploited). Left untouched, a
model could reach high accuracy by detecting these phrases instead of learning
real risk signals. All matching phrases were stripped before modeling;
`had_leakage_phrase` is kept as an audit column, not a model input.

## Train / test split (time-based, not random)
| Split | Years | Rows | Exploited | Rate |
|---|---|---|---|---|
| Train | <=2022 | 26,034 | 1,034 | 3.972% |
| Test  | 2023-2024 | 68,771 | 325 | 0.473% |

## Yearly trend (all years, for reference)
| Year | CVEs | Exploited | Rate % |
|---|---|---|---|
| 2010 | 4,639 | 23 | 0.496 |
| 2011 | 4,150 | 9 | 0.217 |
| 2012 | 5,288 | 22 | 0.416 |
| 2013 | 5,187 | 35 | 0.675 |
| 2014 | 7,928 | 34 | 0.429 |
| 2015 | 6,494 | 45 | 0.693 |
| 2016 | 6,457 | 53 | 0.821 |
| 2017 | 14,642 | 89 | 0.608 |
| 2018 | 16,510 | 76 | 0.46 |
| 2019 | 17,308 | 129 | 0.745 |
| 2020 | 18,363 | 146 | 0.795 |
| 2021 | 20,177 | 214 | 1.061 |
| 2022 | 25,000 | 131 | 0.524 |
| 2023 | 28,847 | 165 | 0.572 |
| 2024 | 39,924 | 160 | 0.401 |
| 2025 | 48,153 | 197 | 0.409 |
| 2026 | 71,283 | 172 | 0.241 |

## Columns
| Column | Meaning |
|---|---|
| cve | CVE identifier |
| published | Disclosure date |
| year | Disclosure year (used for the split) |
| description | Cleaned text (leakage phrases removed) -- main model input |
| cvss | CVSS base score if present |
| vector | CVSS vector string |
| cwe | MITRE CWE weakness type |
| vendor / product | Affected vendor/product |
| had_leakage_phrase | Audit flag, not a model input |
| exploited | Label: 1 if in CISA KEV, else 0 |

## Known limitations
1. KEV records only confirmed, publicly known exploitation -- some "0" labels are unconfirmed, not proven-safe.
2. `dateAdded` in KEV is when CISA listed it, which can lag real-world exploitation.
3. CVSS/CWE are sometimes missing on older or very new records; handled as a "missing" indicator, not dropped.
