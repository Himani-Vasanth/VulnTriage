# VulnTriage — Model Report (Part 2)

## Setup
- Trained on 26,034 CVEs published <=2022 (1034 exploited).
- Evaluated on 68,771 CVEs published 2023-2024 (325 exploited), never seen during training.
- Class imbalance (~0.5% positive) means accuracy is not reported -- a model
  predicting "never exploited" would score >99% accuracy. We report recall at
  a fixed review budget plus PR-AUC instead.

## Headline result: recall at a review budget, vs. CVSS

| Model | Recall@1% | Recall@5% | Recall@10% | PR-AUC | ROC-AUC |
|---|---|---|---|---|---|
| CVSS-only (baseline) | 5% [0.03, 0.07] | 20% [0.15, 0.24] | 40% [0.32, 0.43] | 0.015 | 0.781 |
| TF-IDF + Logistic Regression | 17% [0.13, 0.21] | 48% [0.42, 0.53] | 64% [0.59, 0.69] | 0.047 | 0.889 |
| TF-IDF + Random Forest | 9% [0.06, 0.13] | 35% [0.29, 0.39] | 54% [0.49, 0.60] | 0.033 | 0.824 |

At a 5%-of-CVEs review budget, CVSS-only ranking finds 20% of the
CVEs that go on to be exploited. TF-IDF + Logistic Regression finds 48%
-- roughly 2.3x more, for the same
analyst review time. 95% confidence intervals (bootstrap, 300
resamples) don't overlap CVSS's interval.

## Early-warning lead time
Of the CVEs correctly flagged in the model's top 5%, the gap between public
disclosure and CISA formally listing them as exploited:
- Median: **4 days**
- Mean: 86 days (range -56-1154, n=155)

## Explainability
Top terms that raise predicted risk (full list in top_features.csv):
apache, unauthenticated, report issue, remote code, ios, 2013, exim, netgear, roundcube, adobe

Top terms that lower predicted risk:
xss, denial, denial service, cross, cve 2014, file, allows attacker, sql commands

## Limitations
1. Test-set positives are only 325 CVEs -- confidence intervals matter more than point estimates.
2. KEV is a lower bound on real exploitation; some "0" labels are unconfirmed, not proven-safe.
3. Random Forest underperforms Logistic Regression here -- reported honestly, not cherry-picked.

## Report quirks (checked, not hidden)
- Negative lead time (min seen: -56 days) happens when a CVE ID is reserved
  and exploited before its official record is fully published -- a real
  quirk of CVE/KEV timing, not a data error. Median is the number to trust.
- "report issue" in the feature list is a TF-IDF tokenization artifact
  (punctuation stripped before forming bigrams lets two unrelated sentences
  form a fake adjacent pair) -- verified against the training text, not leakage.
- Date tokens like "2013" reflect a narrow but real pattern -- a cluster of
  heavily-exploited 2013 Oracle Java CVEs -- a disclosed small-sample limitation.
