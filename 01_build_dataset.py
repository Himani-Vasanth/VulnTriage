"""
VulnTriage - Part 1: Dataset Build

Builds a leakage-free, labeled dataset for predicting whether a CVE will be
added to CISA's Known Exploited Vulnerabilities (KEV) catalog.

Inputs:
  raw/cvelist.zip   -> CVEProject/cvelistV5 (full CVE record corpus)
  raw/kev.json      -> CISA KEV catalog

Outputs:
  vulntriage_train.csv, vulntriage_test.csv, dataset_report.md
"""
import zipfile, json, re, os
from pathlib import Path
import pandas as pd
import numpy as np

RAW_ZIP = str(Path(__file__).resolve().parent / "raw" / "cvelist.zip")
KEV_JSON = str(Path(__file__).resolve().parent / "raw" / "kev.json")
OUT_DIR = str(Path(__file__).resolve().parent)

# The full CVE corpus is ~380,000 rows. Training on that directly is slow and
# memory-heavy on a laptop. Fix: keep every exploited CVE (they're rare and
# valuable), randomly downsample the non-exploited majority -- but only in
# the training split (see time_split below for why the test set stays full).
NEGATIVE_SAMPLE_SIZE = 25_000
RANDOM_SEED = 42


def parse_cves(zip_path):
    """Parse every published CVE record out of the CVEProject/cvelistV5 zip."""
    z = zipfile.ZipFile(zip_path)
    rows = []
    for name in z.namelist():
        if not name.endswith(".json") or "/cves/" not in name or "CVE-" not in name:
            continue
        try:
            d = json.loads(z.read(name))
        except Exception:
            continue
        meta = d.get("cveMetadata", {})
        if meta.get("state") != "PUBLISHED":
            continue
        cna = d.get("containers", {}).get("cna", {})

        desc = " ".join(
            x.get("value", "") for x in cna.get("descriptions", [])
            if x.get("lang", "").startswith("en")
        )

        cvss, vector = None, None
        def grab(metrics):
            nonlocal cvss, vector
            for m in metrics or []:
                for k, v in m.items():
                    if k.startswith("cvss") and isinstance(v, dict) and "baseScore" in v:
                        cvss, vector = v["baseScore"], v.get("vectorString")
                        return
        grab(cna.get("metrics"))
        if cvss is None:
            for adp in d.get("containers", {}).get("adp", []):
                grab(adp.get("metrics"))
                if cvss is not None:
                    break

        cwe = None
        for p in cna.get("problemTypes", []):
            for dd in p.get("descriptions", []):
                if dd.get("cweId"):
                    cwe = dd["cweId"]
                    break
            if cwe:
                break

        affected = cna.get("affected", [{}])
        vendor = affected[0].get("vendor") if affected else None
        product = affected[0].get("product") if affected else None

        rows.append(dict(
            cve=meta["cveId"], published=meta.get("datePublished", "")[:10],
            desc=desc, cvss=cvss, vector=vector, cwe=cwe,
            vendor=vendor, product=product,
        ))
    return pd.DataFrame(rows)


def label_with_kev(df, kev_path):
    """Label with CISA KEV -- ground truth for 'was actually exploited'."""
    kev = json.load(open(kev_path))["vulnerabilities"]
    kev_df = pd.DataFrame(kev)[["cveID", "dateAdded"]]
    df = df.merge(kev_df, left_on="cve", right_on="cveID", how="left")
    df["exploited"] = df["cveID"].notna().astype(int)
    return df.drop(columns=["cveID"])


# CVE descriptions sometimes say a vulnerability "has been exploited in the
# wild" -- but that sentence gets added to the record *after* CISA lists it.
# Left in, a model could cheat by reading the label off the description
# instead of learning real risk signals. These patterns strip that out.
LEAKY_PATTERNS = [
    r"\bexploited in the wild\b", r"\battacks? in the wild\b",
    r"\bactively exploited\b", r"\bknown to be exploited\b",
    r"\badded to (the |)(cisa |)kev\b", r"\bcisa has added\b",
    r"\bexploitation.{0,15}has been (observed|reported|detected)\b",
    r"\bthreat actors? (are|have been) exploiting\b",
    r"\bin-the-wild exploitation\b", r"\bwe are aware of\b",
    r"\b(is|are|apple is|google is|microsoft is) aware of\b",
    r"\baware of (a report|reports|targeted attacks)\b",
    r"\bmay have been (actively |)exploited\b",
    r"\bthis (flaw|vulnerability|issue) (is|was|has been) (being |)exploited\b",
    r"\bexploited (against|prior to)\b", r"\b0-?day\b.{0,20}\bexploited\b",
]
LEAK_RE = re.compile("|".join(LEAKY_PATTERNS), flags=re.IGNORECASE)


def scrub_leakage(df):
    hit = df["desc"].str.contains(LEAK_RE, na=False, regex=True)
    df["had_leakage_phrase"] = hit.astype(int)
    df["desc_clean"] = df["desc"].str.replace(LEAK_RE, " ", regex=True)
    df["desc_clean"] = df["desc_clean"].str.replace(r"\s+", " ", regex=True).str.strip()
    return df


def time_split(df, train_end=2022, test_start=2023, test_end=2024):
    """
    Train on the past, test on the future. This is what makes the evaluation
    honest -- no CVE from the test years is allowed to influence training,
    the same situation a security team faces in practice.
    """
    df = df.copy()
    df["year"] = pd.to_numeric(df["published"].str[:4], errors="coerce")
    df = df[df["desc_clean"].str.len() > 20]
    train = df[df["year"] <= train_end]
    test = df[(df["year"] >= test_start) & (df["year"] <= test_end)]
    return train, test


def downsample_negatives(df, n_negatives=NEGATIVE_SAMPLE_SIZE, seed=RANDOM_SEED):
    """Keep all exploited CVEs; randomly sample non-exploited ones down to a fixed size."""
    pos = df[df["exploited"] == 1]
    neg_pool = df[df["exploited"] == 0]
    neg = neg_pool.sample(n=min(n_negatives, len(neg_pool)), random_state=seed)
    return pd.concat([pos, neg]).sort_index()


def main():
    print("Parsing CVE corpus (this takes ~1-2 min)...")
    df = parse_cves(RAW_ZIP)
    print(f"  Parsed {len(df):,} published CVE records")

    print("Labeling with CISA KEV catalog...")
    df = label_with_kev(df, KEV_JSON)
    true_base_rate = df["exploited"].mean() * 100
    print(f"  {df['exploited'].sum():,} of {len(df):,} CVEs are in KEV ({true_base_rate:.2f}% true base rate)")

    print("Scrubbing label-leakage phrases from descriptions...")
    df = scrub_leakage(df)
    leaky = df["had_leakage_phrase"].sum()
    leaky_exploited = df.loc[df["had_leakage_phrase"] == 1, "exploited"].sum()
    print(f"  {leaky:,} descriptions contained a leakage phrase ({leaky_exploited:,} of those are actually exploited)")

    full_df_for_report = df.copy()  # untrimmed copy, used below for the real yearly trend

    print("Splitting by publication year (train <=2022, test 2023-2024)...")
    # Split BEFORE any downsampling. Recall-at-a-review-budget only means
    # something if the budget is computed against a realistic CVE stream --
    # shrinking the test set would silently deflate that metric. Scoring the
    # test set is cheap regardless of size; it's fitting the model that was
    # slow, so only training needs trimming.
    train_full, test = time_split(df)
    train = downsample_negatives(train_full)
    trimmed_base_rate = train["exploited"].mean() * 100
    print(f"  Downsampled TRAINING negatives only: {len(train_full):,} -> {len(train):,} rows "
          f"(train base rate now {trimmed_base_rate:.2f}%, vs {true_base_rate:.2f}% true rate)")
    print(f"  Train (trimmed): {len(train):,} rows, {train['exploited'].sum():,} exploited")
    print(f"  Test  (full, untouched): {len(test):,} rows, {test['exploited'].sum():,} exploited")

    keep_cols = ["cve", "published", "year", "desc_clean", "cvss", "vector",
                 "cwe", "vendor", "product", "had_leakage_phrase", "exploited"]
    train = train[keep_cols].rename(columns={"desc_clean": "description"})
    test = test[keep_cols].rename(columns={"desc_clean": "description"})

    os.makedirs(OUT_DIR, exist_ok=True)
    train.to_csv(f"{OUT_DIR}/vulntriage_train.csv", index=False)
    test.to_csv(f"{OUT_DIR}/vulntriage_test.csv", index=False)

    # --- dataset report ---
    full_df_for_report["year"] = pd.to_numeric(full_df_for_report["published"].str[:4], errors="coerce")
    yr_table = full_df_for_report.dropna(subset=["year"]).groupby("year")["exploited"].agg(cves="count", exploited="sum")
    yr_table["rate_%"] = (yr_table["exploited"] / yr_table["cves"] * 100).round(3)

    report = f"""# VulnTriage — Dataset Report (Part 1)

## Sources
- CVE records: CVEProject/cvelistV5, GitHub -- `https://codeload.github.com/CVEProject/cvelistV5/zip/refs/heads/main`
- Exploited labels: CISA KEV catalog -- `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`
- NVD's legacy JSON data feeds were deprecated 2023-12-15; the two sources above are the current official bulk sources.

## Totals (before trimming)
- Published CVE records parsed: **{len(full_df_for_report):,}**
- Confirmed exploited (in KEV): **{int(full_df_for_report['exploited'].sum()):,}** ({true_base_rate:.2f}% true base rate)
- Heavily imbalanced: fewer than 1 in 100 CVEs are ever confirmed exploited. Accuracy is not a useful metric here -- see model_report.md for recall-at-budget and PR-AUC instead.

## Dataset trimming (training set only)
The full corpus is heavy to fit a model on directly. Only the training split is
trimmed -- the test set stays at full, real size, since recall-at-budget only
means something against a realistic CVE stream.

Within the training years (<=2022), every exploited CVE is kept
({int(train['exploited'].sum()):,} of them) and the non-exploited majority is
randomly downsampled to {NEGATIVE_SAMPLE_SIZE:,} rows (seed={RANDOM_SEED}).

This raises the *training* set's positive rate to **{trimmed_base_rate:.2f}%**,
well above the **{true_base_rate:.2f}%** true rate. The *test* set's rate stays
realistic ({test['exploited'].mean()*100:.3f}%).

- Training rows before trimming: {len(train_full):,}
- Training rows after trimming: {len(train):,} ({(1 - len(train)/len(train_full))*100:.0f}% reduction)
- Test rows: {len(test):,} (unchanged)

## Label leakage found and removed
{leaky:,} CVE descriptions ({leaky/len(df)*100:.2f}%) contained phrases like
"exploited in the wild", added to the record *after* exploitation was confirmed
({leaky_exploited:,} of those are indeed labeled exploited). Left untouched, a
model could reach high accuracy by detecting these phrases instead of learning
real risk signals. All matching phrases were stripped before modeling;
`had_leakage_phrase` is kept as an audit column, not a model input.

## Train / test split (time-based, not random)
| Split | Years | Rows | Exploited | Rate |
|---|---|---|---|---|
| Train | <=2022 | {len(train):,} | {int(train['exploited'].sum()):,} | {train['exploited'].mean()*100:.3f}% |
| Test  | 2023-2024 | {len(test):,} | {int(test['exploited'].sum()):,} | {test['exploited'].mean()*100:.3f}% |

## Yearly trend (all years, for reference)
| Year | CVEs | Exploited | Rate % |
|---|---|---|---|
"""
    for y, row in yr_table.iterrows():
        if pd.isna(y) or y < 2010 or y > 2026:
            continue
        report += f"| {int(y)} | {int(row['cves']):,} | {int(row['exploited']):,} | {row['rate_%']} |\n"

    report += f"""
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
"""
    with open(f"{OUT_DIR}/dataset_report.md", "w") as f:
        f.write(report)

    print("\nDone. Files written to", OUT_DIR)


if __name__ == "__main__":
    main()
