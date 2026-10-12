"""
VulnTriage - Live Demo: fetch a real CVE from the NVD API, then score it

Makes one call to the NVD API 2.0 (public, no key required), pulls the
official description and CVSS score for a CVE, and scores it with the
trained model.

Usage:
    python 06_live_demo.py CVE-2024-3400
    python 06_live_demo.py                (prompts for a CVE ID)
"""
import sys
import json
import urllib.request
from vulntriage_lib import score_description

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def fetch_cve(cve_id):
    url = f"{NVD_API}?cveId={cve_id}"
    req = urllib.request.Request(url, headers={"User-Agent": "VulnTriage-demo/1.0"})
    with urllib.request.urlopen(req, timeout=15) as resp:
        data = json.load(resp)

    vulns = data.get("vulnerabilities", [])
    if not vulns:
        raise ValueError(f"NVD has no record for '{cve_id}'.")

    cve = vulns[0]["cve"]
    description = next(
        (d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"), ""
    )

    cvss = None
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if metrics.get(key):
            cvss = metrics[key][0]["cvssData"]["baseScore"]
            break

    return {"id": cve["id"], "published": cve.get("published", "")[:10],
            "description": description, "cvss": cvss}


def main():
    if len(sys.argv) > 1:
        cve_id = sys.argv[1].strip()
    else:
        cve_id = input("Enter a CVE ID (e.g. CVE-2024-3400): ").strip()

    print(f"\nFetching {cve_id} from the NVD API...")
    record = fetch_cve(cve_id)

    print(f"\n--- NVD record: {record['id']} ---")
    print(f"Published: {record['published']}")
    print(f"CVSS:      {record['cvss']}")
    print(f"Description:\n  {record['description']}")

    print(f"\n--- VulnTriage model score ---")
    result = score_description(record["description"])
    print(f"Risk score: {result['score']:.3f}")
    print(f"Tier:       {result['tier']}")
    if result["raising_terms"]:
        print("Raises risk: " + ", ".join(t for t, _ in result["raising_terms"]))
    if result["lowering_terms"]:
        print("Lowers risk: " + ", ".join(t for t, _ in result["lowering_terms"]))

    if record["cvss"] is not None:
        print(f"\nNote: CVSS ({record['cvss']}/10) measures severity if exploited.")
        print("VulnTriage measures likelihood of exploitation -- a different")
        print("question, benchmarked against CVSS in model_report.md.")


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"\nError: {e}")
        print("(Needs an internet connection to reach services.nvd.nist.gov)")
