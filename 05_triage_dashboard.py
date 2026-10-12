"""
VulnTriage dashboard: score a single CVE description, or rank a backlog of
them (pasted one per line, or uploaded as a CSV with a 'description' column).

Usage:
    pip install flask
    python 05_triage_dashboard.py
Then open http://127.0.0.1:5000
"""
import io
import csv as csvmod
from flask import Flask, request, render_template_string, Response
from vulntriage_lib import score_description
import pandas as pd

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 2 * 1024 * 1024  # reject uploads over 2MB
MAX_BATCH = 500

PAGE = """
<!doctype html>
<html>
<head>
<title>VulnTriage Dashboard</title>
<style>
  body { font-family: system-ui, sans-serif; max-width: 900px; margin: 30px auto; padding: 0 16px; color: #1a1a1a; }
  h1 { font-size: 1.4rem; margin-bottom: 4px; }
  .sub { color: #666; margin-top: 0; }
  .tabs { display: flex; gap: 8px; margin: 20px 0 10px; border-bottom: 2px solid #eee; }
  .tab { padding: 8px 16px; cursor: pointer; border-radius: 6px 6px 0 0; }
  .tab.active { background: #eee; font-weight: bold; }
  textarea { width: 100%; height: 110px; font-size: 0.95rem; padding: 8px; box-sizing: border-box; font-family: monospace; }
  button { margin-top: 10px; padding: 10px 20px; font-size: 1rem; cursor: pointer; }
  .result { margin-top: 20px; padding: 14px; border-radius: 8px; }
  .tier-now   { background: #fde2e2; border: 1px solid #d33; }
  .tier-week  { background: #fff2cc; border: 1px solid #d99; }
  .tier-month { background: #e6f0ff; border: 1px solid #99b; }
  .tier-low   { background: #e6f7e6; border: 1px solid #6a6; }
  .score { font-size: 1.6rem; font-weight: bold; }
  .terms span { display: inline-block; background: #eee; border-radius: 4px; padding: 2px 8px; margin: 2px; font-size: 0.85rem; }
  .raising span { background: #fde2e2; } .lowering span { background: #e6f7e6; }
  table { width: 100%; border-collapse: collapse; margin-top: 16px; font-size: 0.9rem; }
  th, td { text-align: left; padding: 6px 8px; border-bottom: 1px solid #eee; vertical-align: top; }
  th { background: #fafafa; }
  .badge { padding: 2px 8px; border-radius: 10px; font-size: 0.8rem; white-space: nowrap; }
  small { color: #666; }
</style>
</head>
<body>
  <h1>VulnTriage Dashboard</h1>
  <p class="sub"><small>Model trained on CVEs ≤2022, labeled with CISA KEV,
  evaluated on 2023–2024 CVEs never seen in training.</small></p>

  <div class="tabs">
    <a href="/" style="text-decoration:none;color:inherit"><div class="tab {{ 'active' if mode=='single' else '' }}">Single CVE</div></a>
    <a href="/batch" style="text-decoration:none;color:inherit"><div class="tab {{ 'active' if mode=='batch' else '' }}">Batch Triage (backlog)</div></a>
  </div>

  {% if mode == 'single' %}
    <form method="post" action="/">
      <textarea name="description" placeholder="e.g. A remote code execution vulnerability exists due to improper input validation...">{{ description or '' }}</textarea><br>
      <button type="submit">Score this vulnerability</button>
    </form>
    {% if result %}
    <div class="result {{ tier_class }}">
      <div class="score">Risk score: {{ '%.3f'|format(result.score) }}</div>
      <div><strong>{{ result.tier }}</strong></div>
      {% if result.raising_terms %}
      <p>Raises risk (present in this text):<br>
        <span class="terms raising">{% for term, w in result.raising_terms %}<span>{{ term }}</span>{% endfor %}</span></p>
      {% endif %}
      {% if result.lowering_terms %}
      <p>Lowers risk (present in this text):<br>
        <span class="terms lowering">{% for term, w in result.lowering_terms %}<span>{{ term }}</span>{% endfor %}</span></p>
      {% endif %}
    </div>
    {% endif %}

  {% else %}
    <p><small>Paste one vulnerability description per line (or upload a CSV with a
    "description" column). You'll get back a ranked backlog: what to patch first,
    this week, this month, or monitor — the same review-budget framing used in
    the model's benchmark against CVSS.</small></p>
    <form method="post" action="/batch" enctype="multipart/form-data">
      <textarea name="bulk_text" placeholder="Paste multiple descriptions, one per line...">{{ bulk_text or '' }}</textarea><br>
      <p><small>...or upload a CSV file with a "description" column:</small>
      <input type="file" name="csv_file" accept=".csv"></p>
      <button type="submit">Rank this backlog</button>
    </form>

    {% if rows %}
    <p><strong>{{ rows|length }} item(s) ranked, highest risk first.</strong></p>
    {% if notice %}<p><small>{{ notice }}</small></p>{% endif %}
    <form method="post" action="/batch/download">
      <input type="hidden" name="csv_data" value="{{ csv_text }}">
      <button type="submit">⬇ Download full results as CSV</button>
    </form>
    <table>
      <tr><th>#</th><th>Score</th><th>Tier</th><th>Description</th></tr>
      {% for r in rows %}
      <tr>
        <td>{{ loop.index }}</td>
        <td>{{ '%.3f'|format(r.score) }}</td>
        <td><span class="badge {{ r.tier_class }}">{{ r.tier_short }}</span></td>
        <td>{{ r.description[:110] }}{{ '...' if r.description|length > 110 else '' }}</td>
      </tr>
      {% endfor %}
    </table>
    {% endif %}
  {% endif %}
</body>
</html>
"""

TIER_CLASS = {
    "Patch immediately": "tier-now",
    "Patch this week": "tier-week",
    "Patch this month": "tier-month",
    "Monitor": "tier-low",
}
TIER_SHORT = {
    "Patch immediately": "PATCH NOW",
    "Patch this week": "THIS WEEK",
    "Patch this month": "THIS MONTH",
    "Monitor": "MONITOR",
}

def csv_safe(text):
    """Stop spreadsheet apps from treating user text as a formula."""
    return "'" + text if text[:1] in ("=", "+", "-", "@") else text


def _tier_class(tier):
    for key, cls in TIER_CLASS.items():
        if tier.startswith(key):
            return cls
    return ""


def _tier_short(tier):
    for key, short in TIER_SHORT.items():
        if tier.startswith(key):
            return short
    return tier


@app.route("/", methods=["GET", "POST"])
def single():
    result, description, tier_class = None, "", ""
    if request.method == "POST":
        description = request.form.get("description", "").strip()
        if description:
            result = score_description(description)
            tier_class = _tier_class(result["tier"])
    return render_template_string(PAGE, mode="single", result=result,
                                   description=description, tier_class=tier_class)


@app.route("/batch", methods=["GET", "POST"])
def batch():
    rows, csv_text, notice = None, "", ""
    bulk_text = ""
    if request.method == "POST":
        descriptions = []
        f = request.files.get("csv_file")
        if f and f.filename:
            content = f.read().decode("utf-8", errors="ignore")
            reader = csvmod.DictReader(io.StringIO(content))
            col = next((c for c in (reader.fieldnames or [])
                        if c.strip().lower() == "description"), None)
            if col:
                descriptions = [row[col].strip() for row in reader if row.get(col, "").strip()]
        else:
            bulk_text = request.form.get("bulk_text", "")
            descriptions = [ln.strip() for ln in bulk_text.splitlines() if ln.strip()]

        if len(descriptions) > MAX_BATCH:
            notice = f"Only the first {MAX_BATCH} of {len(descriptions)} items were scored."
            descriptions = descriptions[:MAX_BATCH]

        if descriptions:
            scored = [score_description(d) for d in descriptions]
            df = pd.DataFrame({
                "description": [csv_safe(d) for d in descriptions],
                "score": [s["score"] for s in scored],
                "tier": [s["tier"] for s in scored],
            }).sort_values("score", ascending=False).reset_index(drop=True)
            csv_text = df.to_csv(index=False)
            rows = [
                {"description": r.description, "score": r.score, "tier": r.tier,
                 "tier_class": _tier_class(r.tier), "tier_short": _tier_short(r.tier)}
                for r in df.itertuples()
            ]
    return render_template_string(PAGE, mode="batch", rows=rows, bulk_text=bulk_text,
                                   csv_text=csv_text, notice=notice)


@app.route("/batch/download", methods=["POST"])
def batch_download():
    # Results travel with the request instead of being kept on the server.
    csv_data = request.form.get("csv_data", "")
    if not csv_data:
        return "No batch results to download.", 400
    return Response(csv_data, mimetype="text/csv",
                    headers={"Content-Disposition": "attachment; filename=vulntriage_ranked_backlog.csv"})


if __name__ == "__main__":
    print("VulnTriage dashboard running at http://127.0.0.1:5000 (Ctrl+C to stop)")
    app.run(debug=False, port=5000)
