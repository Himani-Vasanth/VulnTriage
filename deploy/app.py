"""
VulnTriage dashboard: single-CVE scoring and batch backlog ranking.
Runs locally (python app.py) or on Hugging Face Spaces via Docker.
"""
import io
import os
import json
import csv as csvmod
import pickle
import numpy as np
import pandas as pd
from flask import Flask, request, render_template_string, Response

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 2 * 1024 * 1024  # reject uploads over 2MB
MAX_BATCH = 500  # cap rows scored per request on the public deployment

MODEL_PATH = os.path.join(os.path.dirname(__file__), "vulntriage_model.pkl")
THRESHOLDS_PATH = os.path.join(os.path.dirname(__file__), "thresholds.json")

_model = None
_thresholds = None


def load_model():
    global _model
    if _model is None:
        with open(MODEL_PATH, "rb") as f:
            _model = pickle.load(f)
    return _model


def get_thresholds():
    global _thresholds
    if _thresholds is not None:
        return _thresholds
    with open(THRESHOLDS_PATH) as f:
        _thresholds = json.load(f)
    return _thresholds


def tier_for_score(score, thresholds):
    if score >= thresholds["patch_now"]:
        return "Patch immediately"
    if score >= thresholds["patch_week"]:
        return "Patch this week"
    if score >= thresholds["patch_month"]:
        return "Patch this month"
    return "Monitor"


def explain(description, model, top_k=6):
    tfidf = model.named_steps["tfidf"]
    clf = model.named_steps["clf"]
    vec = tfidf.transform([description])
    coefs = clf.coef_[0]
    contributions = vec.multiply(coefs).toarray()[0]
    nz = np.nonzero(contributions)[0]
    if len(nz) == 0:
        return [], []
    order = nz[np.argsort(-contributions[nz])]
    feat_names = tfidf.get_feature_names_out()
    raising = [(feat_names[i], round(float(contributions[i]), 3))
               for i in order[:top_k] if contributions[i] > 0]
    lowering = [(feat_names[i], round(float(contributions[i]), 3))
                for i in order[::-1][:top_k] if contributions[i] < 0]
    return raising, lowering


def score_description(description):
    model = load_model()
    thresholds = get_thresholds()
    score = float(model.predict_proba([description])[0, 1])
    tier = tier_for_score(score, thresholds)
    raising, lowering = explain(description, model)
    return {"score": score, "tier": tier, "raising_terms": raising,
            "lowering_terms": lowering, "thresholds": thresholds}


TIER_META = {
    "Patch immediately": ("crit", "PATCH NOW", "Top ~1% risk"),
    "Patch this week":   ("high", "THIS WEEK", "Top ~5% risk"),
    "Patch this month":  ("med",  "THIS MONTH", "Top ~20% risk"),
    "Monitor":            ("low",  "MONITOR", "Lower priority"),
}


def tier_meta(tier):
    for key, meta in TIER_META.items():
        if tier.startswith(key):
            return meta
    return ("low", tier.upper(), "")


def csv_safe(text):
    """Stop spreadsheet apps from treating user text as a formula."""
    return "'" + text if text[:1] in ("=", "+", "-", "@") else text


PAGE = """
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>VulnTriage // exploit-risk console</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;700&family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
<style>
  :root {
    --bg: #0a0e14;
    --panel: #0f1620;
    --panel-2: #131c28;
    --line: #1f2b3a;
    --text: #d6e2f0;
    --muted: #7189a3;
    --accent: #35e0c2;
    --accent-dim: #1a7a68;
    --crit: #ff4d5e;
    --high: #ff9f43;
    --med:  #ffd23f;
    --low:  #35e0c2;
  }
  * { box-sizing: border-box; }
  body {
    margin: 0; background: radial-gradient(ellipse at top, #101823 0%, #0a0e14 60%);
    color: var(--text); font-family: 'Inter', system-ui, sans-serif;
    min-height: 100vh;
  }
  .topbar {
    display: flex; align-items: center; justify-content: space-between;
    padding: 18px 28px; border-bottom: 1px solid var(--line);
    background: linear-gradient(180deg, rgba(20,28,40,0.9), rgba(15,22,32,0.6));
    position: sticky; top: 0; backdrop-filter: blur(6px); z-index: 5;
  }
  .brand { display: flex; align-items: center; gap: 10px; }
  .brand .dot { width: 10px; height: 10px; border-radius: 50%; background: var(--accent);
    box-shadow: 0 0 10px 2px var(--accent); animation: pulse 2s infinite; }
  @keyframes pulse { 0%,100% { opacity: 1; } 50% { opacity: 0.4; } }
  .brand h1 { font-size: 1.05rem; margin: 0; letter-spacing: 0.5px; font-weight: 700; }
  .brand small { color: var(--muted); font-family: 'JetBrains Mono', monospace; font-size: 0.72rem; }
  .stat-strip { display:flex; gap: 22px; font-family: 'JetBrains Mono', monospace; font-size: 0.72rem; color: var(--muted); }
  .stat-strip b { color: var(--accent); }

  .wrap { max-width: 980px; margin: 0 auto; padding: 26px 20px 60px; }

  .tabs { display: flex; gap: 4px; margin-bottom: 20px; border: 1px solid var(--line); border-radius: 10px; padding: 4px; background: var(--panel); width: fit-content; }
  .tab { padding: 9px 18px; border-radius: 7px; text-decoration: none; color: var(--muted); font-size: 0.88rem; font-weight: 600; letter-spacing: 0.2px; }
  .tab.active { background: var(--accent); color: #06231d; }

  .card { background: var(--panel); border: 1px solid var(--line); border-radius: 14px; padding: 22px; margin-bottom: 20px;
          box-shadow: 0 0 0 1px rgba(255,255,255,0.02) inset; }
  .card h2 { margin: 0 0 6px; font-size: 1rem; }
  .hint { color: var(--muted); font-size: 0.85rem; margin: 0 0 16px; line-height: 1.5; }

  textarea, input[type=file] {
    width: 100%; background: #0a1119; border: 1px solid var(--line); border-radius: 10px;
    color: var(--text); padding: 12px; font-family: 'JetBrains Mono', monospace; font-size: 0.9rem;
  }
  textarea { height: 120px; resize: vertical; }
  textarea:focus { outline: none; border-color: var(--accent-dim); }

  button {
    margin-top: 14px; padding: 11px 22px; border-radius: 9px; border: none;
    background: var(--accent); color: #06231d; font-weight: 700; font-size: 0.92rem;
    cursor: pointer; letter-spacing: 0.3px; transition: transform 0.08s ease;
  }
  button:hover { transform: translateY(-1px); }

  .result { margin-top: 20px; border-radius: 12px; padding: 18px; border: 1px solid var(--line); background: var(--panel-2); }
  .score-row { display: flex; align-items: baseline; gap: 14px; margin-bottom: 8px; }
  .score { font-family: 'JetBrains Mono', monospace; font-size: 2rem; font-weight: 700; }
  .badge { display: inline-block; padding: 4px 12px; border-radius: 999px; font-size: 0.75rem; font-weight: 700; letter-spacing: 0.5px; }
  .badge.crit { background: rgba(255,77,94,0.15); color: var(--crit); border: 1px solid rgba(255,77,94,0.4); }
  .badge.high { background: rgba(255,159,67,0.15); color: var(--high); border: 1px solid rgba(255,159,67,0.4); }
  .badge.med  { background: rgba(255,210,63,0.15); color: var(--med); border: 1px solid rgba(255,210,63,0.4); }
  .badge.low  { background: rgba(53,224,194,0.12); color: var(--low); border: 1px solid rgba(53,224,194,0.4); }
  .tier-desc { color: var(--muted); font-size: 0.82rem; margin-top: 2px; }

  .bar-track { height: 8px; border-radius: 6px; background: #0a1119; margin: 14px 0 4px; overflow: hidden; border: 1px solid var(--line); }
  .bar-fill { height: 100%; border-radius: 6px; }

  .terms { display: flex; flex-wrap: wrap; gap: 6px; margin-top: 6px; }
  .terms span { font-family: 'JetBrains Mono', monospace; font-size: 0.78rem; padding: 3px 9px; border-radius: 6px; }
  .raising span { background: rgba(255,77,94,0.12); color: var(--crit); }
  .lowering span { background: rgba(53,224,194,0.12); color: var(--low); }
  .terms-label { font-size: 0.75rem; color: var(--muted); text-transform: uppercase; letter-spacing: 0.5px; margin-top: 12px; }

  table { width: 100%; border-collapse: collapse; margin-top: 14px; font-size: 0.86rem; }
  th, td { text-align: left; padding: 10px 10px; border-bottom: 1px solid var(--line); vertical-align: top; }
  th { color: var(--muted); font-weight: 600; font-size: 0.72rem; text-transform: uppercase; letter-spacing: 0.5px; }
  td.score-cell { font-family: 'JetBrains Mono', monospace; }
  tr:hover td { background: rgba(255,255,255,0.02); }

  a.dl { display: inline-flex; align-items: center; gap: 6px; margin-top: 4px; color: var(--accent); text-decoration: none; font-weight: 600; font-size: 0.85rem; }
  a.dl:hover { text-decoration: underline; }

  .footer-note { color: var(--muted); font-size: 0.78rem; margin-top: 30px; text-align: center; }
  .footer-note code { color: var(--accent); }
</style>
</head>
<body>
  <div class="topbar">
    <div class="brand">
      <div class="dot"></div>
      <div>
        <h1>VulnTriage</h1>
        <small>ml-based exploit-likelihood triage // CISA KEV-trained</small>
      </div>
    </div>
    <div class="stat-strip">
      <div>MODEL <b>TF-IDF+LogReg</b></div>
      <div>RECALL@5% <b>51%</b> <span style="opacity:.5">vs CVSS 20%</span></div>
    </div>
  </div>

  <div class="wrap">
    <div class="tabs">
      <a href="/" class="tab {{ 'active' if mode=='single' else '' }}">Single CVE</a>
      <a href="/batch" class="tab {{ 'active' if mode=='batch' else '' }}">Batch Triage</a>
    </div>

    {% if mode == 'single' %}
    <div class="card">
      <h2>Score a vulnerability</h2>
      <p class="hint">Paste a CVE / vulnerability description below. The model was trained on CVEs
        published through 2022 and evaluated on 2023-2024 CVEs it never saw during training.</p>
      <form method="post" action="/">
        <textarea name="description" placeholder="e.g. A remote code execution vulnerability exists due to improper input validation...">{{ description or '' }}</textarea>
        <button type="submit">Run triage &rarr;</button>
      </form>

      {% if result %}
      {% set cls, short, sub = tier_meta(result.tier) %}
      <div class="result">
        <div class="score-row">
          <div class="score">{{ '%.3f'|format(result.score) }}</div>
          <div>
            <span class="badge {{ cls }}">{{ short }}</span>
            <div class="tier-desc">{{ sub }}</div>
          </div>
        </div>
        <div class="bar-track"><div class="bar-fill" style="width:{{ (result.score*100)|round(1) }}%; background: var(--{{ cls }});"></div></div>

        {% if result.raising_terms %}
        <div class="terms-label">Raises risk</div>
        <div class="terms raising">{% for term, w in result.raising_terms %}<span>{{ term }}</span>{% endfor %}</div>
        {% endif %}
        {% if result.lowering_terms %}
        <div class="terms-label">Lowers risk</div>
        <div class="terms lowering">{% for term, w in result.lowering_terms %}<span>{{ term }}</span>{% endfor %}</div>
        {% endif %}
      </div>
      {% endif %}
    </div>

    {% else %}
    <div class="card">
      <h2>Rank a backlog</h2>
      <p class="hint">Paste several descriptions (one per line), or upload a CSV with a
        <code>description</code> column. Results come back ranked highest-risk-first —
        the same review-budget framing behind the model's benchmark against CVSS.</p>
      <form method="post" action="/batch" enctype="multipart/form-data">
        <textarea name="bulk_text" placeholder="Paste multiple descriptions, one per line...">{{ bulk_text or '' }}</textarea>
        <p class="hint" style="margin:10px 0 4px">...or upload a CSV file:</p>
        <input type="file" name="csv_file" accept=".csv">
        <br><button type="submit">Rank this backlog &rarr;</button>
      </form>
    </div>

    {% if rows %}
    <div class="card">
      <h2>{{ rows|length }} item(s) ranked</h2>
      {% if notice %}<p class="hint">{{ notice }}</p>{% endif %}
      <form method="post" action="/batch/download">
        <input type="hidden" name="csv_data" value="{{ csv_text }}">
        <button type="submit">&#8681; Download ranked backlog (CSV)</button>
      </form>
      <table>
        <tr><th>#</th><th>Score</th><th>Priority</th><th>Description</th></tr>
        {% for r in rows %}
        <tr>
          <td>{{ loop.index }}</td>
          <td class="score-cell">{{ '%.3f'|format(r.score) }}</td>
          <td><span class="badge {{ r.cls }}">{{ r.short }}</span></td>
          <td>{{ r.description[:120] }}{{ '...' if r.description|length > 120 else '' }}</td>
        </tr>
        {% endfor %}
      </table>
    </div>
    {% endif %}
    {% endif %}

    <div class="footer-note">Trained on the public CVE corpus + CISA KEV catalog &middot; time-based train/test split &middot; see <code>model_report.md</code> for methodology and limitations</div>
  </div>
</body>
</html>
"""


@app.route("/", methods=["GET", "POST"])
def single():
    result, description = None, ""
    if request.method == "POST":
        description = request.form.get("description", "").strip()
        if description:
            result = score_description(description)
    return render_template_string(PAGE, mode="single", result=result,
                                   description=description, tier_meta=tier_meta)


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
            rows = []
            for r in df.itertuples():
                cls, short, _ = tier_meta(r.tier)
                rows.append({"description": r.description, "score": r.score,
                             "cls": cls, "short": short})
    return render_template_string(PAGE, mode="batch", rows=rows, bulk_text=bulk_text,
                                   csv_text=csv_text, notice=notice)


@app.route("/batch/download", methods=["POST"])
def batch_download():
    # Results travel with the request rather than living on the server, so
    # concurrent visitors never see each other's data.
    csv_data = request.form.get("csv_data", "")
    if not csv_data:
        return "No batch results to download.", 400
    return Response(csv_data, mimetype="text/csv",
                    headers={"Content-Disposition": "attachment; filename=vulntriage_ranked_backlog.csv"})


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 7860))
    print(f"Starting VulnTriage dashboard on 0.0.0.0:{port}")
    app.run(host="0.0.0.0", port=port, debug=False)
