"""
VulnTriage - shared scoring logic used by both the CLI demo and the web demo.
"""
import pickle
from pathlib import Path
import numpy as np
import pandas as pd

BASE_DIR = Path(__file__).resolve().parent
MODEL_PATH = BASE_DIR / "vulntriage_model.pkl"
TEST_PATH = BASE_DIR / "vulntriage_test.csv"

_model = None
_thresholds = None


def load_model():
    global _model
    if _model is None:
        with open(MODEL_PATH, "rb") as f:
            _model = pickle.load(f)
    return _model


def get_thresholds():
    """
    Tier cutoffs, derived from where the model's own score distribution sits
    on a real (2023-2024) set of CVEs. This mirrors a review-budget framing:
    'Patch now' = roughly the riskiest 1% of CVEs a team would see in practice.
    """
    global _thresholds
    if _thresholds is not None:
        return _thresholds
    model = load_model()
    test = pd.read_csv(TEST_PATH)
    test["description"] = test["description"].fillna("")
    scores = model.predict_proba(test["description"])[:, 1]
    _thresholds = {
        "patch_now": float(np.percentile(scores, 99)),   # top 1%
        "patch_week": float(np.percentile(scores, 95)),  # top 5%
        "patch_month": float(np.percentile(scores, 80)), # top 20%
    }
    return _thresholds


def tier_for_score(score, thresholds):
    if score >= thresholds["patch_now"]:
        return "Patch immediately (top ~1% risk)"
    if score >= thresholds["patch_week"]:
        return "Patch this week (top ~5% risk)"
    if score >= thresholds["patch_month"]:
        return "Patch this month (top ~20% risk)"
    return "Monitor / low priority"


def explain(description, model, top_k=6):
    """
    Returns the words/phrases actually present in this description that
    pushed the score up or down the most (coefficient x tf-idf weight for
    terms that appear in the input) - not just the model's global top terms.
    """
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
    return {
        "score": score,
        "tier": tier,
        "raising_terms": raising,
        "lowering_terms": lowering,
        "thresholds": thresholds,
    }
