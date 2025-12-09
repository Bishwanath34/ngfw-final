from fastapi import FastAPI
from pydantic import BaseModel
from collections import deque
import os
import joblib
import numpy as np
import pandas as pd
from datetime import datetime

# -------- Load trained ML bundle --------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(BASE_DIR, "model.joblib")
CSV_PATH = os.path.join(BASE_DIR, "dataset.csv")

bundle = joblib.load(MODEL_PATH)
pipeline = bundle.get("pipeline")
anomaly_model = bundle.get("anomaly_model")
feature_cols = bundle.get("feature_cols") or [
    "method",
    "path",
    "role",
    "userId",
    "userAgent",
    "risk_rule",
    "tls_version",
    "tls_cipher",
    "ja3_bot_score",
    "tls_signals_count",
]

recent_scores = deque(maxlen=10000)

app = FastAPI(title="AI-NGFW ML Scoring & Policy Engine")


# -------- Request schema --------
class RequestContext(BaseModel):
    method: str
    path: str
    role: str
    userId: str
    userAgent: str
    risk_rule: float
    tls_version: str = "unknown"
    tls_cipher: str = "unknown"
    ja3_bot_score: float = 0.0
    tls_signals_count: int = 0


# -------- Internal helpers --------
def _row_from_context(ctx: RequestContext) -> dict:
    """Build a single-row feature dict from the gateway context."""
    return {
        "method": ctx.method,
        "path": ctx.path,
        "role": ctx.role,
        "userId": ctx.userId,
        "userAgent": ctx.userAgent,
        "risk_rule": float(ctx.risk_rule),
        "tls_version": ctx.tls_version or "unknown",
        "tls_cipher": ctx.tls_cipher or "unknown",
        "ja3_bot_score": float(ctx.ja3_bot_score or 0.0),
        "tls_signals_count": int(ctx.tls_signals_count or 0),
    }


def _dynamic_thresholds() -> tuple[float, float]:
    """Adaptive thresholds based on the recent score distribution.

    Returns (medium_threshold, high_threshold).
    """
    if len(recent_scores) < 200:
        return 0.30, 0.60

    arr = np.asarray(recent_scores, dtype=float)
    # Use median for "medium" and 85th percentile for "high"
    medium = float(np.quantile(arr, 0.50))
    high = float(np.quantile(arr, 0.85))

    # Clamp to reasonable ranges
    medium = max(0.15, min(medium, 0.50))
    high = max(0.60, min(high, 0.95))
    return medium, high


def _anomaly_risk(df: pd.DataFrame) -> float:
    """Return an anomaly-based risk score in [0, 1] using IsolationForest."""
    if anomaly_model is None or pipeline is None:
        return 0.0

    try:
        pre = pipeline.named_steps.get("preprocess")
        if pre is None:
            return 0.0
        X = pre.transform(df[feature_cols])
        # decision_function: positive → inlier, negative → outlier
        raw = float(anomaly_model.decision_function(X)[0])
        # Map [-1, +1] → [1, 0] so more negative is more risky
        risk = max(0.0, min(1.0, -raw))
        return risk
    except Exception:
        return 0.0


def _combine_risks(
    supervised: float,
    rule_risk: float,
    anomaly_risk: float,
    ja3_bot_score: float,
    tls_signals_count: int,
) -> float:
    """Weighted combination of different risk sources into a single [0, 1] score."""

    def clamp01(x: float) -> float:
        return float(max(0.0, min(1.0, x)))

    supervised = clamp01(supervised)
    rule_risk = clamp01(rule_risk)
    anomaly_risk = clamp01(anomaly_risk)
    ja3_component = clamp01(ja3_bot_score)  # already ~0..1
    tls_component = clamp01(tls_signals_count / 5.0)  # 0..1 if <=5 signals

    combined = (
        0.45 * supervised +
        0.25 * rule_risk +
        0.20 * anomaly_risk +
        0.07 * ja3_component +
        0.03 * tls_component
    )
    return clamp01(combined)


def _map_policy_level(risk: float, medium_thr: float, high_thr: float) -> str:
    """Map a risk score into a policy level string."""
    if risk < medium_thr:
        return "level_0_trusted"
    if risk < high_thr:
        return "level_1_observe"
    if risk < min(0.95, high_thr + 0.1):
        return "level_2_restrict"
    return "level_3_block"


# -------- Scoring endpoint (inline prevention brain) --------
@app.post("/score")
def score(context: RequestContext):
    # 1) Build feature row and dataframe
    row = _row_from_context(context)
    df = pd.DataFrame([row])

    # 2) Supervised probability (RandomForest)
    if pipeline is None:
        supervised_proba = 0.0
    else:
        proba = pipeline.predict_proba(df[feature_cols])[0][1]
        supervised_proba = float(proba)

    # 3) Adaptive thresholds
    recent_scores.append(supervised_proba)
    medium_thr, high_thr = _dynamic_thresholds()

    # 4) Unsupervised anomaly score
    anomaly_r = _anomaly_risk(df)

    # 5) Combine with rule risk + TLS signals
    combined_risk = _combine_risks(
        supervised=supervised_proba,
        rule_risk=context.risk_rule,
        anomaly_risk=anomaly_r,
        ja3_bot_score=context.ja3_bot_score,
        tls_signals_count=context.tls_signals_count,
    )

    # 6) Map to policy level & label
    level = _map_policy_level(combined_risk, medium_thr, high_thr)

    if level == "level_0_trusted":
        label = "ml_trusted"
    elif level == "level_1_observe":
        label = "ml_observe"
    elif level == "level_2_restrict":
        label = "ml_high_risk"
    else:
        label = "ml_critical"

    return {
        "ml_risk": float(combined_risk),
        "ml_label": label,
        "policy_level": level,
        "supervised_risk": float(supervised_proba),
        "anomaly_risk": float(anomaly_r),
        "thresholds": {
            "medium": float(medium_thr),
            "high": float(high_thr),
        },
    }


# -------- Automated policy recommendation --------
@app.get("/policy/recommend")
def policy_recommend():
    """Analyze historical dataset.csv and recommend RBAC and threshold policies."""
    if not os.path.exists(CSV_PATH):
        return {
            "generatedAt": datetime.utcnow().isoformat() + "Z",
            "rbacRecommendations": [],
            "thresholdRecommendations": [],
            "note": "dataset.csv not found yet; generate it from gateway logs first.",
        }

    df = pd.read_csv(CSV_PATH)

    if "is_attack" not in df.columns:
        df["is_attack"] = (
            (df.get("statusCode", 0) >= 400)
            | (df.get("label_rule", "").isin(["high_risk"]))
        ).astype(int)

    recs = []

    # Group by (role, path) to see which combinations are mostly malicious / benign
    grouped = df.groupby(["role", "path"], dropna=False)
    for (role, path), g in grouped:
        total = len(g)
        if total < 10:
            continue  # not enough evidence

        attacks = int(g["is_attack"].sum())
        benign = total - attacks
        attack_rate = attacks / float(total)

        if attack_rate >= 0.8:
            recs.append({
                "type": "rbac",
                "role": role,
                "pathPrefix": path,
                "suggestedAction": "deny",
                "confidence": round(attack_rate, 3),
                "reason": f"{attacks}/{total} (~{attack_rate:.0%}) of requests for this role/path looked malicious",
            })
        elif attack_rate <= 0.05 and (g["statusCode"] >= 400).mean() > 0.5:
            recs.append({
                "type": "rbac",
                "role": role,
                "pathPrefix": path,
                "suggestedAction": "relax",
                "confidence": round(1.0 - attack_rate, 3),
                "reason": f"Almost all ({benign}/{total}) requests looked benign but many were blocked; candidate to relax.",
            })

    # Threshold recommendations based on global risk distribution
    global_medium, global_high = _dynamic_thresholds()
    thr_recs = [
        {
            "type": "threshold",
            "parameter": "medium_risk_threshold",
            "suggestedValue": round(global_medium, 3),
            "reason": "Approximate median of recent supervised risk scores.",
        },
        {
            "type": "threshold",
            "parameter": "high_risk_threshold",
            "suggestedValue": round(global_high, 3),
            "reason": "Approximate 85th percentile of recent supervised risk scores.",
        },
    ]

    return {
        "generatedAt": datetime.utcnow().isoformat() + "Z",
        "rbacRecommendations": recs,
        "thresholdRecommendations": thr_recs,
    }


# -------- Run server --------
if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=5000)
