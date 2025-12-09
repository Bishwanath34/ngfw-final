from fastapi import FastAPI
from pydantic import BaseModel
from collections import deque
import os
import joblib
import numpy as np
import pandas as pd
from datetime import datetime
import uvicorn

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

app = FastAPI(
    title="AI-NGFW ML Scoring & Policy Engine",
    description="Machine learning inline risk scoring and policy automation engine",
    version="1.0.0"
)

# -------- Health root endpoint --------
@app.get("/")
def home():
    return {
        "service": "AI-NGFW ML Scoring & Policy Engine",
        "status": "running",
        "docs": "/docs",
        "score_endpoint": "/score",
        "policy_recommend": "/policy/recommend"
    }


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
    if len(recent_scores) < 200:
        return 0.30, 0.60

    arr = np.asarray(recent_scores, dtype=float)
    medium = float(np.quantile(arr, 0.50))
    high = float(np.quantile(arr, 0.85))

    medium = max(0.15, min(medium, 0.50))
    high = max(0.60, min(high, 0.95))
    return medium, high


def _anomaly_risk(df: pd.DataFrame) -> float:
    if anomaly_model is None or pipeline is None:
        return 0.0
    try:
        pre = pipeline.named_steps.get("preprocess")
        if pre is None:
            return 0.0
        X = pre.transform(df[feature_cols])
        raw = float(anomaly_model.decision_function(X)[0])
        return max(0.0, min(1.0, -raw))
    except Exception:
        return 0.0


def _combine_risks(supervised, rule_risk, anomaly_risk, ja3_bot_score, tls_signals_count) -> float:
    def clamp01(x: float) -> float:
        return float(max(0.0, min(1.0, x)))

    supervised = clamp01(supervised)
    rule_risk = clamp01(rule_risk)
    anomaly_risk = clamp01(anomaly_risk)
    ja3_component = clamp01(ja3_bot_score)
    tls_component = clamp01(tls_signals_count / 5.0)

    combined = (
        0.45 * supervised +
        0.25 * rule_risk +
        0.20 * anomaly_risk +
        0.07 * ja3_component +
        0.03 * tls_component
    )

    return clamp01(combined)


def _map_policy_level(risk: float, medium_thr: float, high_thr: float) -> str:
    if risk < medium_thr:
        return "level_0_trusted"
    if risk < high_thr:
        return "level_1_observe"
    if risk < min(0.95, high_thr + 0.1):
        return "level_2_restrict"
    return "level_3_block"


# -------- Inline scoring brain --------
@app.post("/score")
def score(context: RequestContext):
    row = _row_from_context(context)
    df = pd.DataFrame([row])

    if pipeline is None:
        supervised_proba = 0.0
    else:
        supervised_proba = float(pipeline.predict_proba(df[feature_cols])[0][1])

    recent_scores.append(supervised_proba)
    medium_thr, high_thr = _dynamic_thresholds()

    anomaly_r = _anomaly_risk(df)

    combined_risk = _combine_risks(
        supervised=supervised_proba,
        rule_risk=context.risk_rule,
        anomaly_risk=anomaly_r,
        ja3_bot_score=context.ja3_bot_score,
        tls_signals_count=context.tls_signals_count,
    )

    level = _map_policy_level(combined_risk, medium_thr, high_thr)

    label = {
        "level_0_trusted": "ml_trusted",
        "level_1_observe": "ml_observe",
        "level_2_restrict": "ml_high_risk",
    }.get(level, "ml_critical")

    return {
        "ml_risk": float(combined_risk),
        "ml_label": label,
        "policy_level": level,
        "supervised_risk": float(supervised_proba),
        "anomaly_risk": float(anomaly_r),
        "thresholds": {"medium": float(medium_thr), "high": float(high_thr)},
    }


# -------- Automated policy recommendations --------
@app.get("/policy/recommend")
def policy_recommend():
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
    grouped = df.groupby(["role", "path"], dropna=False)

    for (role, path), g in grouped:
        total = len(g)
        if total < 10:
            continue

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
                "reason": f"{attacks}/{total} (~{attack_rate:.0%}) were malicious",
            })
        elif attack_rate <= 0.05 and (g["statusCode"] >= 400).mean() > 0.5:
            recs.append({
                "type": "rbac",
                "role": role,
                "pathPrefix": path,
                "suggestedAction": "relax",
                "confidence": round(1.0 - attack_rate, 3),
                "reason": f"Mostly benign ({benign}/{total}) but heavily blocked",
            })

    global_medium, global_high = _dynamic_thresholds()
    thr_recs = [
        {
            "type": "threshold",
            "parameter": "medium_risk_threshold",
            "suggestedValue": round(global_medium, 3),
            "reason": "Approx median of recent risk scores",
        },
        {
            "type": "threshold",
            "parameter": "high_risk_threshold",
            "suggestedValue": round(global_high, 3),
            "reason": "Approx 85th percentile of risk scores",
        },
    ]

    return {
        "generatedAt": datetime.utcnow().isoformat() + "Z",
        "rbacRecommendations": recs,
        "thresholdRecommendations": thr_recs,
    }


# -------- Run server (Render compatible) --------
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    uvicorn.run(app, host="0.0.0.0", port=port)
