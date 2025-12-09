import os
import joblib
import pandas as pd

from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.compose import ColumnTransformer
from sklearn.preprocessing import OneHotEncoder
from sklearn.pipeline import Pipeline


# -------- Paths --------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
csv_path = os.path.join(BASE_DIR, "dataset.csv")
model_path = os.path.join(BASE_DIR, "model.joblib")

print("[ML TRAIN] Loading dataset from:", csv_path)
df = pd.read_csv(csv_path)
print("[ML TRAIN] Rows in dataset:", len(df))
print(df.head())


# -------- Target label: is_attack --------
# Consider a request an attack if:
#  - statusCode >= 400  OR
#  - rule engine labeled it as high_risk
df["is_attack"] = (
    (df["statusCode"] >= 400)
    | (df["label_rule"].isin(["high_risk"]))
).astype(int)

print("[ML TRAIN] Attack label distribution:")
print(df["is_attack"].value_counts())


# -------- Feature engineering --------
base_feature_cols = [
    "method",
    "path",
    "role",
    "userId",
    "userAgent",
    "risk_rule",
]

tls_feature_cols = [
    # Optional TLS / JA3 features. If they are not present yet in dataset.csv
    # we will create them with neutral defaults so the pipeline still works.
    "tls_version",
    "tls_cipher",
    "ja3_bot_score",
    "tls_signals_count",
]

# Ensure all feature columns exist in the dataframe
for col in tls_feature_cols:
    if col not in df.columns:
        if col in ("ja3_bot_score", "tls_signals_count"):
            df[col] = 0.0
        else:
            df[col] = "unknown"

feature_cols = base_feature_cols + tls_feature_cols

X = df[feature_cols]
y = df["is_attack"]

categorical_cols = [
    "method",
    "path",
    "role",
    "userId",
    "userAgent",
    "tls_version",
    "tls_cipher",
]

numeric_cols = [
    "risk_rule",
    "ja3_bot_score",
    "tls_signals_count",
]

preprocess = ColumnTransformer(
    transformers=[
        ("cat", OneHotEncoder(handle_unknown="ignore"), categorical_cols),
        ("num", "passthrough", numeric_cols),
    ]
)

rf_model = RandomForestClassifier(
    n_estimators=200,
    random_state=42,
    class_weight="balanced",
    n_jobs=-1,
)

pipeline = Pipeline(
    steps=[
        ("preprocess", preprocess),
        ("model", rf_model),
    ]
)

# -------- Train / test split --------
X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.3,
    random_state=42,
    stratify=y if len(y.unique()) > 1 else None,
)

print("[ML TRAIN] Training shape:", X_train.shape, " Test shape:", X_test.shape)

pipeline.fit(X_train, y_train)

train_score = pipeline.score(X_train, y_train)
test_score = pipeline.score(X_test, y_test)
print(f"[ML TRAIN] Train accuracy: {train_score:.3f}")
print(f"[ML TRAIN] Test  accuracy: {test_score:.3f}")

# -------- Unsupervised anomaly model (IsolationForest) --------
# This model provides an additional anomaly-based risk score that helps
# with adaptive / proactive detection of previously unseen patterns.
print("[ML TRAIN] Fitting IsolationForest anomaly model...")
X_all_transformed = pipeline.named_steps["preprocess"].transform(X)

iso = IsolationForest(
    n_estimators=100,
    contamination=0.05,   # expected proportion of anomalies
    random_state=42,
)
iso.fit(X_all_transformed)

# -------- Save bundle --------
bundle = {
    "pipeline": pipeline,
    "anomaly_model": iso,
    "feature_cols": feature_cols,
    "categorical_cols": categorical_cols,
    "numeric_cols": numeric_cols,
}

joblib.dump(bundle, model_path)
print("[ML TRAIN] Saved model bundle to:", model_path)
