"""
Machine Learning Vulnerability Classifier for Network Port Intelligence.
Trains a multi-class Random Forest classifier to predict vulnerability risk levels
('Safe', 'Low', 'Medium', 'High', 'Critical') based on port intelligence features.
"""

import os
import pickle
import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import OneHotEncoder, StandardScaler
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score

MODEL_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "models")
MODEL_PATH = os.path.join(MODEL_DIR, "vulnerability_model.pkl")

CATEGORICAL_FEATURES = ["protocol", "service", "port_state", "exposure_level", "banner_flags"]
NUMERICAL_FEATURES = ["port", "service_version_risk", "known_vuln_indicator", "cvss_baseline", "encryption_detected"]
CLASS_ORDER = ["Safe", "Low", "Medium", "High", "Critical"]

def build_model_pipeline():
    """Builds a scikit-learn preprocessing and Random Forest pipeline."""
    preprocessor = ColumnTransformer(
        transformers=[
            ("cat", OneHotEncoder(handle_unknown="ignore", sparse_output=False), CATEGORICAL_FEATURES),
            ("num", StandardScaler(), NUMERICAL_FEATURES)
        ]
    )

    clf = RandomForestClassifier(
        n_estimators=120,
        max_depth=14,
        min_samples_split=4,
        random_state=42,
        class_weight="balanced"
    )

    pipeline = Pipeline(steps=[
        ("preprocessor", preprocessor),
        ("classifier", clf)
    ])
    return pipeline

def train_and_save_model(data_path=None, model_path=MODEL_PATH):
    """
    Loads dataset, trains the Random Forest vulnerability classifier,
    evaluates performance, and serializes the model.
    """
    if data_path is None:
        data_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "training_data.csv")

    if not os.path.exists(data_path):
        print(f"[-] Training data not found at '{data_path}'. Generating now...")
        from data.generate_dataset import generate_dataset
        generate_dataset(3000, data_path)

    df = pd.read_csv(data_path)
    X = df[CATEGORICAL_FEATURES + NUMERICAL_FEATURES]
    y = df["risk_level"]

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

    print("[*] Training Random Forest Vulnerability Classifier...")
    model_pipeline = build_model_pipeline()
    model_pipeline.fit(X_train, y_train)

    y_pred = model_pipeline.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    print(f"[+] Model Accuracy: {acc * 100:.2f}%")
    print("[+] Classification Report:")
    print(classification_report(y_test, y_pred, labels=CLASS_ORDER, zero_division=0))

    os.makedirs(os.path.dirname(model_path), exist_ok=True)
    with open(model_path, "wb") as f:
        pickle.dump(model_pipeline, f)

    print(f"[+] Model successfully saved to '{model_path}'.")
    return model_pipeline

_CACHED_MODEL = None

def get_loaded_model(model_path=MODEL_PATH):
    """Loads and caches the serialized vulnerability classifier."""
    global _CACHED_MODEL
    if _CACHED_MODEL is not None:
        return _CACHED_MODEL

    if not os.path.exists(model_path):
        print("[*] Model file not found. Triggering training...")
        _CACHED_MODEL = train_and_save_model(model_path=model_path)
    else:
        with open(model_path, "rb") as f:
            _CACHED_MODEL = pickle.load(f)
    return _CACHED_MODEL

def predict_single_port(port_record, model=None):
    """
    Predicts the vulnerability risk level and confidence score for a port record.
    Returns: (predicted_risk_level, confidence_score, probabilities_dict)
    """
    if model is None:
        model = get_loaded_model()

    # Create single-row DataFrame with expected schema
    input_df = pd.DataFrame([{
        "protocol": port_record.get("protocol", "TCP"),
        "service": port_record.get("service", "Unknown"),
        "port_state": port_record.get("state", "Open"),
        "exposure_level": port_record.get("exposure_level", "External"),
        "banner_flags": port_record.get("banner", "None") or "None",
        "port": int(port_record.get("port", 80)),
        "service_version_risk": float(port_record.get("service_version_risk", 0.5)),
        "known_vuln_indicator": int(1 if port_record.get("known_vuln_indicator") else 0),
        "cvss_baseline": float(port_record.get("cvss_score", 5.0)),
        "encryption_detected": int(1 if port_record.get("encryption_detected") else 0)
    }])

    pred = model.predict(input_df)[0]
    probs = model.predict_proba(input_df)[0]
    classes = list(model.classes_)
    
    # Extract predicted class probability
    pred_idx = classes.index(pred)
    confidence = float(probs[pred_idx])

    prob_dict = {cls_name: round(float(prob), 4) for cls_name, prob in zip(classes, probs)}
    return pred, round(confidence, 2), prob_dict

if __name__ == "__main__":
    train_and_save_model()
