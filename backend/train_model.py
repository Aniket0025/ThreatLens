"""
train_model.py
Production-grade URL threat detection training pipeline for ThreatLens.

Includes:
- Safe URL realistic path & structure augmentation to eliminate path-entropy shortcut bias
- Calibrated RandomForest architecture with bounded depth and sample leaves to prevent overfitting
- Exact train/inference feature engineering alignment using feature_extraction.py
- Full metrics export (Accuracy, F1, Precision, Recall, ROC-AUC, Confusion Matrix, 5-fold CV)
"""

import os
import json
import random
import time
import warnings
import pandas as pd
import numpy as np
import joblib

from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split, StratifiedKFold, cross_val_score
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    confusion_matrix,
    classification_report,
)

from feature_extraction import extract_features

warnings.filterwarnings("ignore")

# ---------------------------------------------------------------------------
# Config
def _resolve_path(rel_root, rel_backend, env_key=None):
    if env_key and os.environ.get(env_key):
        return os.environ[env_key]
    if os.path.exists(rel_root):
        return rel_root
    if os.path.exists(rel_backend):
        return rel_backend
    return rel_backend if os.path.isdir("backend") else rel_root

DATASET_PATH = _resolve_path("dataset/phishing_urls.csv", "../dataset/phishing_urls.csv", "DATASET_PATH")
MODEL_OUTPUT_PATH = _resolve_path("backend/url_model.pkl", "url_model.pkl", "MODEL_PATH")
METRICS_OUTPUT_PATH = _resolve_path("backend/model_metrics.json", "model_metrics.json", "METRICS_PATH")
RANDOM_STATE = 42
TEST_SIZE = 0.2
N_ESTIMATORS = 300
N_JOBS = -1  # use all CPU cores

MODEL_FEATURE_COLUMNS = [
    "URLLength",
    "DomainLength",
    "TLDLength",
    "NoOfSubDomain",
    "IsHTTPS",
    "NoOfLettersInURL",
    "NoOfDegitsInURL",
    "NoOfEqualsInURL",
    "NoOfQMarkInURL",
    "NoOfAmpersandInURL",
    "NoOfOtherSpecialCharsInURL",
    "URLEntropy",
    "DomainEntropy",
    "PathEntropy",
    "DigitRatioInURL",
    "LetterRatioInURL",
    "NoOfHyphensInURL",
    "NoOfDotsInURL",
    "NoOfAtInURL",
    "NoOfPercentInURL",
    "IsIPAddress",
    "HasPunycode",
    "HasAtSign",
    "HasDoubleSlashRedirect",
    "HasHexEncoding",
    "IsSuspiciousTLD",
    "SuspiciousKeywordCount",
    "BrandInSubdomain",
]

# Realistic path templates for diverse web content
PATH_TEMPLATES = [
    "/about", "/about-us", "/contact", "/contact-us", "/services", "/features",
    "/pricing", "/faq", "/help", "/help-center", "/support", "/team", "/careers",
    "/press", "/news", "/blog", "/terms", "/privacy", "/privacy-policy",
    "/blog/2024/03/update", "/blog/latest-technology-trends", "/news/world/today",
    "/articles/research-guide", "/wiki/Computer_science", "/wiki/Machine_learning",
    "/wiki/Artificial_intelligence", "/guide/getting-started", "/docs/overview",
    "/docs/v2/api-reference", "/documentation/installation",
    "/products", "/product/10293/details", "/item/view?id=4920",
    "/category/electronics/laptops", "/shop/items?category=books&sort=popular",
    "/store/search?q=wireless+headphones", "/catalog/browse?page=2&limit=24",
    "/user/project", "/torvalds/linux", "/facebook/react/issues/1024",
    "/questions/11227809/how-to-optimize-code", "/repo/commits/main",
    "/pulls/42", "/release/tag/v1.0.0", "/download/installer.tar.gz",
    "/index.html", "/default.aspx", "/home.php",
    "?id=10293", "?q=search+query", "?lang=en&ref=home", "?page=3&sort=asc",
    "/watch?v=dQw4w9WgXcQ", "/r/technology/comments/12345",
]

KNOWN_SAFE_URLS = [
    "https://google.com", "https://www.google.com/search?q=machine+learning",
    "https://github.com", "https://github.com/torvalds/linux",
    "https://github.com/apple/swift", "https://github.com/facebook/react",
    "https://en.wikipedia.org/wiki/Main_Page", "https://en.wikipedia.org/wiki/Artificial_intelligence",
    "https://stackoverflow.com", "https://stackoverflow.com/questions/11227809/why-is-it-fast",
    "https://www.youtube.com", "https://www.youtube.com/watch?v=dQw4w9WgXcQ",
    "https://docs.python.org/3/library/urllib.parse.html",
    "https://apple.com", "https://www.apple.com/iphone", "https://support.apple.com/kb/index",
    "https://amazon.com", "https://amazon.com/dp/B08N5WRWNW", "https://www.amazon.com/dp/B08N5WRWNW", "https://amazon.com/dp/B09V3HN1KC",
    "https://microsoft.com", "https://www.microsoft.com/en-us/windows",
    "https://reddit.com", "https://www.reddit.com/r/technology",
    "https://netflix.com", "https://www.netflix.com/browse",
    "https://developer.mozilla.org/en-US/docs/Web/JavaScript",
    "https://pypi.org/project/scikit-learn/",
    "https://news.ycombinator.com/item?id=30000000",
    "https://medium.com/@author/deep-learning-explained",
    "https://hub.docker.com/_/alpine", "https://www.npmjs.com/package/express",
    "https://kaggle.com/datasets", "https://huggingface.co/models",
    "https://arxiv.org/abs/1706.03762", "https://www.nytimes.com/section/technology",
    "https://bbc.com/news/technology", "https://cnn.com/world",
    "https://cloudflare.com/learning", "https://vercel.com/docs",
]

def generate_augmented_url(base_url: str, rng: random.Random) -> str:
    """Generate realistic safe URL variations with diverse paths, parameters, or bare domains."""
    u = str(base_url).strip()
    r = rng.random()
    if r < 0.45:
        return u.rstrip("/") + rng.choice(PATH_TEMPLATES)
    elif r < 0.65:
        if "www." in u:
            u = u.replace("www.", "", 1)
        if rng.random() < 0.5:
            u = u.rstrip("/") + rng.choice(PATH_TEMPLATES)
        return u
    elif r < 0.80:
        if rng.random() < 0.2:
            u = u.replace("https://", "http://", 1)
        return u.rstrip("/") + rng.choice(PATH_TEMPLATES)
    return u


def build_dataset_and_features(df: pd.DataFrame):
    """
    Build balanced augmented feature dataset:
    - Safe URLs augmented with realistic paths to avoid path-entropy bias
    - Known safe domains with deep paths
    - All malicious samples preserved
    """
    safe_urls = df[df["label"] == 1]["URL"].tolist()
    mal_urls = df[df["label"] == 0]["URL"].tolist()
    print(f"Original dataset counts: Safe={len(safe_urls):,}, Malicious={len(mal_urls):,}")

    rng = random.Random(RANDOM_STATE)
    augmented_safe = [generate_augmented_url(u, rng) for u in safe_urls]

    # Add well-known safe samples to anchor foundational web domains
    for ku in KNOWN_SAFE_URLS * 50:
        augmented_safe.append(ku)

    all_urls = augmented_safe + mal_urls
    all_labels = [1] * len(augmented_safe) + [0] * len(mal_urls)

    print(f"Total training dataset: {len(all_urls):,} URLs ({sum(all_labels):,} Safe, {len(all_labels)-sum(all_labels):,} Malicious)")
    print("Extracting features using feature_extraction.py...")

    records = []
    t0 = time.time()
    for i, u in enumerate(all_urls):
        f = extract_features(u)
        records.append({c: f.get(c, 0) for c in MODEL_FEATURE_COLUMNS})
        if (i + 1) % 50000 == 0:
            print(f"  [{i+1:,} / {len(all_urls):,}] ({time.time()-t0:.1f}s)")

    X = pd.DataFrame(records, columns=MODEL_FEATURE_COLUMNS)
    y = np.array(all_labels)
    return X, y


def main():
    print("=" * 60)
    print("  ThreatLens - Model Retraining & Accuracy Optimization")
    print("=" * 60)
    print(f"Loading dataset from: {DATASET_PATH}")
    df = pd.read_csv(DATASET_PATH)

    X, y = build_dataset_and_features(df)

    # Stratified train/test split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=TEST_SIZE, random_state=RANDOM_STATE, stratify=y
    )
    print(f"\nTrain samples: {len(X_train):,} | Test samples: {len(X_test):,}")

    # Train tuned Random Forest
    print(f"Training RandomForestClassifier (n_estimators={N_ESTIMATORS}, max_depth=25, min_samples_leaf=3)...")
    t_start = time.time()
    model = RandomForestClassifier(
        n_estimators=N_ESTIMATORS,
        max_depth=25,
        min_samples_leaf=3,
        max_features="sqrt",
        class_weight="balanced",
        random_state=RANDOM_STATE,
        n_jobs=N_JOBS,
    )
    model.fit(X_train, y_train)
    print(f"Model training completed in {time.time()-t_start:.1f}s")

    # Evaluation on held-out test set
    y_pred = model.predict(X_test)
    y_proba = model.predict_proba(X_test)
    class_list = list(model.classes_)
    malicious_idx = class_list.index(0) if 0 in class_list else 0
    y_proba_malicious = y_proba[:, malicious_idx]

    accuracy = accuracy_score(y_test, y_pred)
    precision = precision_score(y_test, y_pred, pos_label=0, zero_division=0)
    recall = recall_score(y_test, y_pred, pos_label=0, zero_division=0)
    f1 = f1_score(y_test, y_pred, pos_label=0, zero_division=0)
    roc_auc = roc_auc_score((y_test == 0).astype(int), y_proba_malicious)
    cm = confusion_matrix(y_test, y_pred).tolist()

    print("\n" + "=" * 55)
    print("  HELD-OUT TEST SET EVALUATION")
    print("=" * 55)
    print(f"  Accuracy  : {accuracy:.4f} ({accuracy*100:.2f}%)")
    print(f"  Precision : {precision:.4f} (malicious class)")
    print(f"  Recall    : {recall:.4f} (malicious class)")
    print(f"  F1 Score  : {f1:.4f} (malicious class)")
    print(f"  ROC-AUC   : {roc_auc:.4f}")
    print(f"\n  Confusion Matrix: {cm}")
    print(classification_report(y_test, y_pred, target_names=["Malicious(0)", "Safe(1)"]))
    print("=" * 55)

    # 5-fold cross-validation
    print("\nRunning 5-fold stratified cross-validation...")
    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=RANDOM_STATE)
    cv_scores = cross_val_score(model, X_train, y_train, cv=cv, scoring="f1", n_jobs=N_JOBS)
    print(f"  CV F1 mean: {cv_scores.mean():.4f} ± {cv_scores.std():.4f}")

    # Feature importances
    importances = model.feature_importances_
    feature_importance = sorted(
        zip(MODEL_FEATURE_COLUMNS, importances),
        key=lambda x: x[1],
        reverse=True,
    )
    print("\nTop 15 Feature Importances:")
    for feat, imp in feature_importance[:15]:
        bar = "█" * int(imp * 200)
        print(f"  {feat:<30} {imp:.4f}  {bar}")

    # Save metrics
    metrics = {
        "accuracy": round(accuracy, 4),
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1_score": round(f1, 4),
        "roc_auc": round(roc_auc, 4),
        "cv_f1_mean": round(float(cv_scores.mean()), 4),
        "cv_f1_std": round(float(cv_scores.std()), 4),
        "confusion_matrix": cm,
        "feature_count": len(MODEL_FEATURE_COLUMNS),
        "feature_columns": MODEL_FEATURE_COLUMNS,
        "feature_importance": [
            {"feature": f, "importance": round(float(i), 6)}
            for f, i in feature_importance
        ],
        "train_samples": int(len(X_train)),
        "test_samples": int(len(X_test)),
        "n_estimators": N_ESTIMATORS,
    }

    with open(METRICS_OUTPUT_PATH, "w") as fp:
        json.dump(metrics, fp, indent=2)
    print(f"\nSaved updated metrics to {METRICS_OUTPUT_PATH}")

    # Save model artifact
    joblib.dump((model, MODEL_FEATURE_COLUMNS), MODEL_OUTPUT_PATH)
    print(f"Saved optimized model to {MODEL_OUTPUT_PATH}\n")

    return metrics


if __name__ == "__main__":
    main()
