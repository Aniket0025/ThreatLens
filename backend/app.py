"""
app.py — URLShield Flask application entry point.
Registers blueprints, extensions, and global error handlers.
"""

import logging
import os
import json

import joblib
import pandas as pd
from flask import Flask, jsonify
from flask_cors import CORS
from flask import send_from_directory
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

from config import Config
from feature_extraction import extract_features

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=getattr(logging, Config.LOG_LEVEL, logging.INFO),
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("urlshield")

# ---------------------------------------------------------------------------
# Load ML model once at startup
# ---------------------------------------------------------------------------
def _load_model():
    path = Config.MODEL_PATH
    if not os.path.exists(path):
        alt_path = os.path.join(os.path.dirname(__file__), path)
        if os.path.exists(alt_path):
            path = alt_path
        else:
            logger.error("Model file not found: %s", path)
            raise FileNotFoundError(f"Model file not found: {path}")
    obj = joblib.load(path)
    if not (isinstance(obj, tuple) and len(obj) == 2):
        raise ValueError("Model file must contain a (model, feature_columns) tuple.")
    model, feature_columns = obj
    logger.info("Model loaded from %s — %d features", path, len(feature_columns))
    return model, list(feature_columns)


def _load_metrics():
    path = Config.METRICS_PATH
    if not os.path.exists(path):
        alt_path = os.path.join(os.path.dirname(__file__), path)
        if os.path.exists(alt_path):
            path = alt_path
    if os.path.exists(path):
        with open(path) as f:
            return json.load(f)
    return {}


try:
    MODEL, FEATURE_COLUMNS = _load_model()
    MODEL_METRICS = _load_metrics()
    MODEL_LOADED = True
except Exception as exc:
    logger.critical("Failed to load model at startup: %s", exc)
    MODEL = None
    FEATURE_COLUMNS = []
    MODEL_METRICS = {}
    MODEL_LOADED = False

# ---------------------------------------------------------------------------
# Flask app + extensions
# ---------------------------------------------------------------------------
app = Flask(__name__)
app.config["SECRET_KEY"] = Config.SECRET_KEY

CORS(app, origins=Config.ALLOWED_ORIGINS)

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=[Config.RATE_LIMIT_DEFAULT],
    storage_uri="memory://",
)

# ---------------------------------------------------------------------------
# Prediction helpers
# ---------------------------------------------------------------------------

from feature_extraction import extract_features, SUSPICIOUS_KEYWORDS, BRAND_KEYWORDS


def _generate_explanations(url_features: dict, risk_score: float, prediction: str) -> list[str]:
    """Rule-based human-readable explanations grounded in extracted features."""
    explanations = []

    url_length = int(url_features.get("URLLength", 0) or 0)
    entropy = float(url_features.get("URLEntropy", 0) or 0)
    no_subdomains = int(url_features.get("NoOfSubDomain", 0) or 0)
    domain_digits = int(url_features.get("_domain_digits", 0) or 0)
    hyphens = int(url_features.get("NoOfHyphensInURL", 0) or 0)
    is_ip = int(url_features.get("IsIPAddress", 0) or 0)
    has_punycode = int(url_features.get("HasPunycode", 0) or 0)
    suspicious_tld = int(url_features.get("IsSuspiciousTLD", 0) or 0)
    brand_subdomain = int(url_features.get("BrandInSubdomain", 0) or 0)
    at_sign = int(url_features.get("HasAtSign", 0) or 0)
    hex_encoding = int(url_features.get("HasHexEncoding", 0) or 0)
    kw_found = url_features.get("_suspicious_keywords_found") or []
    kw_found = [str(k) for k in kw_found][:3]
    is_https = int(url_features.get("IsHTTPS", 0) or 0)

    if is_ip:
        explanations.append("URL uses a raw IP address instead of a domain name — a common phishing technique.")
    if has_punycode:
        explanations.append("Punycode encoding detected; domain may be impersonating a well-known brand.")
    if brand_subdomain:
        explanations.append("A trusted brand name appears in the subdomain or spoofed domain — a strong spoofing signal.")
    if url_length > 110 and prediction.lower() != "safe":
        explanations.append(f"URL is unusually long ({url_length} chars); phishing URLs are often obfuscated with extra path segments.")
    if entropy > 4.7 and prediction.lower() != "safe":
        explanations.append(f"High URL entropy ({entropy:.2f}) suggests random or obfuscated characters.")
    if no_subdomains > 2:
        explanations.append(f"{no_subdomains} subdomain levels detected; excessive subdomains can mask the real domain.")
    if kw_found and prediction.lower() != "safe":
        explanations.append(f"Phishing-related keyword(s) found: {', '.join(kw_found)}.")
    if suspicious_tld:
        explanations.append("The top-level domain (TLD) is commonly associated with spam or phishing.")
    if domain_digits > 0 and prediction.lower() != "safe":
        explanations.append("Digits in the domain name can indicate a dynamically generated or fake domain.")
    if hyphens > 3:
        explanations.append("Excessive hyphens in the URL are used to mimic legitimate domain names.")
    if at_sign:
        explanations.append("@ symbol detected in the URL; everything before @ is ignored by browsers, used to mislead.")
    if hex_encoding:
        explanations.append("Heavy percent-encoding detected, which can obfuscate malicious path segments.")
    if not is_https and prediction.lower() != "safe":
        explanations.append("Connection is not encrypted (HTTP), increasing risk of credential interception.")

    # Positive signals for safe URLs
    if prediction.lower() == "safe":
        if is_https:
            explanations.append("URL uses HTTPS — encrypted connection.")
        if no_subdomains <= 1:
            explanations.append("Domain structure appears clean and straightforward.")
        explanations.append("No brand spoofing, punycode, or raw IP address anomalies detected.")
        explanations.append("Character ratios and entropy are consistent with legitimate web destinations.")

    if risk_score >= 0.70:
        explanations.append("ML model assigns high malicious probability — treat this link with extreme caution.")
    elif risk_score >= 0.40:
        explanations.append("ML model assigns moderate risk — verify the domain and sender before proceeding.")
    else:
        explanations.append("ML model assigns low risk — no strong phishing patterns detected in the URL.")

    return explanations[:8]


def _run_prediction(url: str) -> dict:
    """Core prediction logic. Returns the full result dict."""
    url_features = extract_features(url)

    # Build aligned feature vector (only model input columns, in training order)
    row = {col: url_features.get(col, 0) for col in FEATURE_COLUMNS}
    features_df = pd.DataFrame([row], columns=FEATURE_COLUMNS)

    # Malicious probability
    class_list = list(getattr(MODEL, "classes_", []))
    malicious_idx = class_list.index(0) if 0 in class_list else 0
    prob = float(MODEL.predict_proba(features_df)[0][malicious_idx])

    # Dynamic security rule overrides:
    # 1. Unencrypted HTTP requesting credential actions (login, banking, password, verify)
    if int(url_features.get("IsHTTPS", 0)) == 0 and int(url_features.get("SuspiciousKeywordCount", 0)) > 0:
        prob = max(prob, 0.78)

    # 2. Raw IP address or brand spoofing or punycode:
    if (
        int(url_features.get("BrandInSubdomain", 0)) == 1
        or int(url_features.get("HasPunycode", 0)) == 1
        or int(url_features.get("IsIPAddress", 0)) == 1
    ):
        prob = max(prob, 0.85)

    # Calibrated decision thresholds
    if prob >= 0.70:
        prediction, risk_level = "Malicious", "Critical"
    elif prob >= 0.40:
        prediction, risk_level = "Suspicious", "Medium"
    else:
        prediction, risk_level = "Safe", "Low"

    explanations = _generate_explanations(url_features, prob, prediction)

    # Build feature display dict (strip _ prefixed keys)
    feature_display = {
        k: v for k, v in url_features.items() if not k.startswith("_")
    }

    logger.info("Prediction: url=%s prediction=%s score=%.3f", url[:80], prediction, prob)

    return {
        "prediction": prediction,
        "risk_score": round(prob, 4),
        "risk_level": risk_level,
        "confidence": round(prob * 100, 2),
        "explanations": explanations,
        "reasons": explanations,          # backward compat
        "features": feature_display,      # feature analysis for UI
    }


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route("/")
def home():
    frontend_dir = os.path.join(os.path.dirname(__file__), "..", "frontend")
    frontend_dir = os.path.abspath(frontend_dir)
    if os.path.exists(os.path.join(frontend_dir, "index.html")):
        return send_from_directory(frontend_dir, "index.html")
    return jsonify({
        "service": "URLShield API",
        "version": Config.API_VERSION,
        "status": "running",
        "model_loaded": MODEL_LOADED,
    })


@app.route("/<path:filename>")
def frontend_static(filename):
    frontend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "frontend"))
    return send_from_directory(frontend_dir, filename)


@app.route("/health")
def health():
    return jsonify({
        "status": "ok" if MODEL_LOADED else "degraded",
        "model_loaded": MODEL_LOADED,
        "version": Config.API_VERSION,
    }), (200 if MODEL_LOADED else 503)


@app.route("/api/v1/metrics")
def metrics():
    """Return model training metrics (accuracy, F1, etc.)."""
    if not MODEL_METRICS:
        return jsonify({"error": "Metrics not available."}), 404
    return jsonify(MODEL_METRICS)


@app.route("/predict", methods=["POST"])
@app.route("/api/v1/predict", methods=["POST"])
@limiter.limit(Config.RATE_LIMIT_PREDICT)
def predict():
    from flask import request

    if not MODEL_LOADED:
        return jsonify({"error": "Model not loaded. Check server logs."}), 503

    data = request.get_json(silent=True) or {}
    url = (data.get("url") or "").strip()

    # --- Input validation ---
    if not url:
        return jsonify({"error": "Missing 'url' in request body."}), 400
    if len(url) > 2048:
        return jsonify({"error": "URL exceeds maximum length of 2048 characters."}), 400
    if not any(url.startswith(s) for s in ("http://", "https://", "ftp://")) and "://" not in url:
        # Allow schemeless — feature extractor prepends http://
        pass

    try:
        result = _run_prediction(url)
        return jsonify(result)
    except Exception as exc:
        logger.exception("Prediction failed for url=%s", url[:80])
        return jsonify({"error": "Prediction failed. Please try again."}), 500


# ---------------------------------------------------------------------------
# Global error handlers
# ---------------------------------------------------------------------------

@app.errorhandler(404)
def not_found(e):
    return jsonify({"error": "Endpoint not found."}), 404


@app.errorhandler(405)
def method_not_allowed(e):
    return jsonify({"error": "Method not allowed."}), 405


@app.errorhandler(429)
def rate_limit_exceeded(e):
    return jsonify({"error": "Rate limit exceeded. Please slow down."}), 429


@app.errorhandler(500)
def internal_error(e):
    logger.error("Unhandled server error: %s", e)
    return jsonify({"error": "Internal server error."}), 500


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 5000)),
        debug=Config.DEBUG,
    )
