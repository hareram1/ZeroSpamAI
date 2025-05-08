# app.py
from flask import Flask, render_template, request, session
import pandas as pd
import tldextract
import re
import json
import joblib
import logging
import os
import shap
from datetime import datetime
from collections import Counter
import pdfkit
from utils.whois_utils import get_domain_age, get_whois_summary

app = Flask(__name__)
app.secret_key = os.urandom(24)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

try:
    model = joblib.load("models/best_model.pkl")
    logger.info("Model loaded successfully")

    with open("models/feature_order.json", "r") as f:
        FEATURE_ORDER = json.load(f)
    logger.info(f"Feature order loaded: {FEATURE_ORDER}")

except Exception as e:
    logger.error(f"Initialization failed: {str(e)}")
    raise


def extract_features(url):
    try:
        if not re.match(r"^https?://", url, re.IGNORECASE):
            url = f"http://{url}"
            logger.info(f"Normalized URL: {url}")

        extracted = tldextract.extract(url)

        features = {
            "url_length": float(len(url)),
            "has_https": 1.0 if url.startswith("https://") else 0.0,
            "num_subdomains": float(len(extracted.subdomain.split('.'))) if extracted.subdomain else 0.0,
            "has_special_char": 1.0 if any(c in url for c in ['@', '-', '_']) else 0.0,
            "is_shortened": 1.0 if any(s in url for s in ["bit.ly", "tinyurl", "goo.gl"]) else 0.0,
            "domain_age": float(get_domain_age(url)),
            "contains_ip": 1.0 if re.match(r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", url) else 0.0,
            "has_port": 1.0 if re.search(r":\d{2,5}/", url) else 0.0,
            "suspicious_tld": 1.0 if any(tld in f".{extracted.suffix}" 
                                         for tld in ['.xyz','.top','.loan','.click','.gq','.tk']) else 0.0
        }

        df = pd.DataFrame([features], columns=FEATURE_ORDER)
        return df

    except Exception as e:
        logger.error(f"Feature extraction failed: {str(e)}")
        raise


@app.route("/", methods=["GET", "POST"])
def home():
    result = None
    domain_age = None
    risk_factors = []
    whois_summary = {}
    top_features = []

    if request.method == "POST":
        raw_url = request.form.get("url", "").strip()
        logger.info(f"Received URL input: {raw_url}")

        if raw_url:
            try:
                url = raw_url.lower()
                if not url.startswith(('http://', 'https://')):
                    url = f'http://{url}'

                features_df = extract_features(url)
                prediction = model.predict(features_df)[0]
                confidence = round(model.predict_proba(features_df)[0][1] * 100, 2)

                features = features_df.iloc[0].to_dict()

                if features['contains_ip'] == 1.0:
                    risk_factors.append("Contains IP address")
                if features['has_port'] == 1.0:
                    risk_factors.append("Uses non-standard port")
                if features['suspicious_tld'] == 1.0:
                    risk_factors.append("Suspicious TLD detected")
                if features['domain_age'] < 30:
                    risk_factors.append(f"New domain ({int(features['domain_age'])} days old)")
                if features['is_shortened'] == 1.0:
                    risk_factors.append("URL shortening service detected")

                result = {
                    "label": "⚠️ Phishing URL Detected!" if prediction == 1 else "✅ Legitimate URL",
                    "confidence": confidence
                }

                domain_age = int(features['domain_age']) if features['domain_age'] != 730.0 else None
                whois_summary = get_whois_summary(url)

                scan_entry = {
                    "url": raw_url,
                    "label": result["label"],
                    "confidence": confidence,
                    "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                }

                if "history" not in session:
                    session["history"] = []
                session["history"].insert(0, scan_entry)
                session["history"] = session["history"][:5]

                session["whois"] = whois_summary
                session["risks"] = risk_factors

                if "all_risks" not in session:
                    session["all_risks"] = []
                session["all_risks"].extend(risk_factors)

            except Exception as e:
                result = {"label": f"❌ Processing Error: {str(e)}", "confidence": 0}
                logger.error(f"Processing failed for URL '{raw_url}': {str(e)}")
        else:
            result = {"label": "⚠️ Please enter a URL!", "confidence": 0}
            logger.warning("Empty URL submitted")

    return render_template(
        "index.html",
        result=result,
        domain_age=domain_age,
        risk_factors=risk_factors,
        whois_summary=whois_summary,
        top_features=top_features,
        history=session.get("history", [])
    )


@app.route("/analytics")
def analytics():
    history = session.get("history", [])

    phishing_count = sum(1 for h in history if "Phishing" in h["label"])
    legit_count = len(history) - phishing_count

    all_risks = session.get("all_risks", [])
    risk_counts = dict(Counter(all_risks))

    timestamps = [h["timestamp"] for h in history]
    confidences = [h["confidence"] for h in history]

    return render_template("analytics.html",
                           phishing=phishing_count,
                           legit=legit_count,
                           risk_counts=risk_counts,
                           timestamps=timestamps,
                           confidences=confidences)


@app.route("/download-report")
def download_report():
    latest = session.get("history", [])[0] if "history" in session else None
    whois_summary = session.get("whois", {})
    risk_factors = session.get("risks", [])

    if not latest:
        return "No scan data available", 404

    try:
        rendered = render_template("pdf_template.html",
                                   result=latest,
                                   whois=whois_summary,
                                   risks=risk_factors)

        config = pdfkit.configuration(wkhtmltopdf=r"C:\Program Files\wkhtmltopdf\bin\wkhtmltopdf.exe")
        pdf = pdfkit.from_string(rendered, False, configuration=config)
        response = app.response_class(pdf, mimetype='application/pdf')
        response.headers['Content-Disposition'] = 'attachment; filename=scan_report.pdf'
        return response

    except Exception as e:
        logger.error(f"PDF generation failed: {e}")
        return f"PDF generation failed: {e}", 500


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000, debug=True)
