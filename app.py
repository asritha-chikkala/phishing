from flask import Flask, request, jsonify
from flask_cors import CORS
import pickle
import re
import numpy as np
from urllib.parse import urlparse
import shap


app = Flask(__name__)
CORS(app)

email_model   = pickle.load(open('email_model.pkl',      'rb'))
vectorizer    = pickle.load(open('email_vectorizer.pkl', 'rb'))
website_model = pickle.load(open('website_model.pkl',   'rb'))

EMAIL_PHISHING_IDX = list(email_model.classes_).index(1)

def _detect_website_phishing_idx():
    test_url = "http://free-win-bonus-verify.xyz/login/account/bank"
    parsed   = urlparse(test_url)
    domain   = parsed.netloc.lower()
    url_l    = test_url.lower()
    suspicious_words = ["login","secure","bank","verify","account","update","free","bonus","win","signin","confirm"]
    suspicious_tlds  = ['.xyz','.tk','.ml','.ga','.cf','.gq']
    feat = [[
        len(url_l), url_l.count('.'), url_l.count('-'), url_l.count('@'),
        url_l.count('?'), url_l.count('='), len(domain), len(parsed.path),
        0, 0,
        sum(url_l.count(w) for w in suspicious_words),
        0, 0, 0, 0,
        sum(c.isdigit() for c in url_l),
        len(parsed.path)/len(url_l),
        1 if any(tld in domain for tld in suspicious_tlds) else 0,
        url_l.count("http"),
    ]]
    proba = website_model.predict_proba(feat)[0]
    idx   = int(np.argmax(proba))
    print(f"[STARTUP] website_model.classes_: {website_model.classes_}")
    print(f"[STARTUP] WEBSITE_PHISHING_IDX = {idx}  proba={proba}")
    return idx

WEBSITE_PHISHING_IDX = _detect_website_phishing_idx()

URL_FEATURE_NAMES = [
    "URL Length",         "Dot Count",          "Hyphen Count",        "@ Symbol",
    "Query Params (?)",   "Equal Signs (=)",     "Domain Length",       "Path Length",
    "HTTPS",              "IP Address",          "Suspicious Keywords", "Double Slash in Path",
    "Hyphen in Domain",   "Many Subdomains",     "Digits in Domain",    "Digits in URL",
    "Path Ratio",         "Suspicious TLD",      "HTTP Count"
]

KNOWN_DOMAINS = [
    "google.com",     "facebook.com",   "paypal.com",      "apple.com",
    "microsoft.com",  "amazon.com",     "netflix.com",     "instagram.com",
    "twitter.com",    "linkedin.com",   "youtube.com",     "github.com",
    "dropbox.com",    "spotify.com",    "yahoo.com",       "chase.com",
    "wellsfargo.com", "citibank.com",   "hsbc.com",        "bankofamerica.com"
]


SAFE_PATTERNS = [
    r"connection request",
    r"new connection",
    r"has been shipped",
    r"your order",
    r"order confirmation",
    r"tracking number",
    r"standup meeting",
    r"meeting (at|on|tomorrow|scheduled)",
    r"please find attached",
    r"project update",
    r"pull request",
    r"noreply.{0,5}linkedin",
    r"linkedin.{0,10}connection",
    r"sender.*linkedin",
    r"noreply.{0,5}github",
    r"noreply.{0,5}amazon",
    r"noreply.{0,5}spotify",
    r"noreply.{0,5}google",
    r"noreply.{0,5}microsoft",
    r"calendar invite",
    r"team standup",
    r"weekly update",
    r"reminder.*meeting",
    r"meeting.*reminder",
]

PHISHING_PATTERNS = [
    r"click here.*(claim|prize|win|reward|bonus|verify|account)",
    r"(won|winner|selected|chosen).*(prize|reward|iphone|cash|dollar)",
    r"(verify|confirm|update).*(account|bank|password|credential)",
    r"account.*(suspended|compromised|locked|disabled|blocked)",
    r"(urgent|immediate).*(action|verify|login|click)",
    r"free (bonus|gift|iphone|reward|prize)",
    r"(bank|paypal|payoneer).*(compromised|suspended|verify)",
    r"password.*(expired|reset|update).*(avoid|prevent|suspension)",
]

def check_safe_patterns(text):
    t = text.lower()
    for p in SAFE_PATTERNS:
        if re.search(p, t):
            return True
    return False

def check_phishing_patterns(text):
    t = text.lower()
    for p in PHISHING_PATTERNS:
        if re.search(p, t):
            return True
    return False

def clean_text(text):
    text = str(text).lower()
    text = re.sub(r"http\S+|www\.\S+", " url ", text)
    text = re.sub(r"\S+@\S+", " emailaddr ", text)
    text = re.sub(r"\b\d+\b", " num ", text)
    text = re.sub(r"[^a-z\s]", " ", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text

def levenshtein(s1, s2):
    if len(s1) < len(s2): return levenshtein(s2, s1)
    if len(s2) == 0: return len(s1)
    prev = range(len(s2) + 1)
    for c1 in s1:
        curr = [prev[0] + 1]
        for j, c2 in enumerate(s2):
            curr.append(min(prev[j+1]+1, curr[j]+1, prev[j]+(c1!=c2)))
        prev = curr
    return prev[-1]

def check_typosquat(domain):
    domain = domain.lower().replace("www.", "").split(":")[0]
    for legit in KNOWN_DOMAINS:
        if domain == legit: return None
        if 1 <= levenshtein(domain, legit) <= 2: return legit
    return None

def extract_urls_from_email(text):
    return re.findall(r'https?://[^\s<>"\']+', text)

def extract_features(url):
    parsed = urlparse(url)
    domain = parsed.netloc.lower()
    path   = parsed.path.lower()
    url_l  = url.lower()
    suspicious_words = ["login","secure","bank","verify","account","update","free","bonus","win","signin","confirm"]
    suspicious_tlds  = ['.xyz','.tk','.ml','.ga','.cf','.gq']
    return [[
        len(url_l), url_l.count('.'), url_l.count('-'), url_l.count('@'),
        url_l.count('?'), url_l.count('='), len(domain), len(path),
        1 if parsed.scheme == 'https' else 0,
        1 if domain.replace('.','').isdigit() else 0,
        sum(url_l.count(w) for w in suspicious_words),
        1 if "//" in path else 0,
        1 if "-" in domain else 0,
        1 if domain.count('.') > 3 else 0,
        sum(c.isdigit() for c in domain),
        sum(c.isdigit() for c in url_l),
        len(path)/len(url_l) if len(url_l) > 0 else 0,
        1 if any(tld in domain for tld in suspicious_tlds) else 0,
        url_l.count("http"),
    ]]

def get_confidence(score):
    if score > 80:   return "High"
    elif score > 50: return "Medium"
    else:            return "Low"

def get_url_shap(features):
    try:
      
        base      = website_model.calibrated_classifiers_[0].estimator
        explainer = shap.TreeExplainer(base)
        sv        = explainer.shap_values(np.array(features))
        vals      = sv[1][0] if isinstance(sv, list) else sv[0]
        pairs     = sorted(zip(URL_FEATURE_NAMES, vals), key=lambda x: abs(x[1]), reverse=True)[:5]
        return [{"feature": f, "impact": round(float(v), 4)} for f, v in pairs]
    except Exception:
        return []

def get_email_explanation(vec, prob):
    try:
        arr           = vec.toarray()[0]
        feature_names = vectorizer.get_feature_names_out()
        active = [(feature_names[i], float(arr[i])) for i in range(len(arr)) if arr[i] > 0]
        active.sort(key=lambda x: x[1], reverse=True)
        direction = 1 if prob > 0.5 else -1
        return [{"feature": f, "impact": round(v * direction, 4)} for f, v in active[:5]]
    except Exception:
        return []


@app.route('/')
def home():
    return "🚀 Phishing Detection API Running"

@app.route('/predict_url', methods=['POST'])
def predict_url():
    try:
        url = request.json.get('url', '').strip()
        if not url:
            return jsonify({"error": "URL cannot be empty"}), 400
        if not url.startswith("http"):
            return jsonify({"error": "URL must start with http/https"}), 400

        domain       = urlparse(url).netloc.lower().replace("www.", "").split(":")[0]
        typosquat_of = check_typosquat(domain)
        features     = extract_features(url)
        prob         = website_model.predict_proba(features)[0][WEBSITE_PHISHING_IDX]
        risk_score   = round(prob * 100, 2)
        label        = "Phishing" if prob > 0.5 else "Safe"

        if typosquat_of:
            label      = "Phishing"
            risk_score = max(risk_score, 85.0)

        return jsonify({
            "type":        "url",
            "prediction":  label,
            "risk_score":  risk_score,
            "confidence":  get_confidence(risk_score),
            "typosquat":   typosquat_of,
            "explanation": get_url_shap(features)
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/predict_email', methods=['POST'])
def predict_email():
    try:
        text = request.json.get('text', '').strip()
        if not text:
            return jsonify({"error": "Email input cannot be empty"}), 400

        # Scan embedded URLs
        embedded_urls    = extract_urls_from_email(text)
        url_scan_results = []
        url_risk_boost   = 0.0

        for u in embedded_urls[:5]:
            try:
                d            = urlparse(u).netloc.lower().replace("www.", "").split(":")[0]
                typosquat_of = check_typosquat(d)
                feats        = extract_features(u)
                u_prob       = website_model.predict_proba(feats)[0][WEBSITE_PHISHING_IDX]
                u_score      = round(u_prob * 100, 2)
                u_label      = "Phishing" if u_prob > 0.5 or typosquat_of else "Safe"
                if typosquat_of:
                    u_score = max(u_score, 85.0)
                url_scan_results.append({
                    "url": u, "prediction": u_label,
                    "risk_score": u_score, "typosquat": typosquat_of
                })
                if u_label == "Phishing":
                    url_risk_boost = max(url_risk_boost, u_score / 100)
            except Exception:
                pass

        # Rule-based override — phishing patterns
        if check_phishing_patterns(text):
            vec        = vectorizer.transform([clean_text(text)])
            prob       = email_model.predict_proba(vec)[0][EMAIL_PHISHING_IDX]
            prob       = max(prob, 0.80)
            risk_score = round(min(prob, 1.0) * 100, 2)
            label      = "Phishing"
            return jsonify({
                "type": "email", "prediction": label,
                "risk_score": risk_score, "confidence": get_confidence(risk_score),
                "explanation": get_email_explanation(vec, prob),
                "urls_found": url_scan_results
            })

        # Rule-based override — safe patterns
        if check_safe_patterns(text) and url_risk_boost == 0.0:
            vec        = vectorizer.transform([clean_text(text)])
            prob       = email_model.predict_proba(vec)[0][EMAIL_PHISHING_IDX]
            prob       = min(prob, 0.35)
            risk_score = round(prob * 100, 2)
            label      = "Safe"
            return jsonify({
                "type": "email", "prediction": label,
                "risk_score": risk_score, "confidence": "Low",
                "explanation": get_email_explanation(vec, prob),
                "urls_found": url_scan_results
            })

        # Model prediction — ambiguous emails
        vec        = vectorizer.transform([clean_text(text)])
        prob       = email_model.predict_proba(vec)[0][EMAIL_PHISHING_IDX]
        prob       = min(1.0, prob + url_risk_boost * 0.3)
        risk_score = round(prob * 100, 2)
        label      = "Phishing" if prob > 0.5 else "Safe"

        return jsonify({
            "type":        "email",
            "prediction":  label,
            "risk_score":  risk_score,
            "confidence":  get_confidence(risk_score),
            "explanation": get_email_explanation(vec, prob),
            "urls_found":  url_scan_results
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == '__main__':
    app.run(debug=True)