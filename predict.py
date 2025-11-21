import joblib
import json
import numpy as np
import pandas as pd
from urllib.parse import urlparse, parse_qs
import tldextract
import re
import requests
from catboost import CatBoostClassifier
import warnings
warnings.filterwarnings("ignore")


# ======================================================
# 1. LOAD MODELS + FEATURE CONFIG
# ======================================================

cat_model = CatBoostClassifier()
cat_model.load_model("models/cat_model.cbm")

xgb_model = joblib.load("models/xgb_model.pkl")
meta_model = joblib.load("models/meta_model.pkl")

with open("models/feature_config.json", "r") as f:
    feature_config = json.load(f)


# ======================================================
# 2. SMART WHITELIST
# ======================================================

WHITELIST_DOMAINS = {
    "google.com", "instagram.com", "facebook.com",
    "openai.com", "github.com", "microsoft.com",
    "apple.com", "chatgpt.com", "psit.ac.in",
    "erp.psit.ac.in", "aktu.ac.in"
}

TRUSTED_TLD_SUFFIXES = ["ac.in", "edu", "edu.in", "gov.in", "nic.in"]
TRUSTED_KEYWORDS = ["college", "university", "institute", "school", "iit", "nit", "iiit"]


def get_domain(url: str) -> str:
    ext = tldextract.extract(url)
    if ext.suffix:
        return f"{ext.domain}.{ext.suffix}".lower()
    return (ext.domain or "").lower()


def is_whitelisted(url: str) -> bool:
    hostname = (urlparse(url).hostname or "").lower().replace("www.", "")
    root_domain = get_domain(url)

    if root_domain in WHITELIST_DOMAINS or hostname in WHITELIST_DOMAINS:
        return True

    if any(root_domain.endswith(s) for s in TRUSTED_TLD_SUFFIXES):
        return True

    if any(kw in root_domain for kw in TRUSTED_KEYWORDS):
        return True

    return False


# ======================================================
# 3. REPUTATION CHECKS
# ======================================================

def urlhaus_check(url: str) -> bool:
    try:
        r = requests.post(
            "https://urlhaus-api.abuse.ch/v1/url/",
            data={"url": url},
            timeout=5
        )
        return r.json().get("query_status") == "ok"
    except:
        return False


def openphish_check(url: str) -> bool:
    try:
        feed = requests.get(
            "https://openphish.com/feed.txt",
            timeout=5
        ).text.splitlines()
        return url in feed
    except:
        return False


def google_safebrowsing_check(url: str) -> bool:
    try:
        with open("google_key.json") as f:
            api_key = json.load(f)["api_key"]

        api_url = (
            f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}"
        )

        payload = {
            "client": {"clientId": "phishing-detector", "clientVersion": "1.0"},
            "threatInfo": {
                "threatTypes": [
                    "MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"
                ],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}]
            }
        }

        r = requests.post(api_url, json=payload, timeout=5)
        return "matches" in r.json()
    except:
        return False


# ======================================================
# 4. BLACKLIST SUPPORT
# ======================================================

BLACKLIST_FILE = "blacklist.json"


def load_blacklist():
    try:
        with open(BLACKLIST_FILE, "r") as f:
            return set(json.load(f).get("blocked_urls", []))
    except:
        return set()


def save_blacklist(blacklist: set):
    with open(BLACKLIST_FILE, "w") as f:
        json.dump({"blocked_urls": list(blacklist)}, f, indent=4)


BLACKLIST = load_blacklist()


def is_blacklisted(url: str) -> bool:
    host = urlparse(url).hostname or url
    return url in BLACKLIST or host in BLACKLIST


def add_to_blacklist(url: str):
    host = urlparse(url).hostname or url
    BLACKLIST.add(url)
    BLACKLIST.add(host)
    save_blacklist(BLACKLIST)


# ======================================================
# 5. FEATURE EXTRACTION (MATCH TRAINING)
# ======================================================

def extract_features(url: str) -> pd.DataFrame:

    features = {}
    parsed = urlparse(url)

    # ----- Lexical -----
    features["url_length"] = len(url)
    features["num_digits"] = sum(c.isdigit() for c in url)
    features["num_special_chars"] = sum(not c.isalnum() for c in url)
    features["num_dots"] = url.count(".")
    features["has_ip"] = int(bool(re.search(r"\d+\.\d+\.\d+\.\d+", url)))
    features["has_at_symbol"] = int("@" in url)
    features["has_double_slash"] = int(url.count("//") > 1)
    features["has_hyphen"] = int("-" in url)
    features["protocol_http"] = int(parsed.scheme == "http")
    features["protocol_https"] = int(parsed.scheme == "https")

    # ----- Domain -----
    ext = tldextract.extract(url)
    domain = ext.domain or ""
    subdomain = ext.subdomain or ""
    suffix = ext.suffix or ""

    features["domain_length"] = len(domain)
    features["subdomain_length"] = len(subdomain)
    features["num_subdomains"] = subdomain.count(".") + 1 if subdomain else 0
    features["tld_length"] = len(suffix)

    features["suspicious_subdomain"] = int(
        any(word in subdomain.lower() for word in [
            "secure", "account", "verify", "login", "update", "bank", "confirm"
        ])
    ) if subdomain else 0

    # ----- Path / Query -----
    features["path_length"] = len(parsed.path)
    features["query_length"] = len(parsed.query)
    params = parse_qs(parsed.query)
    features["num_params"] = len(params)

    lower = url.lower()
    features["has_login_keyword"] = int("login" in lower)
    features["has_secure_keyword"] = int("secure" in lower)
    features["has_update_keyword"] = int("update" in lower)

    return pd.DataFrame([features])


# ======================================================
# 6. LOW-RISK HEURISTIC
# ======================================================

def is_low_risk_url(row: pd.Series) -> bool:

    if row["has_ip"] == 1:
        return False

    if row["suspicious_subdomain"] == 1:
        return False

    if row["has_login_keyword"] or row["has_secure_keyword"] or row["has_update_keyword"]:
        return False

    if row["url_length"] > 160:
        return False

    if row["num_special_chars"] > 20:
        return False

    if row["num_dots"] > 6:
        return False

    return True


# ======================================================
# 7. ML STACK PREDICTOR (FIXED SHAPE)
# ======================================================

def unified_predict(df: pd.DataFrame):

    numeric = feature_config["numeric_features"]
    allf = feature_config["all_features"]

    df_all = df[allf]
    df_num = df[numeric]

    # CatBoost output → keep only positive class
    cat_p = cat_model.predict_proba(df_all)
    cat_p = np.array(cat_p, dtype=float)
    if cat_p.shape[1] == 2:
        cat_p = cat_p[:, 1:2]

    # XGBoost output → keep only positive class
    xgb_p = xgb_model.predict_proba(df_num)
    xgb_p = np.array(xgb_p, dtype=float)
    if xgb_p.shape[1] == 2:
        xgb_p = xgb_p[:, 1:2]

    # Final 2-column input to meta model
    stack_in = np.hstack((cat_p, xgb_p))

    proba = meta_model.predict_proba(stack_in)[0]
    pred = int(np.argmax(proba))
    max_prob = float(np.max(proba))

    return pred, max_prob, proba


# ======================================================
# 8. MITIGATION SYSTEM (UPDATED LABELS)
# ======================================================

def mitigation_system(url: str) -> dict:
    if not url.startswith("http"):
        url = "https://" + url

    root = get_domain(url)

    # Blacklist
    if is_blacklisted(url):
        return {"url": url, "predicted_class": "Malicious (Blacklisted)",
                "confidence": 1.0, "action_taken": "Blocked", "severity": "High"}

    # Whitelist
    if is_whitelisted(url):
        return {"url": url, "predicted_class": "Legitimate (Whitelisted)",
                "confidence": 1.0, "action_taken": "Allowed", "severity": "None"}

    # Trusted suffix
    if any(root.endswith(s) for s in TRUSTED_TLD_SUFFIXES):
        return {"url": url, "predicted_class": "Legitimate (Trusted Edu/Gov)",
                "confidence": 0.99, "action_taken": "Allowed", "severity": "None"}

    # Reputation APIs
    if urlhaus_check(url):
        return {"url": url, "predicted_class": "Malicious (URLhaus)",
                "confidence": 1.0, "action_taken": "Blocked", "severity": "High"}

    if google_safebrowsing_check(url):
        return {"url": url, "predicted_class": "Malicious (Google Safe Browsing)",
                "confidence": 1.0, "action_taken": "Blocked", "severity": "Critical"}

    if openphish_check(url):
        return {"url": url, "predicted_class": "Malicious (OpenPhish)",
                "confidence": 1.0, "action_taken": "Blocked", "severity": "High"}

    # ML Prediction
    df = extract_features(url)
    row = df.iloc[0]

    pred, max_prob, _ = unified_predict(df)

    labels = {
        0: ("Legitimate", "Allowed", "Low"),
        1: ("Malicious (Phishing)", "User Confirmation Required", "High"),
        2: ("Malicious (Malware)", "User Confirmation Required", "Critical"),
        3: ("Malicious (Defacement)", "User Confirmation Required", "Medium")
    }

    # False-positive control
    if pred != 0 and max_prob < 0.85 and is_low_risk_url(row):
        return {
            "url": url,
            "predicted_class": "Legitimate (ML Low-Confidence)",
            "confidence": max_prob,
            "action_taken": "Allowed (Logged)",
            "severity": "Low"
        }

    name, action, severity = labels[pred]

    # Add to blacklist only if very confident malicious
    if pred != 0 and max_prob >= 0.95:
        add_to_blacklist(url)

    return {
        "url": url,
        "predicted_class": name,
        "confidence": max_prob,
        "action_taken": action,
        "severity": severity
    }


# ======================================================
# 9. MANUAL TEST
# ======================================================

if __name__ == "__main__":
    url = input("Enter URL: ").strip()
    print(mitigation_system(url))
