# 🔐 Phishing Detection & Mitigation System  
A powerful Machine Learning + Reputation-based system to detect **phishing, malware, and malicious URLs** with high accuracy.  
Includes **stacked ensemble models**, **heuristic filters**, **URL reputation APIs**, and a **mitigation engine** that blocks dangerous URLs.

---

## 📸 Project Preview

### 🖼️ Phishing Awareness Images
![Phishing Image](https://i.imgur.com/rFQKN5F.jpeg)
![Malicious URL Example](https://i.imgur.com/qsM5JvF.jpeg)
![Detection System Overview](https://i.imgur.com/49jnM3z.jpeg)

---

## ⭐ Features

### ✔ Machine-Learning Based
- CatBoost binary classifier  
- XGBoost probabilistic classifier  
- Logistic Regression meta-model  
- Stack Ensemble for best precision  

### ✔ Smart Heuristics
- Suspicious keyword detection  
- IP-in-URL detection  
- Subdomain depth analysis  
- Lexical entropy  

### ✔ Reputation APIs
- Google Safe Browsing  
- URLhaus  
- OpenPhish  
- Local Blacklist  

### ✔ Mitigation Engine
- Auto-block malicious links  
- Confidence-based decisioning  
- Low-risk false positive controller  
- User confirmation workflow  

---

## 📁 Folder Structure







---

# 🧠 Machine Learning Architecture

## **🔷 Stacked Ensemble (Version 1.0)**

Your final ML pipeline uses:

### 1️⃣ **CatBoostClassifier**
- Strong performance on noisy lexical data  
- Handles categorical & class imbalances  
- Probability output used for stacking  

### 2️⃣ **XGBoostClassifier**
- Excellent for URL-based binary classification  
- Very fast inference  
- Probability output used in meta model  

### 3️⃣ **Logistic Regression (Meta Model)**
- Combines probabilities from CatBoost and XGBoost  
- Learns most reliable trust signals  

---

# 🔥 Final Meta Features


A lightweight but powerful 2D input to the meta model.

---

## 🧬 Feature Engineering

You extracted **21 lexical features** including:

### ✔ URL-based Metrics  
- url_length  
- num_digits  
- num_special_chars  
- num_dots  
- protocol_http / protocol_https  

### ✔ Domain-based Features  
- domain_length  
- subdomain_length  
- num_subdomains  
- suspicious_subdomain  

### ✔ Query & Path  
- path_length  
- query_length  
- num_params  

### ✔ Keyword Signals  
- has_login_keyword  
- has_secure_keyword  
- has_update_keyword  

---

## 🛡 Mitigation Workflow (Defense Engine)

### 1️⃣ Smart Whitelist  
Trusted educational, government & corporate domains pre-approved.

### 2️⃣ Reputation Checks  
URLhaus, OpenPhish, Google Safe Browsing APIs.

### 3️⃣ ML Prediction  
Stacked ensemble predicts phishing/malware.

### 4️⃣ False Positive Controller  
If URL is “low-risk” but ML is not confident:  
➡ Mark as **Legitimate (Logged)**

### 5️⃣ Auto Blacklisting  
High-confidence malicious URLs are added permanently.

---

## 📊 Example Output

```json
{
  "url": "http://198.23.44.12/login",
  "predicted_class": "Malicious (Phishing)",
  "confidence": 0.9821,
  "action_taken": "User Confirmation Required",
  "severity": "High"
}
