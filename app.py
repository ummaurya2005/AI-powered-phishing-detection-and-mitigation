

from flask import Flask, render_template, request, jsonify, redirect, url_for
from predict import mitigation_system, add_to_blacklist
from urllib.parse import urlparse

app = Flask(__name__)



# ------------------------------------------------------
# Home Page
# ------------------------------------------------------
@app.route("/")
def index():
    return render_template("index.html")



# ------------------------------------------------------
# URL Validator
# ------------------------------------------------------
def is_valid_url(url):
    try:
        parsed = urlparse(url)
        return bool(parsed.netloc or parsed.path)
    except:
        return False



# ------------------------------------------------------
# MAIN CHECK ENDPOINT
# ------------------------------------------------------
@app.route("/check", methods=["POST"])
def check_url():

    url = request.form.get("url", "").strip()

    if not url:
        return render_template("result.html",
                               result={"error": "URL field cannot be empty!"})

    if not is_valid_url(url):
        return render_template("result.html",
                               result={"error": "Invalid URL format!"})

    # Run mitigation system (may return "User Confirmation Required")
    result = mitigation_system(url)

    # If confirmation required → show warning page
    if result["action_taken"] == "User Confirmation Required":
        return render_template("confirm.html", result=result)

    # Otherwise normal result page
    return render_template("result.html", result=result)



# ------------------------------------------------------
# USER CONFIRMS BLOCKING
# ------------------------------------------------------
@app.route("/confirm_block", methods=["POST"])
def confirm_block():
    url = request.form.get("url")

    if url:
        add_to_blacklist(url)
        result = {
            "url": url,
            "predicted_class": "Manually Blocked",
            "confidence": 1.0,
            "action_taken": "Blocked & Added to Blacklist",
            "severity": "High"
        }
        return render_template("result.html", result=result)

    return render_template("result.html", result={"error": "Invalid URL"})


# ------------------------------------------------------
# USER CANCELS / ALLOWS
# ------------------------------------------------------
@app.route("/confirm_allow", methods=["POST"])
def confirm_allow():
    url = request.form.get("url")

    result = {
        "url": url,
        "predicted_class": "Allowed (User Override)",
        "confidence": 1.0,
        "action_taken": "Allowed",
        "severity": "None"
    }

    return render_template("result.html", result=result)



# ------------------------------------------------------
# Debug JSON API
# ------------------------------------------------------
@app.route("/api/check", methods=["POST"])
def check_url_api():

    data = request.json
    if not data or "url" not in data:
        return jsonify({"error": "Missing `url` in JSON body"}), 400

    url = data["url"].strip()

    if not is_valid_url(url):
        return jsonify({"error": "Invalid URL format"}), 400

    result = mitigation_system(url)
    return jsonify(result)



# ------------------------------------------------------
# MAIN
# ------------------------------------------------------
if __name__ == "__main__":
    app.run(debug=True)
