from flask import Flask, render_template, request, jsonify
import hashlib
import base64
import os
import re
import math
import time

app = Flask(__name__, template_folder="web", static_folder="web")


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/password/analyze", methods=["POST"])
def analyze_password():
    data = request.json
    password = data.get("password", "")

    if not password:
        return jsonify({"error": "No password provided"}), 400

    charset_size = 0
    if re.search(r"[a-z]", password):
        charset_size += 26
    if re.search(r"[A-Z]", password):
        charset_size += 26
    if re.search(r"\d", password):
        charset_size += 10
    if re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        charset_size += 32

    entropy = len(password) * math.log2(charset_size) if charset_size > 0 else 0

    score = 0
    feedback = []
    if len(password) >= 8:
        score += 1
    else:
        feedback.append("Use at least 8 characters")
    if len(password) >= 12:
        score += 1
    if re.search(r"[A-Z]", password) and re.search(r"[a-z]", password):
        score += 1
    else:
        feedback.append("Mix uppercase and lowercase letters")
    if re.search(r"\d", password):
        score += 1
    else:
        feedback.append("Add numbers")
    if re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        score += 1
    else:
        feedback.append("Add special characters")
    score = min(score, 4)

    labels = {0: "Very Weak", 1: "Weak", 2: "Fair", 3: "Strong", 4: "Very Strong"}

    combinations = charset_size ** len(password) if charset_size > 0 else 1
    seconds = combinations / 10000

    if seconds < 1:
        crack_time = "Instantly"
    elif seconds < 60:
        crack_time = f"{seconds:.0f} seconds"
    elif seconds < 3600:
        crack_time = f"{seconds / 60:.0f} minutes"
    elif seconds < 86400:
        crack_time = f"{seconds / 3600:.0f} hours"
    elif seconds < 31536000:
        crack_time = f"{seconds / 86400:.0f} days"
    else:
        years = seconds / 31536000
        crack_time = f"{years:,.0f} years" if years < 1e9 else f"{years:.2e} years"

    return jsonify({
        "score": score,
        "strength": labels.get(score, "Unknown"),
        "entropy": round(entropy, 2),
        "crack_time": crack_time,
        "has_upper": bool(re.search(r"[A-Z]", password)),
        "has_lower": bool(re.search(r"[a-z]", password)),
        "has_digit": bool(re.search(r"\d", password)),
        "has_special": bool(re.search(r"[!@#$%^&*(),.?\":{}|<>]", password)),
        "length": len(password),
        "feedback": feedback,
    })


@app.route("/api/encrypt", methods=["POST"])
def encrypt_text():
    data = request.json
    text = data.get("text", "")
    algorithm = data.get("algorithm", "caesar")
    key = data.get("key", "3")

    if not text:
        return jsonify({"error": "No text provided"}), 400

    if algorithm == "caesar":
        shift = int(key) if key.isdigit() else 3
        result = ""
        for char in text:
            if char.isalpha():
                base = ord("A") if char.isupper() else ord("a")
                result += chr((ord(char) - base + shift) % 26 + base)
            else:
                result += char
        return jsonify({"ciphertext": result, "algorithm": "Caesar Cipher"})

    elif algorithm == "vigenere":
        key = key.lower() if key else "key"
        result = []
        ki = 0
        for char in text:
            if char.isalpha():
                base = ord("A") if char.isupper() else ord("a")
                shift = ord(key[ki % len(key)]) - ord("a")
                result.append(chr((ord(char) - base + shift) % 26 + base))
                ki += 1
            else:
                result.append(char)
        return jsonify({"ciphertext": "".join(result), "algorithm": "Vigenere Cipher"})

    elif algorithm == "base64":
        encoded = base64.b64encode(text.encode()).decode()
        return jsonify({"ciphertext": encoded, "algorithm": "Base64"})

    elif algorithm == "md5":
        h = hashlib.md5(text.encode()).hexdigest()
        return jsonify({"ciphertext": h, "algorithm": "MD5"})

    elif algorithm == "sha256":
        h = hashlib.sha256(text.encode()).hexdigest()
        return jsonify({"ciphertext": h, "algorithm": "SHA-256"})

    return jsonify({"error": "Unknown algorithm"}), 400


@app.route("/api/hash/compare", methods=["POST"])
def compare_hashes():
    data = request.json
    text = data.get("text", "")
    if not text:
        return jsonify({"error": "No text provided"}), 400

    return jsonify({
        "md5": hashlib.md5(text.encode()).hexdigest(),
        "sha1": hashlib.sha1(text.encode()).hexdigest(),
        "sha256": hashlib.sha256(text.encode()).hexdigest(),
        "sha512": hashlib.sha512(text.encode()).hexdigest(),
    })


if __name__ == "__main__":
    app.run(debug=True, port=5000)
