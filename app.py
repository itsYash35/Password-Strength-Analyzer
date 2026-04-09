from flask import Flask, request, jsonify, render_template
import re
import secrets
import string
import math

app = Flask(__name__)

def analyze_password(password: str) -> dict:
    if not password:
        return {"score": 0, "strength": "Very Weak", "feedback": ["Password cannot be empty."], "entropy": 0, "suggestion": None}

    feedback = []
    score = 0

    # 1. Length
    if len(password) < 8:
        feedback.append("❌ Too short. Minimum 8 characters required.")
    elif len(password) >= 12:
        score += 25
    else:
        score += 15

    # 2. Character Diversity
    has_lower = bool(re.search(r'[a-z]', password))
    has_upper = bool(re.search(r'[A-Z]', password))
    has_digit = bool(re.search(r'\d', password))
    has_special = bool(re.search(r'[!@#$%^&*(),.?":{}|<>_\-+=]', password))
    char_types = sum([has_lower, has_upper, has_digit, has_special])

    if char_types >= 3: score += 15
    if char_types == 4: score += 10

    # 3. Pattern & Dictionary Checks
    if re.search(r'(.)\1{2,}', password):
        feedback.append("🚫 Avoid repeating characters (e.g., 'aaa', '111')")
        score -= 10
    if any(seq in password.lower() for seq in ["123", "abc", "qwerty", "password", "admin", "letmein"]):
        feedback.append("🚫 Contains common words/sequences")
        score -= 15

    # 4. Entropy Calculation (Cryptographic measure of unpredictability)
    charset_size = (26 if has_lower else 0) + (26 if has_upper else 0) + (10 if has_digit else 0) + (32 if has_special else 0)
    entropy = len(password) * math.log2(charset_size) if charset_size > 0 else 0
    if entropy > 60: score += 20
    elif entropy > 45: score += 15
    elif entropy > 30: score += 10

    score = max(0, min(100, score))
    strength = "Strong 🔒" if score >= 80 else "Moderate 🟡" if score >= 60 else "Weak 🔓"

    # Suggestion if weak
    suggestion = None
    if score < 70:
        alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
        suggestion = ''.join(secrets.choice(alphabet) for _ in range(14))

    return {
        "score": score,
        "strength": strength,
        "entropy_bits": round(entropy, 1),
        "feedback": feedback,
        "suggestion": suggestion
    }

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    data = request.get_json()
    return jsonify(analyze_password(data.get("password", "")))

if __name__ == "__main__":
    app.run(debug=True)