from flask import Flask, request, jsonify
from flask_cors import CORS  # Import CORS
from spellchecker import SpellChecker  # Import spell checker

app = Flask(__name__)  # Define Flask app first
CORS(app)  # Allow all origins for now

# Initialize spell checker
spell = SpellChecker()

# Phishing keyword list
phishing_keywords = ["urgent", "password", "click here", "verify", "update your account", "login now"]

def calculate_risk(text):
    words = text.lower().split()
    
    # Count phishing keywords
    score = sum(1 for word in phishing_keywords if word in words)
    
    # Check for misspelled words
    misspelled = spell.unknown(words)

    # Base risk score
    risk_percentage = min(100, score * 20)
    
    # If at least one word is misspelled, force risk score to at least 75%
    if misspelled:
        risk_percentage = max(risk_percentage, 75)

    return {"risk_score": risk_percentage}

@app.route('/analyze', methods=['POST'])
def analyze_text():
    data = request.json
    if 'text' not in data:
        return jsonify({"error": "No text provided"}), 400
    
    return jsonify(calculate_risk(data['text']))

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)

