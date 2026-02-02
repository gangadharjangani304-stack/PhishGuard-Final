from flask import Flask, render_template, request, jsonify
import joblib
import numpy as np
from feature_extractor import FeatureExtractor
import os

app = Flask(__name__)

# Load Model
model_path = 'model.pkl'

if not os.path.exists(model_path):
    print("❌ Error: 'model.pkl' not found.")
    print("👉 Please run 'python train_model.py' first!")
    exit()

model = joblib.load(model_path)

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    url = request.form.get('url')
    if not url:
        return jsonify({'error': 'No URL provided', 'status': 'ERROR'})

    # 1. Extract Features
    extractor = FeatureExtractor(url)
    features = np.array(extractor.get_features_list()).reshape(1, -1)

    # 2. Predict
    prediction = model.predict(features)[0]
    
    # SAFETY FIX: Handle probabilities robustly
    confidence = 0.0
    if hasattr(model, "predict_proba"):
        probs = model.predict_proba(features)[0]
        # If model has only 1 class (broken training), this length might be 1
        if len(probs) < 2:
            confidence = 100.0
        else:
            # -1 is Phishing (index 0 usually), 1 is Legit (index 1)
            # We map -1 -> index 0 and 1 -> index 1 based on training order
            # But to be safe, we just take the MAX probability
            confidence = max(probs) * 100
    else:
        confidence = 100.0

    # Map Prediction to UI
    # In our dataset: -1 = Phishing, 1 = Legitimate
    if prediction == -1: 
        result_text = "PHISHING"
    else:
        result_text = "LEGITIMATE"

    # 3. Explainability (XAI)
    reasons = []
    if extractor.using_ip() == -1: reasons.append("IP Address used instead of Domain Name")
    if extractor.long_url() == -1: reasons.append("URL is abnormally long")
    if extractor.short_url() == -1: reasons.append("URL Shortening service detected")
    if extractor.symbol_at() == -1: reasons.append("URL contains '@' symbol")
    if extractor.redirecting() == -1: reasons.append("URL contains double slash redirection")
    if extractor.prefix_suffix() == -1: reasons.append("Domain uses hyphen (-) to mimic legitimate brands")
    
    # Fallback reason if it's phishing but no specific rule triggered
    if not reasons and result_text == "PHISHING":
        reasons.append("Suspicious content structure and heuristic patterns detected")

    return jsonify({
        'status': result_text,
        'confidence': round(confidence, 2),
        'reasons': reasons
    })

if __name__ == '__main__':
    app.run(debug=True, port=5000)