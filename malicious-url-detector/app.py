from flask import Flask, request, jsonify
from flask_cors import CORS
import joblib
import numpy as np
import pandas as pd
from urllib.parse import urlparse
import re
import math
from scipy.sparse import hstack
import warnings
import traceback

warnings.filterwarnings("ignore")

app = Flask(__name__)
CORS(app)

# ==================== LOAD MODELS ====================
print("=" * 70)
print("🔹 Đang load models...")

try:
    print("🔹 Loading train_model.pkl...")
    model = joblib.load('train_model.pkl')
    print("✓ train_model.pkl loaded")

    print("🔹 Loading tfidf_vectorizer.pkl...")
    vectorizer = joblib.load('tfidf_vectorizer.pkl')
    print("✓ tfidf_vectorizer.pkl loaded")

    print("🔹 Loading model_metadata.pkl...")
    metadata = joblib.load('model_metadata.pkl')
    print("✓ model_metadata.pkl loaded")

    threshold = metadata.get('threshold', 0.4)
    feature_names = metadata.get('feature_names', [])

    print(f"✓ Threshold: {threshold}")
    print(f"✓ Handcrafted features: {len(feature_names)}")
    print("=" * 70)

except Exception as e:
    print(f"✗ Error loading models: {e}")
    exit(1)

# ==================== FEATURE ENGINEERING ====================

def calculate_entropy(text):
    if not text:
        return 0
    entropy = 0
    for x in range(256):
        p_x = text.count(chr(x)) / len(text)
        if p_x > 0:
            entropy += - p_x * math.log2(p_x)
    return entropy


def extract_url_features(url):
    """Trích xuất 30+ đặc trưng từ URL"""
    features = {}
    try:
        parsed = urlparse(str(url))
        domain = parsed.netloc
        path = parsed.path

        features['url_length'] = len(url)
        features['domain_length'] = len(domain)
        features['path_length'] = len(path)
        features['query_length'] = len(parsed.query)

        features['num_dots'] = url.count('.')
        features['num_hyphens'] = url.count('-')
        features['num_underscores'] = url.count('_')
        features['num_slashes'] = url.count('/')
        features['num_questions'] = url.count('?')
        features['num_equals'] = url.count('=')
        features['num_at'] = url.count('@')
        features['num_ampersands'] = url.count('&')
        features['num_percent'] = url.count('%')
        features['num_digits'] = sum(c.isdigit() for c in url)

        features['has_ip'] = int(bool(re.search(r'\d{1,3}(?:\.\d{1,3}){3}', url)))
        features['has_port'] = int(bool(re.search(r':\d{2,5}', url)))
        features['has_double_slash_redirect'] = int('//' in path)
        features['has_prefix_suffix'] = int('-' in domain)

        suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.work', '.click']
        features['suspicious_tld'] = int(any(url.endswith(tld) for tld in suspicious_tlds))

        features['is_https'] = int(parsed.scheme == 'https')
        features['entropy'] = calculate_entropy(url)
        features['domain_entropy'] = calculate_entropy(domain)

        subdomain_count = domain.count('.') - 1
        features['subdomain_count'] = subdomain_count if subdomain_count >= 0 else 0
        features['has_subdomain'] = int(subdomain_count > 0)

        features['path_depth'] = path.count('/')
        suspicious_keywords = [
            'login', 'signin', 'account', 'verify', 'secure', 'update',
            'bank', 'paypal', 'wallet', 'password', 'confirm'
        ]
        features['suspicious_keywords'] = sum(1 for kw in suspicious_keywords if kw in url.lower())

        features['digit_ratio'] = features['num_digits'] / max(len(url), 1)
        features['special_char_ratio'] = (
            features['num_hyphens'] + features['num_underscores'] +
            features['num_at'] + features['num_percent']
        ) / max(len(url), 1)

        features['abnormal_url'] = int(len(url) > 75)
        features['abnormal_domain'] = int(len(domain) > 30)

    except Exception as e:
        print(f"Error parsing URL: {e}")
        for key in [
            'url_length', 'domain_length', 'path_length', 'query_length',
            'num_dots', 'num_hyphens', 'num_underscores', 'num_slashes',
            'num_questions', 'num_equals', 'num_at', 'num_ampersands',
            'num_percent', 'num_digits', 'has_ip', 'has_port',
            'has_double_slash_redirect', 'has_prefix_suffix', 'suspicious_tld',
            'is_https', 'entropy', 'domain_entropy', 'subdomain_count',
            'has_subdomain', 'path_depth', 'suspicious_keywords',
            'digit_ratio', 'special_char_ratio', 'abnormal_url', 'abnormal_domain'
        ]:
            features[key] = 0
        features['suspicious_tld'] = 1

    return features


def create_feature_matrix(urls):
    if isinstance(urls, str):
        urls = pd.Series([urls])
    elif isinstance(urls, list):
        urls = pd.Series(urls)
    handcrafted = pd.DataFrame([extract_url_features(url) for url in urls])
    tfidf_features = vectorizer.transform(urls.apply(str))
    combined = hstack([tfidf_features, handcrafted.values])
    return combined


def predict_url(url):
    try:
        features = create_feature_matrix(url)
        proba = model.predict(features, num_iteration=model.best_iteration)[0]
        is_malicious = proba >= threshold

        if proba >= 0.8:
            risk_level, risk_text = "critical", "Cực kỳ nguy hiểm"
        elif proba >= 0.6:
            risk_level, risk_text = "high", "Nguy hiểm cao"
        elif proba >= 0.4:
            risk_level, risk_text = "medium", "Cảnh báo"
        else:
            risk_level, risk_text = "low", "An toàn"

        return {
            'is_malicious': bool(is_malicious),
            'confidence': float(proba),
            'risk_level': risk_level,
            'risk_text': risk_text,
            'threshold': float(threshold)
        }

    except Exception as e:
        print("Prediction error:", e)
        traceback.print_exc()
        return {'error': str(e), 'is_malicious': False, 'confidence': 0.0}


# ==================== API ENDPOINTS ====================

@app.route('/health', methods=['GET'])
def health_check():
    return jsonify({
        'status': 'healthy',
        'model_loaded': model is not None,
        'vectorizer_loaded': vectorizer is not None,
        'threshold': float(threshold),
        'model_info': {
            'best_iteration': getattr(model, 'best_iteration', 'N/A'),
            'num_features': len(feature_names),
            'auc': metadata.get('auc', 'N/A'),
            'f1': metadata.get('f1', 'N/A'),
            'recall': metadata.get('recall', 'N/A')
        }
    })


@app.route('/scan', methods=['POST'])
def scan_url():
    try:
        data = request.get_json(force=True)
        if not data or 'url' not in data:
            return jsonify({'error': 'Missing URL parameter'}), 400

        url = data['url']

        # ⚠️ Bỏ qua URL nội bộ của Chrome/DevTools
        if url.startswith(("chrome://", "devtools://", "edge://", "about:", "file://")):
            print(f"⚙️ Bỏ qua URL nội bộ: {url}")
            return jsonify({
                "url": url,
                "is_malicious": False,
                "confidence": 0.0,
                "risk_level": "none",
                "risk_text": "Bỏ qua URL nội bộ trình duyệt"
            }), 200

        if not url or len(url) < 10:
            return jsonify({'error': 'Invalid URL'}), 400

        result = predict_url(url)
        result['url'] = url

        status = "🔴 MALICIOUS" if result.get('is_malicious') else "🟢 SAFE"
        print(f"{status} ({result.get('confidence', 0):.2%}) - {url[:80]}")

        return jsonify(result)

    except Exception as e:
        print("Error in /scan:", e)
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500


@app.route('/batch-scan', methods=['POST'])
def batch_scan():
    try:
        data = request.get_json(force=True)
        if not data or 'urls' not in data:
            return jsonify({'error': 'Missing URLs parameter'}), 400

        urls = data['urls']
        if not isinstance(urls, list):
            return jsonify({'error': 'URLs must be an array'}), 400

        results = []
        for url in urls[:50]:
            result = predict_url(url)
            result['url'] = url
            results.append(result)

        return jsonify({'results': results, 'total': len(results)})

    except Exception as e:
        print("Error in /batch-scan:", e)
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500


@app.route('/test', methods=['GET'])
def test_samples():
    test_urls = [
        "https://www.google.com",
        "https://github.com",
        "http://secure-paypal-verify-account.tk/login.php",
        "https://192.168.1.1/admin/login",
        "https://amaz0n-security-alert.com/update-payment",
    ]

    results = []
    for url in test_urls:
        result = predict_url(url)
        result['url'] = url
        results.append(result)

    return jsonify({'test_results': results, 'total': len(results)})


# ==================== MAIN ====================

if __name__ == '__main__':
    print("\n" + "=" * 70)
    print("🛡️  MALICIOUS URL DETECTION SERVER")
    print("=" * 70)
    print("Server: http://localhost:5000")
    print(f"Threshold: {threshold}")
    print(f"Model AUC: {metadata.get('auc', 'N/A')}")
    print(f"Model F1: {metadata.get('f1', 'N/A')}")
    print(f"Model Recall: {metadata.get('recall', 'N/A')}")
    print("=" * 70)
    print("\n🔹 Endpoints:")
    print("   GET  /health      - Health check")
    print("   POST /scan        - Scan single URL")
    print("   POST /batch-scan  - Scan multiple URLs")
    print("   GET  /test        - Test with sample URLs")
    print("\n🚀 Server is ready!\n")

    app.run(host='0.0.0.0', port=5000, debug=True)
