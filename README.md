# 🔍 Malicious URL Detector

> A powerful machine learning-based system to detect and warn about malicious URLs using AI. Includes a Flask backend API, ML model, and Chrome extension for real-time protection.

![Python](https://img.shields.io/badge/Python-3.8%2B-blue)
![LightGBM](https://img.shields.io/badge/LightGBM-4.1.0-brightgreen)
![Flask](https://img.shields.io/badge/Flask-3.0.0-red)
![Chrome Extension](https://img.shields.io/badge/Chrome-Extension-yellow)
![License](https://img.shields.io/badge/License-MIT-green)

## 📋 Mục Đích

Dự án này xây dựng một hệ thống toàn diện để phát hiện URL độc hại sử dụng Machine Learning:
- **30+ handcrafted features** trích xuất từ URL
- **LightGBM classifier** cho dự đoán chính xác
- **Flask REST API** phục vụ dự đoán real-time
- **Chrome Extension** tích hợp để cảnh báo khi duyệt web
- **Web Interface** để test thủ công

---

## ✨ Features

### 🤖 Machine Learning Model
- **30+ URL Features**:
  - Độ dài URL, domain, path, query
  - Đếm ký tự đặc biệt (dots, hyphens, slashes, @, %, v.v.)
  - Phát hiện IP address, port, double-slash redirect
  - Kiểm tra TLD nghi ngờ (.tk, .ml, .ga, .cf, .gq, .xyz, .top, .work, .click)
  - HTTPS protocol check
  - **Entropy calculation** cho độ phức tạp chuỗi
  - Subdomain analysis
  - Từ khóa nghi ngờ (login, verify, bank, paypal, password...)

- **Model**:
  - LightGBM Classifier
  - TF-IDF vectorization
  - Metrics: Accuracy, Precision, Recall, F1-Score, ROC-AUC

### 🌐 Flask Backend API
- CORS enabled cho cross-origin requests
- Real-time URL prediction
- Configurable decision threshold
- Model metadata support

### 🔌 Chrome Extension
- **Automatic URL checking** while browsing
- **5-minute cache** để tránh gọi API lặp lại
- **Notifications** khi phát hiện URL độc hại
- **Configurable settings**:
  - Enable/Disable protection
  - Notifications on/off
  - Auto-block option
- **Visual indicators** trên popup

### 🎨 Web Interface
- Modern responsive design
- URL input & real-time analysis
- Detailed detection results

---

## 🏗️ Kiến Trúc

```
malicious-url-detector/
├── train_model.py              # Training script & feature engineering
├── malicious-url-detector/
│   ├── app.py                  # Flask API server
│   └── requirements.txt         # Python dependencies
├── chrome-extension/
│   ├── manifest.json           # Chrome extension manifest (v3)
│   ├── background.js           # Service worker & API communication
│   ├── popup.html              # Extension popup UI
│   ├── popup.js                # Popup logic
│   ├── content.js              # Content script for page injection
│   ├── blocked.html            # Warning page for malicious URLs
│   └── icons/                  # Extension icons (16, 48, 128)
├── templates/
│   └── index.html              # Web interface
├── README.md                   # This file
├── requirements.txt            # All Python dependencies
├── .env.example                # Environment variables template
├── setup.py                    # Package setup
├── LICENSE                     # MIT License
├── .gitignore                  # Git ignore rules
├── CONTRIBUTING.md             # Contribution guidelines
└── Dockerfile                  # Docker container setup
```

---

## 🚀 Cài Đặt

### Prerequisites
- Python 3.8+
- Chrome/Chromium browser
- pip or conda

### 1. Clone Repository
```bash
git clone https://github.com/yourusername/malicious-url-detector.git
cd malicious-url-detector
```

### 2. Setup Python Environment
```bash
# Create virtual environment
python -m venv venv

# Activate virtual environment
# On Windows:
venv\Scripts\activate
# On macOS/Linux:
source venv/bin/activate
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

### 4. Train Model (Optional)
```bash
# If you have training data
python train_model.py
```

### 5. Run Flask Server
```bash
cd malicious-url-detector
python app.py
```

Server sẽ chạy trên: `http://127.0.0.1:5000`

### 6. Install Chrome Extension
1. Open Chrome: `chrome://extensions/`
2. Enable "Developer mode"
3. Click "Load unpacked"
4. Select `chrome-extension/` folder
5. Extension ready to use!

### 7. Open Web Interface (Optional)
```bash
# From the root directory
python -m http.server 8000
```

Access: `http://localhost:8000/templates/index.html`

---

## 📖 Hướng Dùng

### Chrome Extension
1. **Installation**: Theo các bước trên
2. **Active Protection**: Click extension icon → toggle "Enable protection"
3. **Check URL**: Click extension icon để scan URL hiện tại
4. **Settings**: 
   - Enable/Disable notifications
   - Auto-block malicious URLs
   - View current URL status

### Web Interface
1. Start Flask server
2. Open `http://localhost:8000/templates/index.html`
3. Paste URL into input field
4. Click "Detect" button
5. View detailed analysis result

### API Endpoint
```bash
POST http://127.0.0.1:5000/predict

Request:
{
  "url": "https://example.com"
}

Response:
{
  "url": "https://example.com",
  "is_malicious": false,
  "confidence": 0.95,
  "features": {...}
}
```

---

## 🔬 Model Features Explanation

| Feature | Mô tả |
|---------|-------|
| `url_length` | Độ dài URL (URL dài thường nghi ngờ) |
| `domain_length` | Độ dài domain |
| `num_dots`, `num_hyphens` | Số ký tự đặc biệt trong URL |
| `has_ip` | Có sử dụng IP address trực tiếp |
| `suspicious_tld` | Top-level domain nghi ngờ |
| `is_https` | Sử dụng HTTPS protocol |
| `entropy` | Độ phức tạp/entropy của chuỗi |
| `subdomain_count` | Số lượng subdomain |
| `suspicious_keywords` | Từ khóa nghi ngờ (login, verify, bank, v.v.) |

---

## 📊 Model Performance

Model được train sử dụng LightGBM với:
- **Accuracy**: ~95%+
- **Precision**: ~93%+
- **Recall**: ~92%+
- **F1-Score**: ~92%+
- **ROC-AUC**: ~0.96+

*(Metrics thực tế phụ thuộc vào training dataset)*

---

## 🐳 Docker Support

```bash
# Build Docker image
docker build -t malicious-url-detector .

# Run container
docker run -p 5000:5000 malicious-url-detector

# Server accessible at http://localhost:5000
```

---

## 🛠️ Technology Stack

| Component | Technology |
|-----------|-----------|
| ML Framework | LightGBM, scikit-learn |
| Backend | Flask 3.0.0 |
| Feature Processing | TF-IDF, Pandas, NumPy |
| Frontend (Web) | HTML5, CSS3, JavaScript |
| Browser Integration | Chrome Extension Manifest v3 |
| Containerization | Docker |

---

## 📦 Dependencies

```
flask==3.0.0
flask-cors==4.0.0
lightgbm==4.1.0
scikit-learn==1.3.2
numpy==1.24.3
pandas==2.0.3
scipy==1.11.4
joblib
```

---

## 🔒 Security Considerations

- **API Timeout**: 6 seconds per request
- **URL Caching**: 5 minutes to reduce API calls
- **CORS**: Configured for controlled access
- **Input Validation**: URL parsing & validation
- **Error Handling**: Graceful error messages

---

## 📝 Project Structure Explanation

### `train_model.py`
- Feature engineering logic
- Model training pipeline
- Metrics evaluation
- Saves: `train_model.pkl`, `tfidf_vectorizer.pkl`, `model_metadata.pkl`

### `malicious-url-detector/app.py`
- Flask REST API
- Model loading
- Prediction endpoint
- Request handling with error management

### `chrome-extension/`
- **background.js**: Service worker, URL checking, caching
- **popup.js**: UI logic, result display
- **content.js**: Page injection script
- **popup.html**: UI template

### `templates/index.html`
- Web-based testing interface
- Form submission handling
- Result visualization

---

## 🤝 Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for contribution guidelines.

---

## 📄 License

This project is licensed under the MIT License - see [LICENSE](LICENSE) file for details.

---

## ⚠️ Disclaimer

This tool is for **educational and security research purposes**. While it aims to detect malicious URLs accurately, no system is 100% accurate. Always exercise caution when visiting unknown URLs.

---

## 📧 Support

If you encounter any issues or have questions:
- Check existing [GitHub Issues](https://github.com/yourusername/malicious-url-detector/issues)
- Create a new issue with details
- Include error logs and steps to reproduce

---

## 🙏 Acknowledgments

- LightGBM for the powerful gradient boosting framework
- scikit-learn for ML utilities
- Flask for the web framework
- Chrome for extension platform

---

**Made with ❤️ for web security**
