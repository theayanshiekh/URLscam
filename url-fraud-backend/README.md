# 🛡️ URL Fraud & Phishing Detection Backend Service

Production-ready, high-throughput REST API backend and interactive dashboard for detecting malicious, fraudulent, and phishing URLs. Powered by a pre-trained **Random Forest Classifier** trained on 24 lexical and structural features, enhanced with a threat heuristics explainability engine, audit logging, and analyst feedback mechanisms.

---

## 🚀 Features

- **Sub-millisecond Lexical Feature Extraction**: Extracts 24 numeric structural features (lengths, Shannon entropy, sensitive keywords, IPv4 detection, URL shorteners, delimiter patterns) without external network/DNS calls.
- **High-Throughput Vectorized Batch Inference**: Evaluates hundreds of URLs in a single matrix computation (10x–50x faster than single-row loops).
- **Multi-tiered Risk Scoring & Levels**: Categorizes URLs into `SAFE`, `LOW`, `SUSPICIOUS`, and `DANGEROUS` (or `CRITICAL`) with 0–100 risk score and calibrated probability.
- **Threat Indicator Explainability**: Highlights human-readable danger flags (IP hostnames, URL shorteners, credential spoofing `@`, redundant slashes, high entropy, unencrypted HTTP, and suspicious keywords).
- **Interactive Cyber-Security Web Dashboard**: Built-in dark-mode UI at `/` and `/dashboard` for instant browser testing with visual gauges, presets, batch scans, and feature inspection.
- **Analyst Feedback & Retraining Loop**: Community and analyst feedback endpoint (`/api/v1/reports`) stored in SQLite for false positive/negative tracking and continuous model retraining.
- **Production-Ready WSGI & Containerization**: Includes multi-stage `Dockerfile`, `docker-compose.yml`, and `Waitress` production WSGI server.
- **Automated Test Suite**: Full `pytest` unit & integration test coverage.

---

## 📂 Project Structure

```
url-fraud-backend/
├── app/
│   ├── __init__.py          # Flask application factory, CORS & error handlers
│   ├── config.py            # Environment-driven configuration
│   ├── core/
│   │   ├── extractor.py     # 24-feature lexical extraction & Shannon entropy
│   │   ├── detector.py      # ML inference engine (single & vectorized batch)
│   │   └── explainability.py # Rule-based threat indicators & scoring
│   ├── routes/
│   │   ├── api.py           # REST API endpoints (/check-url, /check-urls, /reports, etc.)
│   │   └── web.py           # Web UI dashboard route
│   ├── database/
│   │   └── db.py            # SQLite persistence for scan audits & feedback reports
│   ├── static/
│   │   ├── css/style.css    # Responsive dark cyber theme
│   │   └── js/app.js        # Interactive frontend script
│   └── templates/
│       └── index.html       # Web dashboard template
├── model_artifacts/
│   ├── model.joblib         # Pre-trained Random Forest model
│   ├── scaler.joblib        # Feature scaler
│   └── metadata.json        # Training metrics and threshold
├── tests/
│   ├── test_extractor.py    # Unit tests for feature extraction
│   └── test_api.py          # Integration tests for all REST endpoints
├── Dockerfile               # Production Docker image
├── docker-compose.yml       # Container orchestration
├── requirements.txt         # Pinned Python dependencies
├── run.py                   # Development and production runner
└── README.md                # Documentation & API specs
```

---

## ⚡ Quick Start

### 1. Prerequisites
- Python 3.10+ (or `uv`)

### 2. Installation
```bash
# Clone or navigate to the directory
cd url-fraud-backend

# Install dependencies
pip install -r requirements.txt
```

### 3. Run the Server

**Development Mode (Flask):**
```bash
python run.py --debug
```

**Production Mode (Waitress WSGI):**
```bash
python run.py --prod --port 5000
```

The server will start on `http://localhost:5000`:
- **Web UI Dashboard**: `http://localhost:5000/`
- **Healthcheck API**: `http://localhost:5000/api/v1/health`

---

## 🧪 Running Tests

```bash
pytest tests/ -v
```

---

## 🐳 Docker Deployment

### Using Docker Compose
```bash
docker-compose up --build -d
```

### Using Docker CLI
```bash
docker build -t url-fraud-backend .
docker run -p 5000:5000 -v $(pwd)/data:/app/data url-fraud-backend
```

---

## 📡 REST API Reference

### 1. Check Single URL
`POST /api/v1/check-url` (also aliases `POST /api/check-url`)

**Request:**
```bash
curl -X POST "http://localhost:5000/api/v1/check-url" \
  -H "Content-Type: application/json" \
  -d '{
    "url": "http://192.168.1.55/bank-security-update/login",
    "include_features": true,
    "include_explainability": true
  }'
```

**Response (200 OK):**
```json
{
  "url": "http://192.168.1.55/bank-security-update/login",
  "is_flagged": true,
  "probability": 0.8124,
  "threshold": 0.7405,
  "risk_score": 81.2,
  "risk_level": "HIGH",
  "verdict": "FRAUD_SUSPECTED",
  "recommendation": "Do NOT visit or submit sensitive credentials/passwords. High probability of deceptive or malicious destination.",
  "indicator_count": 3,
  "indicators": [
    {
      "id": "RAW_IP_HOSTNAME",
      "severity": "CRITICAL",
      "title": "Raw IP Address as Hostname",
      "description": "The URL uses a numeric IP address instead of a domain name, commonly used to bypass domain reputation checks and domain takedowns."
    },
    {
      "id": "PHISHING_KEYWORDS",
      "severity": "HIGH",
      "title": "Sensitive Phishing Keywords (3 detected)",
      "description": "Target URL contains high-risk keywords: login, security, update."
    },
    {
      "id": "UNENCRYPTED_HTTP",
      "severity": "LOW",
      "title": "Unencrypted HTTP Protocol",
      "description": "Traffic is sent unencrypted, making data susceptible to eavesdropping or tampering."
    }
  ],
  "latency_ms": 1.45,
  "features": {
    "url_length": 46,
    "domain_length": 12,
    "path_length": 34,
    "query_length": 0,
    "has_ip_address": 1,
    "has_https": 0,
    "has_shortener": 0,
    "suspicious_word_count": 3,
    "shannon_entropy": 4.12
  }
}
```

---

### 2. Check Batch URLs
`POST /api/v1/check-urls` (also aliases `POST /api/check-urls`)

**Request:**
```bash
curl -X POST "http://localhost:5000/api/v1/check-urls" \
  -H "Content-Type: application/json" \
  -d '{
    "urls": [
      "https://www.google.com/search?q=security",
      "https://bit.ly/free-gift-card-claim",
      "http://10.0.0.1/auth/login"
    ]
  }'
```

**Response (200 OK):**
```json
{
  "summary": {
    "total": 3,
    "flagged_count": 2,
    "safe_count": 1,
    "avg_probability": 0.582,
    "highest_risk_url": "http://10.0.0.1/auth/login",
    "highest_probability": 0.845,
    "total_latency_ms": 3.82
  },
  "results": [
    {
      "url": "https://www.google.com/search?q=security",
      "is_flagged": false,
      "probability": 0.082,
      "risk_score": 8.2,
      "risk_level": "SAFE",
      "verdict": "CLEAN"
    },
    {
      "url": "https://bit.ly/free-gift-card-claim",
      "is_flagged": true,
      "probability": 0.819,
      "risk_score": 81.9,
      "risk_level": "HIGH",
      "verdict": "FRAUD_SUSPECTED"
    }
  ]
}
```

---

### 3. Extract Raw Features
`POST /api/v1/extract-features`

**Request:**
```bash
curl -X POST "http://localhost:5000/api/v1/extract-features" \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com/test?token=xyz"}'
```

---

### 4. Model Metadata & Performance
`GET /api/v1/model/info`

Returns active model architecture, hyperparameters, ROC-AUC score, decision threshold, and training metrics for all candidate models evaluated during training.

---

### 5. Submit Feedback / Retraining Reports
`POST /api/v1/reports`

**Request:**
```bash
curl -X POST "http://localhost:5000/api/v1/reports" \
  -H "Content-Type: application/json" \
  -d '{
    "url": "https://bloomberg.com/tosv2.html",
    "reported_as": "FALSE_POSITIVE",
    "actual_status": "LEGITIMATE",
    "notes": "Terms of service page falsely flagged due to newsletter token patterns",
    "submitted_by": "security-analyst@example.com"
  }'
```

---

## ⚙️ Configuration (.env)

| Variable | Default | Description |
|---|---|---|
| `HOST` | `0.0.0.0` | Binding host IP |
| `PORT` | `5000` | Port number |
| `DEBUG` | `false` | Enable Flask debug mode |
| `CORS_ORIGINS` | `*` | Allowed CORS origins (comma-separated) |
| `THRESHOLD_OVERRIDE`| `None` | Override the recommended `0.7405` decision threshold |
| `MAX_BATCH_SIZE` | `500` | Maximum URLs permitted per batch request |
| `DATABASE_PATH` | `data/url_fraud.db` | Path to SQLite audit/feedback database |
