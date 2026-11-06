<div align="center">

# 🎣 PhishNet

**AI-powered, real-time phishing URL detection as a Chrome extension**

Warns you *before* you enter your credentials on a fake website.

![Python](https://img.shields.io/badge/Python-3.10+-3776AB?logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-009688?logo=fastapi&logoColor=white)
![JavaScript](https://img.shields.io/badge/JavaScript-F7DF1E?logo=javascript&logoColor=black)
![Chrome Extension](https://img.shields.io/badge/Chrome-Extension-4285F4?logo=googlechrome&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green)

</div>

---

## 📌 Overview

Phishing is still one of the most common ways attackers steal passwords and money. **PhishNet** checks every URL you visit in real time. It combines a **machine learning classifier** with **threat intelligence feeds** (OpenPhish and PhishTank) and shows a clear warning if the site looks dangerous.

## ✨ Features

- ⚡ **Real-time detection** while you browse
- 🤖 **ML-based classification** using URL features
- 🛡️ **Threat intelligence check** with OpenPhish and PhishTank
- 🔔 **Instant warning** before you type credentials
- 🧪 **Multiple models compared** to pick the best performer
- 🔌 **Lightweight Chrome extension** with a FastAPI backend

## 🏗️ Architecture

```
┌──────────────────┐   URL    ┌─────────────────────┐
│ Chrome Extension │ ───────▶ │   FastAPI Backend   │
│   (JavaScript)   │          │  Feature Extraction │
└──────────────────┘          │   + ML Prediction   │
         ▲                    │   + Feed Lookup     │
         │   Verdict          └──────────┬──────────┘
         └───────────────────────────────┤
                                         ▼
                          OpenPhish / PhishTank feeds
```

**How it works**

1. The extension reads the URL of the page you open.
2. It sends the URL to the FastAPI backend.
3. The backend extracts features and checks the threat feeds.
4. The ML model predicts **Safe** or **Phishing**.
5. The extension shows the result and warns you if needed.

## 🔍 Features Used for Detection

| Feature | Why it matters |
|---|---|
| URL length | Phishing URLs are often very long |
| HTTPS presence | Missing HTTPS is a red flag |
| Domain age | New domains are more suspicious |
| IP address in URL | Real sites rarely use raw IPs |
| Number of subdomains | Many subdomains can hide the real domain |
| Suspicious keywords | Words like `login`, `verify`, `secure` |
| Special characters | Symbols like `@`, `-`, `//` are used to trick users |

## 🤖 ML Models Compared

| Model | Accuracy | Precision | Recall | F1 |
|---|---|---|---|---|
| Logistic Regression | _TBD_ | _TBD_ | _TBD_ | _TBD_ |
| Decision Tree | _TBD_ | _TBD_ | _TBD_ | _TBD_ |
| Random Forest | _TBD_ | _TBD_ | _TBD_ | _TBD_ |
| SVM | _TBD_ | _TBD_ | _TBD_ | _TBD_ |
| XGBoost | _TBD_ | _TBD_ | _TBD_ | _TBD_ |

> Replace `_TBD_` with your real results.

## 🧰 Tech Stack

| Layer | Technology |
|---|---|
| Extension | JavaScript, Chrome Extension (Manifest V3) |
| Backend | Python, FastAPI |
| ML | scikit-learn, XGBoost, pandas |
| Threat Intel | OpenPhish, PhishTank |

## 📁 Project Structure

```
phishnet/
├── extension/        # Chrome extension (manifest, popup, content/background scripts)
├── backend/          # FastAPI app, feature extraction, prediction
├── model/            # Training notebooks and saved models
├── data/             # Datasets (not committed if large)
├── requirements.txt
└── README.md
```

> Update this tree to match your actual folders.

## 🚀 Getting Started

### Prerequisites

- Python 3.10+
- Google Chrome
- Git

### 1. Clone the repository

```bash
git clone https://github.com/realeesh17/phishnet.git
cd phishnet
```

### 2. Run the backend

```bash
cd backend
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
uvicorn main:app --reload
```

The API runs at `http://127.0.0.1:8000`. Docs are at `/docs`.

### 3. Load the extension in Chrome

1. Open `chrome://extensions`
2. Turn on **Developer mode**
3. Click **Load unpacked**
4. Select the `extension/` folder

## 📡 API Example

**Request**

```http
POST /predict
Content-Type: application/json

{ "url": "http://secure-login-paypal.example.xyz/verify" }
```

**Response**

```json
{
  "url": "http://secure-login-paypal.example.xyz/verify",
  "verdict": "phishing",
  "confidence": 0.97,
  "in_threat_feed": false
}
```

> Adjust the endpoint and fields to match your code.

## 🗺️ Roadmap

- [ ] Add page-content analysis (forms, hidden fields)
- [ ] Cache results for faster checks
- [ ] Add user "report a site" button
- [ ] Publish to the Chrome Web Store
- [ ] Support Firefox and Edge

## ⚠️ Limitations

- No detector is 100% accurate. Always stay careful with links.
- New phishing sites may not be in the threat feeds yet.
- Domain age lookups can be slow or fail for some domains.

## 🤝 Contributing

Pull requests are welcome.

1. Fork the repo
2. Create a branch: `git checkout -b feature/your-feature`
3. Commit your changes
4. Open a Pull Request

## 📄 License

Distributed under the MIT License. See `LICENSE` for details.

## 👤 Author

**Rakesh Babriya**
- GitHub: [@realeesh17](https://github.com/realeesh17)
- LinkedIn: [rakeshbabariya](https://linkedin.com/in/rakeshbabariya)

---

<div align="center">

⭐ If you find this project useful, please give it a star!

</div>
