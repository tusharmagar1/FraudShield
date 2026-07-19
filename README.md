<div align="center">

# 🛡️ FraudShield

An AI-powered phishing & URL threat detection dashboard — scan single or bulk URLs,
visualize threat activity in real time, and learn to spot phishing attempts yourself,
all in one Flask + Machine Learning web app.

[![python](https://img.shields.io/badge/python-Flask-blue?logo=python&logoColor=white)](#)
[![ml](https://img.shields.io/badge/ML-Random%20Forest-orange)](#)
[![status](https://img.shields.io/badge/status-portfolio--project-blue)](#)
[![license](https://img.shields.io/badge/license-MIT-green)](#-license)

[Features](#-features) • [Screenshots](#-screenshots) • [Setup](#%EF%B8%8F-installation--setup) • [Tech Stack](#%EF%B8%8F-tech-stack) • [Use Cases](#-sample-use-cases)

</div>

---

## 📌 Overview

FraudShield analyzes URLs and web patterns to flag phishing attempts and malicious
domains, using a trained Random Forest classifier behind a Flask backend. It's built
as a full security-dashboard experience rather than a single prediction endpoint —
scanning, analytics, threat visualization, scan history, an AI assistant for
security questions, and even a phishing-awareness training game are all part of the
same app.

---

## 🚀 Features

### 🔍 URL Threat Scanner
Analyzes single or bulk URLs to detect phishing attempts, malicious domains,
suspicious keywords, and unsafe web patterns using AI-powered threat intelligence.
- Single URL scanning
- Bulk URL analysis
- QR code scanning
- Threat level detection
- Feature-based security analysis
- Real-time phishing detection

### 📊 Analytics Dashboard
Visual insights into detected threats, scan activity, and risk trends through
interactive Chart.js visualizations.
- Threat severity breakdown
- Risk trend visualization
- Flagged domain monitoring
- Scan statistics

### 🌍 Live Threat Map
Visualizes global cyber threats and attack origins in real time.
- Live cyber-attack visualization
- Global threat tracking
- Threat severity indicators
- Attack source monitoring

### 🕒 Scan History
Stores previously scanned URLs and their detailed threat analysis results.
- Previous scan records
- Safe/Unsafe classification
- Risk percentage tracking
- Timestamped scan history

### 🤖 AI Security Analyst
An intelligent chatbot assistant that helps users understand cybersecurity threats,
phishing techniques, and online safety practices.

### 🎮 Spot The Phish Game
An interactive training game that challenges users to identify phishing URLs and
suspicious websites under time pressure, with difficulty levels and score tracking.

### 📝 Feedback System
Users can submit feedback on predictions, helping guide future model improvements.

---

## 📸 Screenshots

| URL Threat Scanner | Analytics Dashboard |
|:---:|:---:|
| ![URL Scanner](assets/scan-dashboard.png) | ![Analytics Dashboard](assets/analytics-dashboard.png) |

| Live Threat Map | Scan History |
|:---:|:---:|
| ![Threat Map](assets/threat-map.png) | ![Scan History](assets/history-page.png) |

| AI Security Analyst | Spot The Phish Game |
|:---:|:---:|
| ![AI Analyst](assets/ai-analyst.png) | ![Spot The Phish](assets/spot-the-phish.png) |

---

## 🛠 Tech Stack

| Layer | Tools |
|---|---|
| **Backend** | Python, Flask |
| **Machine Learning** | Scikit-learn (Random Forest), Pandas, NumPy |
| **Frontend** | HTML, CSS, JavaScript, Chart.js |
| **Database** | SQLite |

---

## 🧠 Machine Learning Workflow

1. Data collection (URL / domain features)
2. Data preprocessing
3. Feature engineering
4. Model training (Random Forest)
5. Threat prediction
6. Result visualization on the dashboard

---

## 📂 Project Structure

```bash
FraudShield/
│
├── app.py                  # Main Flask application
├── requirements.txt        # Python dependencies
├── model.pkl               # Trained ML model
├── templates/               # HTML templates
├── static/                   # CSS, JS, images
├── instance/                 # SQLite database
├── assets/                   # Screenshots for README
├── README.md                 # Project documentation
└── .gitignore                # Ignored files
```

---

## ⚙️ Installation & Setup

**1. Clone the repository**
```bash
git clone https://github.com/tusharmagar1/FraudShield.git
cd FraudShield
```

**2. Create a virtual environment (recommended)**

Windows:
```bash
python -m venv venv
venv\Scripts\activate
```

Mac/Linux:
```bash
python3 -m venv venv
source venv/bin/activate
```

**3. Install dependencies**
```bash
pip install -r requirements.txt
```

**4. Run the application**
```bash
python app.py
```

**5. Open it in your browser**
```
http://127.0.0.1:5000
```

---

## 🧪 Sample Use Cases

- Phishing link detection before clicking a suspicious URL
- Security awareness training for teams (via Spot The Phish)
- Monitoring flagged domains over time
- Educating non-technical users on phishing red flags via the AI Security Analyst

---

## 📈 Future Improvements

- Real-time fraud/threat monitoring with live alerts
- Cloud deployment
- User authentication system
- REST API for third-party integration
- Deep learning model integration
- Email/SMS threat alerts

---

## 🤝 Contributing

Contributions are welcome!

1. Fork the repository
2. Create a new branch
   ```bash
   git checkout -b feature-name
   ```
3. Make your changes
4. Commit your changes
   ```bash
   git commit -m "Added new feature"
   ```
5. Push to GitHub
   ```bash
   git push origin feature-name
   ```
6. Open a Pull Request

**Contribution ideas:** improve UI/UX, enhance model accuracy, add new cybersecurity
features, fix bugs, optimize performance.

---

## 📄 License

This project is licensed under the [MIT License](LICENSE).

---

## 👤 Author

**Tushar Magar**

- GitHub: [@tusharmagar1](https://github.com/tusharmagar1)
- LinkedIn: [tushar-magar](https://www.linkedin.com/in/tushar-magar-7b80a2255)
- Email: tusharmagar321@gmail.com

## ⭐ Support

If you found this project useful, please consider giving it a ⭐ on GitHub.
