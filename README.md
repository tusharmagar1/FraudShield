<div align="center">

<img src="https://capsule-render.vercel.app/api?type=rect&color=0:0D1117,100:1B2735&height=180&text=FraudShield&fontSize=50&fontColor=00FF9C&fontAlignY=55&desc=%3E%20phishing_detection_engine.exe%20--status%20ACTIVE&descAlignY=80&descSize=15&descColor=3B82F6" width="100%"/>

<img src="https://readme-typing-svg.demolab.com?font=Fira+Code&weight=600&size=20&duration=2200&pause=700&color=00FF9C&center=true&vCenter=true&width=750&lines=%3E+Scanning+URL...;%3E+Extracting+security+features...;%3E+Random+Forest+Classifier+loaded...;%3E+Verdict%3A+SAFE+%E2%9C%93+%2F+PHISHING+%E2%9C%97" />

<br/>

![Python](https://img.shields.io/badge/-Python-000000?style=flat-square&logo=python)
![Flask](https://img.shields.io/badge/-Flask-000000?style=flat-square&logo=flask)
![scikit--learn](https://img.shields.io/badge/-scikit--learn-000000?style=flat-square&logo=scikit-learn)
![Chart.js](https://img.shields.io/badge/-Chart.js-000000?style=flat-square&logo=chartdotjs)
![SQLite](https://img.shields.io/badge/-SQLite-000000?style=flat-square&logo=sqlite)

<sub>🟢 SYSTEM STATUS: <b>OPERATIONAL</b> &nbsp;|&nbsp; 🛡 MODEL: <b>Random Forest</b> &nbsp;|&nbsp; 📡 THREAT FEED: <b>LIVE</b></sub>

</div>

<br/>

```
╔══════════════════════════════════════════════════════════════╗
║  FraudShield — an AI security layer between you and the link  ║
║  you were about to click.                                     ║
╚══════════════════════════════════════════════════════════════╝
```

FraudShield inspects URLs the way a security analyst would — pulling structural, lexical, and domain-level signals, then feeding them through a trained classifier to hand back a verdict: **safe** or **phishing**. Everything around that verdict — the dashboard, the map, the game — exists to make that decision explainable and the habit of checking a link stick.

---

## 🧩 Modules

<table>
<tr>
<td width="50%" valign="top">

**🔍 `scan.url()`**
Single & bulk URL scanning, QR code intake, full risk-score breakdown per link.

**📊 `dashboard.render()`**
Chart.js-powered view of scan volume, threat categories, and risk trends over time.

**🌍 `threatmap.live()`**
Global visualization of where flagged threats are geographically concentrated.

</td>
<td width="50%" valign="top">

**🤖 `analyst.chat()`**
An in-app AI assistant that explains *why* a URL was flagged, in plain English.

**🕒 `history.log()`**
Timestamped record of every scan — searchable, filterable, exportable.

**🎮 `spotthephish.play()`**
A timed mini-game that trains the human in the loop to spot fakes on sight.

</td>
</tr>
</table>

---

## 📸 Interface

> Swap these placeholders for real captures once you've got them — this section sells the project harder than any badge does.

| Scanner | Analytics |
|---|---|
| `assets/scan-dashboard.png` | `assets/analytics-dashboard.png` |

| Threat Map | Scan History |
|---|---|
| `assets/threat-map.png` | `assets/history-page.png` |

| AI Analyst | Spot The Phish |
|---|---|
| `assets/ai-analyst.png` | `assets/spot-the-phish.png` |

---

## 🧠 Detection Pipeline

```
   URL Input
      │
      ▼
┌─────────────────┐    length, hyphens, dots, HTTPS,
│ Feature Extract  │ ─▶ IP-in-URL, suspicious chars,
└─────────────────┘    domain age & registrar signals
      │
      ▼
┌─────────────────┐
│ Random Forest    │ ──▶  probability score (0–100)
│ Classifier        │
└─────────────────┘
      │
      ▼
   ┌───────┬────────┐
   │ SAFE ✅ │ PHISHING ❌ │
   └───────┴────────┘
      │
      ▼
  Logged → Dashboard → Threat Map
```

<details>
<summary><b>Show the six-stage build pipeline</b></summary>

<br/>

| Stage | What Happens |
|---|---|
| 1️⃣ Data Collection | Gather labeled phishing / legitimate URL datasets |
| 2️⃣ Preprocessing | Clean, deduplicate, normalize |
| 3️⃣ Feature Engineering | Derive URL length, HTTPS flag, hyphen/dot counts, IP presence, domain info |
| 4️⃣ Training | Fit a Random Forest Classifier on labeled data |
| 5️⃣ Inference | Classify new URLs as Safe / Phishing |
| 6️⃣ Visualization | Push results into the live dashboard |

</details>

---

## ⚙️ Deploy It Locally

```bash
# 1. Clone
git clone https://github.com/tusharmagar1/FraudShield.git
cd FraudShield

# 2. Virtual environment
python -m venv venv
source venv/bin/activate      # Windows: venv\Scripts\activate

# 3. Install
pip install -r requirements.txt

# 4. Launch
python app.py
```

<div align="center">
<img src="https://img.shields.io/badge/-http%3A%2F%2F127.0.0.1%3A5000-00FF9C?style=flat-square&logoColor=black"/>
</div>

---

## 📂 File Tree

```text
FraudShield
│
├── assets/                 # screenshots
├── instance/database.db    # scan history storage
├── static/{css,js,images}
├── templates/              # index, dashboard, history
├── model.pkl                # trained classifier
├── app.py                   # Flask entrypoint
├── requirements.txt
└── README.md
```

---

## 📡 Threat Radar (Roadmap)

```
[■■■■■■■■■□] Live threat monitoring
[■■■■■□□□□□] Email phishing detection
[■■■□□□□□□□] Browser extension
[■■□□□□□□□□] User authentication
[■□□□□□□□□□] Cloud deployment + REST API
[□□□□□□□□□□] Mobile app · Deep Learning model · Real-time alerts
```

---

## 🤝 Contributing

```bash
git checkout -b feature/AmazingFeature
git commit -m "Add AmazingFeature"
git push origin feature/AmazingFeature
```
Then open a PR. Good first contributions: UI/UX polish, dataset expansion, model tuning, docs, bug hunts.

---

<div align="center">

## 👨‍💻 Author

**Tushar Magar** — AI & Machine Learning Enthusiast

<a href="https://github.com/tusharmagar1">
<img src="https://img.shields.io/badge/GitHub-tusharmagar1-00FF9C?style=for-the-badge&logo=github&logoColor=black"/>
</a>

<br/><br/>

⭐ **Star this repo if FraudShield helped you dodge a bad link.**

<sub>Licensed under MIT · Made with Python, Flask & a healthy distrust of URLs</sub>

<img src="https://capsule-render.vercel.app/api?type=rect&color=0:1B2735,100:0D1117&height=100&section=footer" width="100%"/>

</div>
