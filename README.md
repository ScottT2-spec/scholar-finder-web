# 🎓 ScholarFinder

**Find your perfect scholarship match.** A free platform helping students discover scholarships, universities, and study abroad opportunities worldwide.

🔗 **Live:** [scholarfinder.pythonanywhere.com](https://scholarfinder.pythonanywhere.com)

---

## ✨ Features

- 🎯 **Smart Matching** — Scholarships ranked by how well they fit your profile
- 📌 **Save & Track** — Bookmark opportunities and track application status (live-updating dashboard)
- 🏫 **University Explorer** — Browse 184+ universities with rankings and tuition
- 💰 **Cost Comparison** — Compare living costs across 51+ student cities
- 🛂 **Visa Guides** — Student visa info for 26 countries
- 📝 **Test Prep** — IELTS, TOEFL, SAT, GRE tips and resources

### 🤖 AI-Powered Tools
- **Essay Rater** — Instant feedback on personal statements and motivation letters
- **Resume Review** — AI analysis of structure and impact
- **School Matcher** — Find universities that fit your profile
- **6 AI Agents** — Scout, Writer, Profiler, Tracker, Advisor, and Prep — working together to guide your scholarship journey

### 📊 Database
- 487+ scholarships
- 184+ universities
- 138+ opportunities
- 51+ cities

---

## 🛠️ Tech Stack

- **Backend:** Python / Flask
- **Frontend:** Jinja2 templates, vanilla JS, CSS
- **AI:** Groq API (LLaMA 3.3 70B)
- **Auth:** Email/password + Google OAuth
- **Hosting:** PythonAnywhere
- **Data:** SQLite + JSON

---

## 🚀 Setup

### 1. Clone
```bash
git clone https://github.com/ScottT2-spec/scholar-finder-web.git
cd scholar-finder-web
```

### 2. Install dependencies
```bash
pip install -r requirements.txt
```

```

### 4. Run
```bash
python app.py
```

---

## 📁 Project Structure

```
├── app.py                  # Main Flask application
├── scholarship_scraper.py  # Automated scholarship scraper
├── templates/              # Jinja2 HTML templates
│   ├── base.html           # Base layout (nav, theme, particles)
│   ├── index.html          # Homepage (typewriter, counter, AI agents)
│   ├── dashboard.html      # User dashboard (live-updating)
│   ├── scholarships.html   # Scholarship search & filter
│   └── ...                 # 15+ more pages
├── data/                   # JSON data files
│   ├── scholarships.json   # Scholarship database
│   ├── universities.json   # University database
│   └── ...
├── .env                    # Secrets (not in repo)
└── requirements.txt
```

---

## 🔐 Security

All sensitive data (API keys, OAuth credentials, passwords) are stored in `.env` and excluded from version control via `.gitignore`. Zero hardcoded secrets.

---

## 👤 Author



---

## 📄 License

This project is proprietary. All rights reserved.
