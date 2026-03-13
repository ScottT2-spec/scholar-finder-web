# ScholarFinder

source code for [scholarfinder.pythonanywhere.com](https://scholarfinder.pythonanywhere.com)

flask app with SQLite, 12 Groq API keys (LLaMA 3.3 70B), and a daily scraper.

## features

- 400+ scholarships, 200+ universities, 195+ opportunities
- smart matching (country + field + level + interests scoring)
- 6 AI agents (scout, writer, profiler, tracker, advisor, prep)
- essay rater and resume reviewer (strict scoring)
- cost of living for 85 cities, visa guides for 49 countries
- test prep, FAQ, email verification, Google OAuth

## ai setup

12 Groq keys with round-robin rotation. auto-skips rate-limited keys, retries with next available. 30s retry budget.

## scraper

runs daily on GitHub Actions. 40+ sources, BeautifulSoup + AI extraction, auto-dedup, deadline parsing.

## running

hosted on PythonAnywhere free tier. set your Groq keys as env vars (`GROQ_KEY_1` through `GROQ_KEY_12`).
