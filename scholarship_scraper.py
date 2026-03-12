#!/usr/bin/env python3
"""
ScholarFinder — Scholarship Scraper & Cleaner
================================================
Run daily via PythonAnywhere scheduled tasks:
  python3 /home/scholarfinder/scholar-finder-web/scholarship_scraper.py

What it does:
1. Scrapes scholarship sources for new listings
2. Removes expired scholarships (past deadline)
3. Deduplicates entries
4. Logs all changes

Sources (10 total):
- Opportunities for Africans (+ page 2)
- After School Africa
- Scholars4Dev
- Scholarship Positions
- Opportunity Desk (+ page 2)
- Scholarships Corner
- Youth Opportunities (general + postgrad)

NOTE: Scraping runs on GitHub Actions (not PA) because
PythonAnywhere free tier blocks outbound HTTP.
"""

import os
import sys
import json
import re
import hashlib
import logging
from datetime import datetime, timedelta
from collections import OrderedDict

# Add project to path
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, SCRIPT_DIR)

# Load .env
env_path = os.path.join(SCRIPT_DIR, '.env')
if os.path.exists(env_path):
    with open(env_path) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith('#') and '=' in line:
                k, v = line.split('=', 1)
                os.environ.setdefault(k.strip(), v.strip())

# Support both GROQ_API_KEY (single) and GROQ_KEY_1..9 (rotation pool)
GROQ_API_KEY = os.environ.get('GROQ_API_KEY', '')
if not GROQ_API_KEY:
    # Fall back to the key pool used by app.py
    for i in range(1, 10):
        k = os.environ.get(f'GROQ_KEY_{i}', '')
        if k:
            GROQ_API_KEY = k
            break

# Groq key pool for rotation (spreads rate limits across accounts)
_GROQ_KEYS = [os.environ.get(f'GROQ_KEY_{i}', '') for i in range(1, 10)]
_GROQ_KEYS = [k for k in _GROQ_KEYS if k]
if GROQ_API_KEY and GROQ_API_KEY not in _GROQ_KEYS:
    _GROQ_KEYS.insert(0, GROQ_API_KEY)
_groq_idx = 0

def _get_next_groq_key():
    """Round-robin through available Groq keys"""
    global _groq_idx
    if not _GROQ_KEYS:
        return GROQ_API_KEY
    key = _GROQ_KEYS[_groq_idx % len(_GROQ_KEYS)]
    _groq_idx += 1
    return key

# Paths
DATA_DIR = os.path.join(SCRIPT_DIR, 'data')
SCHOLARSHIPS_PATH = os.path.join(DATA_DIR, 'scholarships.json')
ARCHIVE_PATH = os.path.join(DATA_DIR, 'scholarships_archived.json')
LOG_DIR = os.path.join(SCRIPT_DIR, 'logs')
os.makedirs(LOG_DIR, exist_ok=True)
os.makedirs(DATA_DIR, exist_ok=True)

# Logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler(os.path.join(LOG_DIR, 'scraper.log')),
        logging.StreamHandler()
    ]
)
log = logging.getLogger('scraper')

# ============================================
# SCHOLARSHIP SOURCES
# ============================================
SOURCES = [
    # --- Africa-focused ---
    {
        'name': 'Opportunities for Africans',
        'url': 'https://www.opportunitiesforafricans.com/category/scholarships/',
        'type': 'html',
        'selector': 'article',
    },
    {
        'name': 'After School Africa',
        'url': 'https://www.afterschoolafrica.com/scholarship/',
        'type': 'html',
        'selector': '.gb-query-loop-item',  # Uses GenerateBlocks grid, not <article>
    },
    {
        'name': 'Scholars4Dev',
        'url': 'https://www.scholars4dev.com/',
        'type': 'html',
        'selector': '.post',  # Uses .post class, not <article>
    },
    # --- International / Global ---
    {
        'name': 'Opportunity Desk',
        'url': 'https://opportunitydesk.org/tag/scholarships/',
        'type': 'html',
        'selector': 'article',
    },
    {
        'name': 'Scholarships Corner',
        'url': 'https://scholarshipscorner.website/scholarships/',
        'type': 'html',
        'selector': 'article',
    },
    {
        'name': 'Youth Opportunities (Scholarships)',
        'url': 'https://www.youthop.com/scholarships',
        'type': 'html',
        'selector': 'article, .card',  # May use card layout
    },
    {
        'name': 'Youth Opportunities (Postgrad)',
        'url': 'https://www.youthop.com/scholarships/post-graduate',
        'type': 'html',
        'selector': 'article, .card',
    },
    {
        'name': 'Scholarship Positions',
        'url': 'https://scholarship-positions.com/',
        'type': 'html',
        'selector': '.gb-query-loop-item, .post',  # Uses GenerateBlocks grid
    },
    # --- More Africa/developing world sources ---
    {
        'name': 'Opportunities for Africans (Page 2)',
        'url': 'https://www.opportunitiesforafricans.com/category/scholarships/page/2/',
        'type': 'html',
        'selector': 'article',
    },
    {
        'name': 'Opportunity Desk (Page 2)',
        'url': 'https://opportunitydesk.org/tag/scholarships/page/2/',
        'type': 'html',
        'selector': 'article',
    },
]

# ============================================
# UTILITIES
# ============================================

def load_scholarships():
    """Load current scholarship data"""
    if os.path.exists(SCHOLARSHIPS_PATH):
        with open(SCHOLARSHIPS_PATH, 'r') as f:
            return json.load(f)
    return []


def save_scholarships(data):
    """Save scholarship data with backup"""
    # Backup current file
    if os.path.exists(SCHOLARSHIPS_PATH):
        backup_path = SCHOLARSHIPS_PATH + '.bak'
        with open(SCHOLARSHIPS_PATH, 'r') as f:
            with open(backup_path, 'w') as bf:
                bf.write(f.read())

    with open(SCHOLARSHIPS_PATH, 'w') as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    log.info(f'Saved {len(data)} scholarships')


def load_archive():
    """Load archived (expired) scholarships"""
    if os.path.exists(ARCHIVE_PATH):
        with open(ARCHIVE_PATH, 'r') as f:
            return json.load(f)
    return []


def save_archive(data):
    """Save archived scholarships"""
    with open(ARCHIVE_PATH, 'w') as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


def scholarship_id(s):
    """Generate unique ID for a scholarship based on name + university"""
    key = (s.get('name', '') + '|' + s.get('university', '')).lower().strip()
    return hashlib.md5(key.encode()).hexdigest()[:12]


def parse_deadline(deadline_str):
    """Try to parse various deadline formats into a date"""
    if not deadline_str:
        return None

    deadline_str = deadline_str.strip()

    # Skip non-date deadlines
    skip_words = ['varies', 'rolling', 'open', 'ongoing', 'tbd', 'tba', 'check', 'multiple', 'annual']
    if any(w in deadline_str.lower() for w in skip_words):
        return None

    # Common formats
    formats = [
        '%B %d, %Y',       # March 15, 2026
        '%d %B %Y',        # 15 March 2026
        '%B %Y',           # March 2026 (assume end of month)
        '%d/%m/%Y',        # 15/03/2026
        '%m/%d/%Y',        # 03/15/2026
        '%Y-%m-%d',        # 2026-03-15
        '%d-%m-%Y',        # 15-03-2026
        '%b %d, %Y',       # Mar 15, 2026
        '%d %b %Y',        # 15 Mar 2026
        '%b %Y',           # Mar 2026
    ]

    for fmt in formats:
        try:
            dt = datetime.strptime(deadline_str, fmt)
            # If only month+year, use last day of month
            if '%d' not in fmt:
                if dt.month == 12:
                    dt = dt.replace(day=31)
                else:
                    dt = (dt.replace(month=dt.month + 1, day=1) - timedelta(days=1))
            return dt
        except ValueError:
            continue

    # Try to extract year and month from messy strings
    year_match = re.search(r'20\d{2}', deadline_str)
    if year_match:
        year = int(year_match.group())
        months = {
            'jan': 1, 'feb': 2, 'mar': 3, 'apr': 4, 'may': 5, 'jun': 6,
            'jul': 7, 'aug': 8, 'sep': 9, 'oct': 10, 'nov': 11, 'dec': 12
        }
        for abbr, num in months.items():
            if abbr in deadline_str.lower():
                day_match = re.search(r'\b(\d{1,2})\b', deadline_str)
                day = int(day_match.group()) if day_match and 1 <= int(day_match.group()) <= 31 else 28
                try:
                    return datetime(year, num, min(day, 28))
                except ValueError:
                    pass

    return None


# ============================================
# SCRAPING
# ============================================

def fetch_page(url, timeout=20):
    """Fetch a URL and return the HTML content"""
    import requests
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (compatible; ScholarFinderBot/1.0; +https://scholarfinder.pythonanywhere.com)'
        }
        resp = requests.get(url, headers=headers, timeout=timeout)
        resp.raise_for_status()
        return resp.text
    except Exception as e:
        log.error(f'Failed to fetch {url}: {e}')
        return None


def extract_links_from_html(html, base_url, selector='article'):
    """Extract scholarship article links from an HTML page"""
    try:
        from bs4 import BeautifulSoup
        from urllib.parse import urljoin
        soup = BeautifulSoup(html, 'html.parser')
        links = []
        seen_urls = set()

        articles = soup.select(selector)
        for article in articles[:20]:  # Limit to 20 articles per source
            # Strategy: prefer heading link (h2/h3/h4 > a), fall back to first non-category link
            a_tag = None
            title = ''

            # Try heading links first (most reliable for article URLs)
            h_tag = article.find(['h2', 'h3', 'h4'])
            if h_tag:
                a_tag = h_tag.find('a', href=True)
                title = h_tag.get_text(strip=True)

            # Fall back to first link that looks like an article (not a category/tag)
            if not a_tag:
                for candidate in article.find_all('a', href=True):
                    href = candidate['href']
                    # Skip category, tag, author, and pagination links
                    if any(skip in href for skip in ['/category/', '/tag/', '/author/', '/page/', '#']):
                        continue
                    a_tag = candidate
                    if not title:
                        title = candidate.get_text(strip=True)
                    break

            if a_tag:
                href = a_tag['href']
                if not href.startswith('http'):
                    href = urljoin(base_url, href)

                if not title:
                    title = a_tag.get_text(strip=True)

                # Skip duplicates and short/generic titles
                if title and len(title) > 10 and href not in seen_urls:
                    seen_urls.add(href)
                    links.append({'title': title, 'url': href})

        return links
    except ImportError:
        log.error('BeautifulSoup not installed. Run: pip install beautifulsoup4')
        return []
    except Exception as e:
        log.error(f'Error parsing HTML: {e}')
        return []


def extract_scholarship_from_page(url, title=''):
    """Fetch a scholarship page and extract details using AI"""
    html = fetch_page(url)
    if not html:
        return None

    try:
        from bs4 import BeautifulSoup
        soup = BeautifulSoup(html, 'html.parser')

        # Remove scripts and styles
        for tag in soup(['script', 'style', 'nav', 'footer', 'header', 'aside']):
            tag.decompose()

        # Get main content
        main = soup.find('main') or soup.find('article') or soup.find('div', class_=re.compile(r'content|entry|post'))
        text = main.get_text(separator='\n', strip=True) if main else soup.get_text(separator='\n', strip=True)

        # Truncate to save tokens
        text = text[:3000]
    except Exception:
        text = ''

    if not text or len(text) < 100:
        return None

    # Use AI to extract structured scholarship data
    if not GROQ_API_KEY:
        log.warning('No GROQ_API_KEY — skipping AI extraction')
        return None

    return ai_extract_scholarship(text, url, title)


def ai_extract_scholarship(text, url, title=''):
    """Use Groq AI to extract scholarship data from page text"""
    import requests

    # Rotate through available Groq keys
    api_key = _get_next_groq_key()

    prompt = f"""Extract scholarship information from this text. Return ONLY valid JSON (no markdown, no explanation).
If this is NOT about a specific scholarship, return: {{"skip": true}}

Required JSON format:
{{
  "name": "Scholarship Name",
  "university": "University or Organization",
  "country": "Country where you study",
  "field": ["field1", "field2"],
  "level": ["undergraduate", "masters", "phd"],
  "funding": "What's covered (e.g., Full tuition + stipend)",
  "deadline": "Month Day, Year (e.g., March 15, 2026)",
  "description": "One sentence summary"
}}

For "level", only use: undergraduate, masters, phd, postdoctoral
For "field", use lowercase. If open to all fields, use ["any"]
For "deadline", if not clear, use "Varies"

Page title: {title}
Page URL: {url}

Text:
{text}"""

    try:
        resp = requests.post(
            'https://api.groq.com/openai/v1/chat/completions',
            json={
                'model': 'llama-3.3-70b-versatile',
                'messages': [
                    {'role': 'system', 'content': 'You extract scholarship data into JSON. Return ONLY valid JSON.'},
                    {'role': 'user', 'content': prompt}
                ],
                'max_tokens': 500,
                'temperature': 0.1
            },
            headers={'Authorization': 'Bearer ' + api_key},
            timeout=20
        )

        if resp.status_code != 200:
            log.error(f'Groq API error: {resp.status_code}')
            return None

        content = resp.json()['choices'][0]['message']['content'].strip()

        # Clean up response — remove markdown code blocks if present
        content = re.sub(r'^```(?:json)?\s*', '', content)
        content = re.sub(r'\s*```$', '', content)

        data = json.loads(content)

        if data.get('skip'):
            return None

        # Validate required fields
        if not data.get('name') or len(data['name']) < 5:
            return None

        # Normalize
        data['link'] = url
        if isinstance(data.get('field'), str):
            data['field'] = [data['field']]
        if isinstance(data.get('level'), str):
            data['level'] = [data['level']]

        data['field'] = [f.lower().strip() for f in data.get('field', ['any'])]
        data['level'] = [l.lower().strip() for l in data.get('level', [])]

        return data

    except json.JSONDecodeError as e:
        log.error(f'Failed to parse AI response as JSON: {e}')
        return None
    except Exception as e:
        log.error(f'AI extraction error: {e}')
        return None


# ============================================
# CLEANUP — Remove expired scholarships
# ============================================

def clean_expired(scholarships):
    """Move expired scholarships to archive"""
    now = datetime.now()
    grace_period = timedelta(days=7)  # Keep 7 days past deadline

    active = []
    expired = []

    for s in scholarships:
        dl = parse_deadline(s.get('deadline', ''))
        if dl and dl + grace_period < now:
            expired.append(s)
            log.info(f'EXPIRED: {s["name"]} (deadline: {s.get("deadline")})')
        else:
            active.append(s)

    return active, expired


# ============================================
# DEDUPLICATION
# ============================================

def deduplicate(scholarships):
    """Remove duplicate scholarships based on name similarity"""
    seen = {}
    unique = []

    for s in scholarships:
        sid = scholarship_id(s)
        # Also check by normalized name
        norm_name = re.sub(r'[^a-z0-9]', '', s.get('name', '').lower())

        if sid not in seen and norm_name not in seen:
            seen[sid] = True
            if norm_name:
                seen[norm_name] = True
            unique.append(s)

    removed = len(scholarships) - len(unique)
    if removed:
        log.info(f'Removed {removed} duplicates')

    return unique


# ============================================
# MAIN SCRAPER
# ============================================

def scrape_all_sources():
    """Scrape all configured sources and return new scholarships"""
    new_scholarships = []
    total_links = 0

    for source in SOURCES:
        log.info(f'Scraping: {source["name"]} ({source["url"]})')

        html = fetch_page(source['url'])
        if not html:
            continue

        links = extract_links_from_html(html, source['url'], source.get('selector', 'article'))
        log.info(f'  Found {len(links)} article links')
        total_links += len(links)

        # Process each article (limit to 8 per source to save API calls)
        import time
        for link_info in links[:8]:
            log.info(f'  Processing: {link_info["title"][:60]}...')
            scholarship = extract_scholarship_from_page(link_info['url'], link_info['title'])

            if scholarship:
                new_scholarships.append(scholarship)
                log.info(f'  ✓ Extracted: {scholarship["name"]}')
            else:
                log.info(f'  ✗ Skipped (not a scholarship or extraction failed)')

            # Rate-limit: be polite to source sites and Groq API
            time.sleep(2)

        # Small pause between sources
        time.sleep(1)

    log.info(f'Scraped {len(SOURCES)} sources, {total_links} links, extracted {len(new_scholarships)} scholarships')
    return new_scholarships


def merge_new(existing, new_scholarships):
    """Add new scholarships that don't already exist"""
    existing_ids = set()
    existing_names = set()

    for s in existing:
        existing_ids.add(scholarship_id(s))
        existing_names.add(re.sub(r'[^a-z0-9]', '', s.get('name', '').lower()))

    added = []
    for s in new_scholarships:
        sid = scholarship_id(s)
        norm_name = re.sub(r'[^a-z0-9]', '', s.get('name', '').lower())

        if sid not in existing_ids and norm_name not in existing_names:
            existing.append(s)
            added.append(s)
            existing_ids.add(sid)
            existing_names.add(norm_name)
            log.info(f'NEW: {s["name"]} ({s.get("country", "?")})')

    return existing, added


# ============================================
# ENTRY POINT
# ============================================

def run():
    """Main scraper run"""
    log.info('=' * 60)
    log.info(f'ScholarFinder Scraper — {datetime.now().strftime("%Y-%m-%d %H:%M")}')
    log.info('=' * 60)

    # Load current data
    scholarships = load_scholarships()
    log.info(f'Current scholarships: {len(scholarships)}')

    # Step 1: Clean expired
    active, expired = clean_expired(scholarships)
    if expired:
        archive = load_archive()
        archive.extend(expired)
        save_archive(archive)
        log.info(f'Archived {len(expired)} expired scholarships')

    # Step 2: Deduplicate
    active = deduplicate(active)

    # Step 3: Scrape for new scholarships
    if GROQ_API_KEY:
        new_scholarships = scrape_all_sources()

        # Step 4: Merge new into existing
        active, added = merge_new(active, new_scholarships)
        log.info(f'Added {len(added)} new scholarships')
    else:
        log.warning('No GROQ_API_KEY — skipping web scraping (only cleanup ran)')
        added = []

    # Step 5: Save
    save_scholarships(active)

    # Summary
    log.info('-' * 40)
    log.info(f'SUMMARY:')
    log.info(f'  Before: {len(scholarships)}')
    log.info(f'  Expired & archived: {len(expired)}')
    log.info(f'  New added: {len(added)}')
    log.info(f'  Final count: {len(active)}')
    log.info('Done!')

    return {
        'before': len(scholarships),
        'expired': len(expired),
        'added': len(added),
        'final': len(active)
    }


if __name__ == '__main__':
    run()
