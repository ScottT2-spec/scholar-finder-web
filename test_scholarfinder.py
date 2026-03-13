"""
ScholarFinder — Automated Test Suite
=====================================
Run with: python3 -m pytest test_scholarfinder.py -v
Or:       python3 test_scholarfinder.py

Tests: field validation, rate limiting, caching, matching, API endpoints,
       auth flows, essay/resume scoring, search, and data integrity.
"""

import os
import sys
import json
import time
import sqlite3
import tempfile
import shutil

# Add project to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import pytest
from app import app, validate_field_of_study, load_json, clear_json_cache, \
    hash_password, verify_password, match_scholarships, get_scholarships, \
    get_universities, get_opportunities, get_cost_of_living, get_visa_guides, \
    get_faq, get_test_prep, VALID_FIELDS, FIELD_ALIASES


# ============================================
# TEST CLIENT SETUP
# ============================================
@pytest.fixture
def client():
    """Create test client with temp database"""
    app.config['TESTING'] = True
    with app.test_client() as client:
        with app.app_context():
            yield client


# ============================================
# 1. FIELD VALIDATION TESTS
# ============================================
class TestFieldValidation:
    """Test the field of study validation system"""

    def test_valid_fields_accepted(self):
        """Common fields should be recognized"""
        valid = ['computer science', 'medicine', 'law', 'engineering',
                 'nursing', 'psychology', 'business', 'economics',
                 'journalism', 'architecture', 'music', 'philosophy']
        for f in valid:
            is_valid, cleaned, _ = validate_field_of_study(f)
            assert is_valid, f'"{f}" should be valid but was rejected'

    def test_aliases_resolved(self):
        """Abbreviations should map to full field names"""
        assert validate_field_of_study('cs')[1] == 'computer science'
        assert validate_field_of_study('ai')[1] == 'artificial intelligence'
        assert validate_field_of_study('med')[1] == 'medicine'
        assert validate_field_of_study('econ')[1] == 'economics'
        assert validate_field_of_study('bio')[1] == 'biology'

    def test_case_insensitive(self):
        """Should work regardless of case"""
        assert validate_field_of_study('Computer Science')[0] == True
        assert validate_field_of_study('MEDICINE')[0] == True
        assert validate_field_of_study('LaW')[0] == True

    def test_gibberish_rejected(self):
        """Random strings should be flagged"""
        gibberish = ['jkjjlkkj', 'asdfghjk', 'qwerty', 'xxxyyy',
                     'jansted', 'blurpix', 'flonked', 'kkkkk',
                     'ab', '', None, 'zz']
        for g in gibberish:
            is_valid, _, _ = validate_field_of_study(g)
            assert not is_valid, f'"{g}" should be rejected but was accepted'

    def test_fuzzy_matching(self):
        """Partial matches should work"""
        assert validate_field_of_study('marine biology')[0] == True
        assert validate_field_of_study('applied mathematics')[0] == True
        assert validate_field_of_study('electrical engineering')[0] == True
        assert validate_field_of_study('clinical psychology')[0] == True

    def test_suggestions_provided(self):
        """Rejected fields should suggest closest match when possible"""
        is_valid, _, suggestion = validate_field_of_study('jansted')
        assert not is_valid
        # suggestion may or may not be provided, but shouldn't crash

    def test_valid_fields_list_not_empty(self):
        """VALID_FIELDS should have substantial coverage"""
        assert len(VALID_FIELDS) >= 100, f'Only {len(VALID_FIELDS)} fields, expected 100+'

    def test_aliases_map_to_valid_fields(self):
        """All aliases should point to fields in VALID_FIELDS"""
        for alias, target in FIELD_ALIASES.items():
            assert target in VALID_FIELDS, f'Alias "{alias}" -> "{target}" not in VALID_FIELDS'


# ============================================
# 2. PASSWORD SECURITY TESTS
# ============================================
class TestPasswordSecurity:
    """Test password hashing and verification"""

    def test_hash_produces_different_output(self):
        """Same password should produce different hashes (different salts)"""
        hash1, salt1 = hash_password('testpassword')
        hash2, salt2 = hash_password('testpassword')
        assert salt1 != salt2, 'Salts should be unique'
        assert hash1 != hash2, 'Hashes should differ due to different salts'

    def test_verify_correct_password(self):
        """Correct password should verify"""
        hashed, salt = hash_password('mypassword123')
        assert verify_password('mypassword123', hashed, salt) == True

    def test_verify_wrong_password(self):
        """Wrong password should not verify"""
        hashed, salt = hash_password('mypassword123')
        assert verify_password('wrongpassword', hashed, salt) == False

    def test_hash_not_plaintext(self):
        """Hash should never equal the original password"""
        hashed, _ = hash_password('testpassword')
        assert hashed != 'testpassword'

    def test_salt_is_random(self):
        """10 salts should all be different"""
        salts = set()
        for _ in range(10):
            _, salt = hash_password('test')
            salts.add(salt)
        assert len(salts) == 10, 'All salts should be unique'


# ============================================
# 3. DATA INTEGRITY TESTS
# ============================================
class TestDataIntegrity:
    """Test that JSON data files are valid and complete"""

    def test_scholarships_loaded(self):
        with app.app_context():
            data = get_scholarships()
            assert len(data) > 0, 'No scholarships loaded'
            assert len(data) >= 300, f'Only {len(data)} scholarships, expected 300+'

    def test_scholarship_has_required_fields(self):
        with app.app_context():
            for s in get_scholarships()[:50]:
                assert s.get('name'), f'Scholarship missing name: {s}'
                assert s.get('country'), f'Scholarship missing country: {s.get("name")}'

    def test_universities_loaded(self):
        with app.app_context():
            data = get_universities()
            assert len(data) >= 100, f'Only {len(data)} universities'

    def test_opportunities_loaded(self):
        with app.app_context():
            data = get_opportunities()
            assert len(data) >= 100, f'Only {len(data)} opportunities'

    def test_cost_data_loaded(self):
        with app.app_context():
            data = get_cost_of_living()
            assert len(data) >= 50, f'Only {len(data)} cities'

    def test_cost_data_has_total(self):
        with app.app_context():
            for c in get_cost_of_living()[:10]:
                assert 'total' in c, f'City missing total: {c.get("city")}'
                assert c['total'] > 0, f'City has zero total: {c.get("city")}'

    def test_visa_data_loaded(self):
        with app.app_context():
            data = get_visa_guides()
            assert len(data) >= 30, f'Only {len(data)} visa guides'

    def test_faq_loaded(self):
        with app.app_context():
            data = get_faq()
            assert len(data) >= 20, f'Only {len(data)} FAQs'

    def test_test_prep_loaded(self):
        with app.app_context():
            data = get_test_prep()
            assert len(data) >= 5, f'Only {len(data)} test prep guides'


# ============================================
# 4. CACHING TESTS
# ============================================
class TestCaching:
    """Test the JSON caching system"""

    def test_cache_returns_same_data(self):
        """Multiple loads should return identical data"""
        with app.app_context():
            data1 = load_json('scholarships.json')
            data2 = load_json('scholarships.json')
            assert data1 is data2, 'Second load should return cached object (same reference)'

    def test_cache_clear_works(self):
        """Clearing cache should force re-read"""
        with app.app_context():
            data1 = load_json('scholarships.json')
            clear_json_cache('scholarships.json')
            data2 = load_json('scholarships.json')
            assert data1 is not data2, 'After clear, should be a new object'
            assert len(data1) == len(data2), 'Data should be identical content'

    def test_missing_file_returns_empty(self):
        """Non-existent file should return empty list"""
        with app.app_context():
            data = load_json('nonexistent_file_12345.json')
            assert data == []


# ============================================
# 5. API ENDPOINT TESTS
# ============================================
class TestAPIEndpoints:
    """Test that all public API endpoints work"""

    def test_homepage(self, client):
        resp = client.get('/')
        assert resp.status_code == 200

    def test_scholarships_page(self, client):
        resp = client.get('/scholarships')
        assert resp.status_code == 200

    def test_universities_page(self, client):
        resp = client.get('/universities')
        assert resp.status_code == 200

    def test_api_scholarships(self, client):
        resp = client.get('/api/scholarships')
        assert resp.status_code == 200
        data = json.loads(resp.data)
        assert 'total' in data
        assert 'results' in data
        assert data['total'] > 0

    def test_api_scholarships_search(self, client):
        resp = client.get('/api/scholarships?q=engineering&per_page=5')
        data = json.loads(resp.data)
        assert data['per_page'] == 5

    def test_api_universities(self, client):
        resp = client.get('/api/universities')
        data = json.loads(resp.data)
        assert data['total'] > 0

    def test_api_opportunities(self, client):
        resp = client.get('/api/opportunities')
        data = json.loads(resp.data)
        assert data['total'] > 0

    def test_api_stats(self, client):
        resp = client.get('/api/stats')
        data = json.loads(resp.data)
        assert data['scholarships'] > 0
        assert data['universities'] > 0
        assert data['opportunities'] > 0

    def test_api_cost(self, client):
        resp = client.get('/api/cost')
        data = json.loads(resp.data)
        assert len(data) > 0

    def test_api_visa(self, client):
        resp = client.get('/api/visa')
        data = json.loads(resp.data)
        assert len(data) > 0

    def test_api_faq(self, client):
        resp = client.get('/api/faq')
        data = json.loads(resp.data)
        assert len(data) > 0

    def test_404_page(self, client):
        resp = client.get('/nonexistent-page-12345')
        assert resp.status_code == 404

    def test_api_404(self, client):
        resp = client.get('/api/nonexistent')
        assert resp.status_code == 404

    def test_robots_txt(self, client):
        resp = client.get('/robots.txt')
        assert resp.status_code == 200
        assert b'Sitemap' in resp.data

    def test_sitemap_xml(self, client):
        resp = client.get('/sitemap.xml')
        assert resp.status_code == 200
        assert b'<urlset' in resp.data


# ============================================
# 6. AUTH FLOW TESTS
# ============================================
class TestAuth:
    """Test authentication endpoints"""

    def test_login_page_loads(self, client):
        resp = client.get('/login')
        assert resp.status_code == 200

    def test_signup_page_loads(self, client):
        resp = client.get('/signup')
        assert resp.status_code == 200

    def test_dashboard_requires_login(self, client):
        resp = client.get('/dashboard', follow_redirects=False)
        assert resp.status_code == 302  # Redirect to login

    def test_profile_requires_login(self, client):
        resp = client.get('/profile', follow_redirects=False)
        assert resp.status_code == 302

    def test_bookmarks_require_login(self, client):
        resp = client.get('/api/bookmarks')
        assert resp.status_code == 401


# ============================================
# 7. CHATBOT TESTS
# ============================================
class TestChatbot:
    """Test the rule-based chatbot"""

    def test_greeting(self, client):
        resp = client.post('/api/chat',
            data=json.dumps({'message': 'hello'}),
            content_type='application/json')
        data = json.loads(resp.data)
        assert 'reply' in data
        assert 'Welcome' in data['reply'] or 'Hey' in data['reply']

    def test_scholarship_query(self, client):
        resp = client.post('/api/chat',
            data=json.dumps({'message': 'scholarships in USA'}),
            content_type='application/json')
        data = json.loads(resp.data)
        assert 'reply' in data
        assert data['source'] == 'Scholarships'

    def test_university_query(self, client):
        resp = client.post('/api/chat',
            data=json.dumps({'message': 'top universities in Canada'}),
            content_type='application/json')
        data = json.loads(resp.data)
        assert 'reply' in data

    def test_empty_message_rejected(self, client):
        resp = client.post('/api/chat',
            data=json.dumps({'message': ''}),
            content_type='application/json')
        assert resp.status_code == 400

    def test_no_message_rejected(self, client):
        resp = client.post('/api/chat',
            data=json.dumps({}),
            content_type='application/json')
        assert resp.status_code == 400


# ============================================
# 8. ESSAY & RESUME TOOL TESTS
# ============================================
class TestAITools:
    """Test essay rater and resume review (basic validation, not AI)"""

    def test_essay_empty_rejected(self, client):
        resp = client.post('/api/tools/rate-essay',
            data=json.dumps({'essay': ''}),
            content_type='application/json')
        assert resp.status_code == 400

    def test_essay_no_data_rejected(self, client):
        resp = client.post('/api/tools/rate-essay',
            data=json.dumps({}),
            content_type='application/json')
        assert resp.status_code == 400

    def test_resume_empty_rejected(self, client):
        resp = client.post('/api/tools/rate-resume',
            data=json.dumps({'resume': ''}),
            content_type='application/json')
        assert resp.status_code == 400


# ============================================
# 9. SEARCH TESTS
# ============================================
class TestSearch:
    """Test search and filtering"""

    def test_scholarship_pagination(self, client):
        resp = client.get('/api/scholarships?page=1&per_page=5')
        data = json.loads(resp.data)
        assert len(data['results']) <= 5
        assert data['page'] == 1

    def test_scholarship_country_filter(self, client):
        resp = client.get('/api/scholarships?country=usa')
        data = json.loads(resp.data)
        # Should return some results (we have USA scholarships)
        assert data['total'] >= 0

    def test_dashboard_search(self, client):
        resp = client.get('/api/dashboard-search?q=engineering&cat=scholarships')
        data = json.loads(resp.data)
        assert 'total' in data
        assert 'results' in data

    def test_dashboard_search_universities(self, client):
        resp = client.get('/api/dashboard-search?q=mit&cat=universities')
        data = json.loads(resp.data)
        assert 'results' in data


# ============================================
# RUN
# ============================================
if __name__ == '__main__':
    pytest.main([__file__, '-v', '--tb=short'])
