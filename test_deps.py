import sys
try:
    import requests
    print("requests: OK")
except ImportError:
    print("requests: MISSING")
try:
    from bs4 import BeautifulSoup
    print("bs4: OK")
except ImportError:
    print("bs4: MISSING")
print("Python:", sys.version)
