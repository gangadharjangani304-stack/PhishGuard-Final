import re
from urllib.parse import urlparse
import ipaddress
import requests
from bs4 import BeautifulSoup
import tldextract

class FeatureExtractor:
    def __init__(self, url):
        self.url = url
        if not re.match(r"^https?", url):
            self.url = "http://" + url
            
        self.parsed = urlparse(self.url)
        self.soup = None
        
        # TIMEBOXING: If site takes >2s to load, we skip content features to keep it "Real-Time"
        try:
            response = requests.get(self.url, timeout=2)
            self.soup = BeautifulSoup(response.content, 'html.parser')
        except:
            self.soup = None

    # 1. IP Address in URL
    def using_ip(self):
        try:
            ipaddress.ip_address(self.parsed.netloc)
            return -1 # Phishing
        except:
            return 1 # Legitimate

    # 2. Long URL (>75 chars is suspicious)
    def long_url(self):
        if len(self.url) < 54: return 1
        if len(self.url) >= 54 and len(self.url) <= 75: return 0
        return -1

    # 3. Shortening Service
    def short_url(self):
        match = re.search('bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.wb|lnkd\.in|db\.tt|qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|q\.gs|is\.gd|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|x\.co|prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|tr\.im|link\.zip\.net', self.url)
        return -1 if match else 1

    # 4. @ Symbol
    def symbol_at(self):
        return -1 if "@" in self.url else 1

    # 5. Redirecting //
    def redirecting(self):
        return -1 if self.parsed.path.rfind('//') > 6 else 1

    # 6. Prefix-Suffix (-)
    def prefix_suffix(self):
        return -1 if '-' in self.parsed.netloc else 1

    # 7. SubDomains
    def sub_domains(self):
        ext = tldextract.extract(self.url)
        if ext.subdomain:
            return 0 if len(ext.subdomain.split('.')) == 1 else -1
        return 1

    # 8. HTTPS Token
    def https_token(self):
        return 1 if self.parsed.scheme == 'https' else -1

    # 9. Request URL (Content)
    def request_url(self):
        if not self.soup: return -1
        i = 0
        success = 0
        for img in self.soup.find_all('img', src=True):
            dots = [x.start() for x in re.finditer(r'\.', img['src'])]
            if self.url in img['src'] or len(dots) == 1:
                success = success + 1
            i = i + 1
        
        if i == 0: return -1
        percentage = success / float(i) * 100
        if percentage < 22.0: return 1
        elif 22.0 <= percentage < 61.0: return 0
        else: return -1

    # 10. Anchor URL (Content)
    def anchor_url(self):
        if not self.soup: return -1
        i = 0
        unsafe = 0
        for a in self.soup.find_all('a', href=True):
            if "#" in a['href'] or "javascript" in a['href'].lower() or "mailto" in a['href'].lower() or not (self.url in a['href'] or self.parsed.netloc in a['href']):
                unsafe = unsafe + 1
            i = i + 1
            
        if i == 0: return -1
        percentage = unsafe / float(i) * 100
        if percentage < 31.0: return 1
        elif 31.0 <= percentage < 67.0: return 0
        else: return -1

    def get_features_list(self):
        # ORDER MATTERS: Must match train_model.py selected_features
        return [
            self.using_ip(),
            self.long_url(),
            self.short_url(),
            self.symbol_at(),
            self.redirecting(),
            self.prefix_suffix(),
            self.sub_domains(),
            self.https_token(),
            self.request_url(),
            self.anchor_url()
        ]