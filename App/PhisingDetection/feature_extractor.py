"""
Advanced URL Feature Extractor for Phishing Detection
Extracts 87 features from URLs to match the trained PyTorch model
Based on the dataset_phishing.csv feature set
"""

import re
import socket
import urllib.parse
from urllib.parse import urlparse
import tldextract
import requests
from bs4 import BeautifulSoup
import whois
from datetime import datetime, timezone
import logging

logger = logging.getLogger(__name__)


class URLFeatureExtractor:
    """
    Extracts features from URLs for phishing detection.
    Features are designed to match the trained model's expected input.
    """
    
    # Known shortening services
    SHORTENING_SERVICES = {
        'bit.ly', 'goo.gl', 't.co', 'tinyurl.com', 'is.gd', 'cli.gs',
        'ow.ly', 'j.mp', 'short.to', 'u.to', 'yfrog.com', 'migre.me',
        'ff.im', 'tiny.cc', 'url4.eu', 'tr.im', 'twit.ac', 'su.pr',
        'twurl.nl', 'snipurl.com', 'budurl.com', 'short.ie', 'kl.am',
        'ping.fm', 'post.ly', 'just.as', 'bkite.com', 'snipr.com',
        'fic.kr', 'loopt.us', 'doiop.com', 'rb.gy', 'cutt.ly', 'tny.im'
    }
    
    # Known brand domains for detection
    BRAND_DOMAINS = {
        'paypal', 'apple', 'microsoft', 'google', 'amazon', 'facebook',
        'instagram', 'twitter', 'netflix', 'linkedin', 'dropbox', 'yahoo',
        'ebay', 'wellsfargo', 'chase', 'bankofamerica', 'citibank',
        'americanexpress', 'visa', 'mastercard', 'discover', 'hsbc',
        'barclays', 'santander', 'usbank', 'capitalone', 'blockchain',
        'coinbase', 'binance', 'metamask', 'opensea', 'adobe', 'oracle',
        'salesforce', 'spotify', 'steam', 'discord', 'telegram', 'whatsapp'
    }
    
    # Suspicious TLDs often used in phishing
    SUSPICIOUS_TLDS = {
        'tk', 'ml', 'ga', 'cf', 'gq', 'pw', 'cc', 'top', 'click', 
        'loan', 'work', 'buzz', 'fit', 'xyz', 'club', 'online', 'site'
    }
    
    # Phishing hint keywords
    PHISH_HINTS = [
        'login', 'signin', 'verify', 'account', 'update', 'confirm',
        'secure', 'banking', 'password', 'credential', 'suspend',
        'unlock', 'alert', 'notification', 'validate', 'authenticate'
    ]
    
    def __init__(self, url: str, timeout: int = 5):
        """Initialize the feature extractor with a URL."""
        self.url = url
        self.timeout = timeout
        self.parsed = urlparse(url)
        self.extracted = tldextract.extract(url)
        self.hostname = self.parsed.netloc
        self.path = self.parsed.path
        self.query = self.parsed.query
        self.scheme = self.parsed.scheme
        
        # HTML content (fetched on demand)
        self._html_content = None
        self._soup = None
        self._whois_info = None
        
    def _fetch_html(self):
        """Fetch HTML content of the URL."""
        if self._html_content is None:
            try:
                headers = {
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
                }
                response = requests.get(self.url, timeout=self.timeout, headers=headers, verify=False, allow_redirects=True)
                self._html_content = response.text
                self._soup = BeautifulSoup(self._html_content, 'html.parser')
            except Exception as e:
                logger.debug(f"Could not fetch HTML: {e}")
                self._html_content = ""
                self._soup = BeautifulSoup("", 'html.parser')
        return self._html_content, self._soup
    
    def _get_whois(self):
        """Get WHOIS information for the domain."""
        if self._whois_info is None:
            try:
                domain = self.extracted.registered_domain
                self._whois_info = whois.whois(domain)
            except Exception as e:
                logger.debug(f"Could not fetch WHOIS: {e}")
                self._whois_info = {}
        return self._whois_info
    
    # ==================== URL-based Features ====================
    
    def length_url(self) -> int:
        """Length of the URL."""
        return len(self.url)
    
    def length_hostname(self) -> int:
        """Length of the hostname."""
        return len(self.hostname)
    
    def ip(self) -> int:
        """Check if URL uses IP address instead of domain name."""
        # Check for IP pattern in hostname
        ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        if re.match(ip_pattern, self.hostname):
            return 1
        # Check for hex IP
        hex_pattern = r'^0x[0-9a-fA-F]+$'
        if re.match(hex_pattern, self.hostname):
            return 1
        return 0
    
    def nb_dots(self) -> int:
        """Number of dots in the URL."""
        return self.url.count('.')
    
    def nb_hyphens(self) -> int:
        """Number of hyphens in the URL."""
        return self.url.count('-')
    
    def nb_at(self) -> int:
        """Number of @ symbols in the URL."""
        return self.url.count('@')
    
    def nb_qm(self) -> int:
        """Number of question marks in the URL."""
        return self.url.count('?')
    
    def nb_and(self) -> int:
        """Number of & symbols in the URL."""
        return self.url.count('&')
    
    def nb_or(self) -> int:
        """Number of | symbols in the URL."""
        return self.url.count('|')
    
    def nb_eq(self) -> int:
        """Number of = symbols in the URL."""
        return self.url.count('=')
    
    def nb_underscore(self) -> int:
        """Number of underscores in the URL."""
        return self.url.count('_')
    
    def nb_tilde(self) -> int:
        """Number of ~ symbols in the URL."""
        return self.url.count('~')
    
    def nb_percent(self) -> int:
        """Number of % symbols in the URL."""
        return self.url.count('%')
    
    def nb_slash(self) -> int:
        """Number of / symbols in the URL."""
        return self.url.count('/')
    
    def nb_star(self) -> int:
        """Number of * symbols in the URL."""
        return self.url.count('*')
    
    def nb_colon(self) -> int:
        """Number of : symbols in the URL."""
        return self.url.count(':')
    
    def nb_comma(self) -> int:
        """Number of , symbols in the URL."""
        return self.url.count(',')
    
    def nb_semicolumn(self) -> int:
        """Number of ; symbols in the URL."""
        return self.url.count(';')
    
    def nb_dollar(self) -> int:
        """Number of $ symbols in the URL."""
        return self.url.count('$')
    
    def nb_space(self) -> int:
        """Number of spaces in the URL (encoded or not)."""
        return self.url.count(' ') + self.url.count('%20')
    
    def nb_www(self) -> int:
        """Number of www occurrences in the URL."""
        return self.url.lower().count('www')
    
    def nb_com(self) -> int:
        """Number of .com occurrences in the URL."""
        return self.url.lower().count('.com')
    
    def nb_dslash(self) -> int:
        """Number of // occurrences (excluding http://)."""
        count = self.url.count('//')
        if self.url.startswith('http://') or self.url.startswith('https://'):
            count -= 1
        return max(0, count)
    
    def http_in_path(self) -> int:
        """Check if 'http' appears in the path."""
        return 1 if 'http' in self.path.lower() else 0
    
    def https_token(self) -> int:
        """Check if URL uses HTTPS."""
        return 0 if self.scheme == 'https' else 1
    
    def ratio_digits_url(self) -> float:
        """Ratio of digits in URL."""
        if len(self.url) == 0:
            return 0
        digits = sum(c.isdigit() for c in self.url)
        return digits / len(self.url)
    
    def ratio_digits_host(self) -> float:
        """Ratio of digits in hostname."""
        if len(self.hostname) == 0:
            return 0
        digits = sum(c.isdigit() for c in self.hostname)
        return digits / len(self.hostname)
    
    def punycode(self) -> int:
        """Check if URL contains punycode (internationalized domain)."""
        return 1 if 'xn--' in self.hostname.lower() else 0
    
    def port(self) -> int:
        """Check if URL specifies a non-standard port."""
        port = self.parsed.port
        if port and port not in [80, 443]:
            return 1
        return 0
    
    def tld_in_path(self) -> int:
        """Check if TLD appears in path."""
        tlds = ['com', 'org', 'net', 'edu', 'gov', 'co', 'io', 'uk', 'de', 'fr']
        path_lower = self.path.lower()
        for tld in tlds:
            if f'.{tld}' in path_lower or f'/{tld}/' in path_lower:
                return 1
        return 0
    
    def tld_in_subdomain(self) -> int:
        """Check if TLD appears in subdomain."""
        subdomain = self.extracted.subdomain.lower()
        tlds = ['com', 'org', 'net', 'edu', 'gov', 'co', 'io', 'uk', 'de', 'fr']
        for tld in tlds:
            if tld in subdomain:
                return 1
        return 0
    
    def abnormal_subdomain(self) -> int:
        """Check for abnormal subdomain patterns."""
        subdomain = self.extracted.subdomain
        # Check for suspicious patterns
        if re.search(r'\d{5,}', subdomain):  # Too many digits
            return 1
        if len(subdomain) > 30:  # Too long
            return 1
        if subdomain.count('.') > 3:  # Too many levels
            return 1
        return 0
    
    def nb_subdomains(self) -> int:
        """Number of subdomain levels."""
        subdomain = self.extracted.subdomain
        if not subdomain:
            return 0
        return subdomain.count('.') + 1
    
    def prefix_suffix(self) -> int:
        """Check if domain contains prefix or suffix with hyphen."""
        domain = self.extracted.domain
        return 1 if '-' in domain else 0
    
    def random_domain(self) -> int:
        """Check if domain appears to be randomly generated."""
        domain = self.extracted.domain.lower()
        
        # Check consonant/vowel ratio
        vowels = sum(1 for c in domain if c in 'aeiou')
        if len(domain) > 0:
            vowel_ratio = vowels / len(domain)
            if vowel_ratio < 0.1 or vowel_ratio > 0.6:
                return 1
        
        # Check for random character sequences
        if len(domain) > 10 and re.search(r'[bcdfghjklmnpqrstvwxyz]{5,}', domain):
            return 1
            
        return 0
    
    def shortening_service(self) -> int:
        """Check if URL uses a URL shortening service."""
        domain = f"{self.extracted.domain}.{self.extracted.suffix}".lower()
        return 1 if domain in self.SHORTENING_SERVICES else 0
    
    def path_extension(self) -> int:
        """Check if path has a suspicious extension."""
        suspicious_ext = ['.exe', '.zip', '.rar', '.php', '.asp', '.scr', '.bat']
        path_lower = self.path.lower()
        return 1 if any(path_lower.endswith(ext) for ext in suspicious_ext) else 0
    
    def nb_redirection(self) -> int:
        """Count redirections in URL."""
        return self.url.count('//') - 1 if '//' in self.url else 0
    
    def nb_external_redirection(self) -> int:
        """Count external redirections (simplified)."""
        # Check for redirect patterns in URL
        redirect_patterns = ['redirect=', 'url=', 'link=', 'goto=', 'return=']
        return sum(1 for p in redirect_patterns if p in self.url.lower())
    
    # ==================== Word-based Features ====================
    
    def _get_words(self, text: str) -> list:
        """Extract words from text."""
        return re.findall(r'[a-zA-Z]+', text)
    
    def length_words_raw(self) -> int:
        """Number of words in URL."""
        return len(self._get_words(self.url))
    
    def char_repeat(self) -> int:
        """Maximum character repetition in URL."""
        max_repeat = 0
        for i in range(len(self.url) - 1):
            count = 1
            while i + count < len(self.url) and self.url[i] == self.url[i + count]:
                count += 1
            max_repeat = max(max_repeat, count)
        return max_repeat
    
    def shortest_words_raw(self) -> int:
        """Length of shortest word in URL."""
        words = self._get_words(self.url)
        return min(len(w) for w in words) if words else 0
    
    def shortest_word_host(self) -> int:
        """Length of shortest word in hostname."""
        words = self._get_words(self.hostname)
        return min(len(w) for w in words) if words else 0
    
    def shortest_word_path(self) -> int:
        """Length of shortest word in path."""
        words = self._get_words(self.path)
        return min(len(w) for w in words) if words else 0
    
    def longest_words_raw(self) -> int:
        """Length of longest word in URL."""
        words = self._get_words(self.url)
        return max(len(w) for w in words) if words else 0
    
    def longest_word_host(self) -> int:
        """Length of longest word in hostname."""
        words = self._get_words(self.hostname)
        return max(len(w) for w in words) if words else 0
    
    def longest_word_path(self) -> int:
        """Length of longest word in path."""
        words = self._get_words(self.path)
        return max(len(w) for w in words) if words else 0
    
    def avg_words_raw(self) -> float:
        """Average word length in URL."""
        words = self._get_words(self.url)
        return sum(len(w) for w in words) / len(words) if words else 0
    
    def avg_word_host(self) -> float:
        """Average word length in hostname."""
        words = self._get_words(self.hostname)
        return sum(len(w) for w in words) / len(words) if words else 0
    
    def avg_word_path(self) -> float:
        """Average word length in path."""
        words = self._get_words(self.path)
        return sum(len(w) for w in words) / len(words) if words else 0
    
    def phish_hints(self) -> int:
        """Count phishing hint keywords in URL."""
        url_lower = self.url.lower()
        return sum(1 for hint in self.PHISH_HINTS if hint in url_lower)
    
    def domain_in_brand(self) -> int:
        """Check if domain mimics a known brand."""
        domain = self.extracted.domain.lower()
        for brand in self.BRAND_DOMAINS:
            if brand in domain and domain != brand:
                return 1
        return 0
    
    def brand_in_subdomain(self) -> int:
        """Check if brand appears in subdomain."""
        subdomain = self.extracted.subdomain.lower()
        return 1 if any(brand in subdomain for brand in self.BRAND_DOMAINS) else 0
    
    def brand_in_path(self) -> int:
        """Check if brand appears in path."""
        path = self.path.lower()
        return 1 if any(brand in path for brand in self.BRAND_DOMAINS) else 0
    
    def suspecious_tld(self) -> int:
        """Check if TLD is suspicious."""
        tld = self.extracted.suffix.lower()
        return 1 if tld in self.SUSPICIOUS_TLDS else 0
    
    def statistical_report(self) -> int:
        """Placeholder for statistical report feature (requires external API)."""
        return 0
    
    # ==================== HTML-based Features ====================
    
    def nb_hyperlinks(self) -> int:
        """Number of hyperlinks in page."""
        _, soup = self._fetch_html()
        return len(soup.find_all('a', href=True))
    
    def ratio_intHyperlinks(self) -> float:
        """Ratio of internal hyperlinks."""
        _, soup = self._fetch_html()
        links = soup.find_all('a', href=True)
        if not links:
            return 0
        domain = self.extracted.registered_domain
        internal = sum(1 for link in links if domain in link.get('href', ''))
        return internal / len(links)
    
    def ratio_extHyperlinks(self) -> float:
        """Ratio of external hyperlinks."""
        return 1 - self.ratio_intHyperlinks()
    
    def ratio_nullHyperlinks(self) -> float:
        """Ratio of null/empty hyperlinks."""
        _, soup = self._fetch_html()
        links = soup.find_all('a', href=True)
        if not links:
            return 0
        null_links = sum(1 for link in links if link.get('href', '').strip() in ['', '#', 'javascript:void(0)', 'javascript:;'])
        return null_links / len(links)
    
    def nb_extCSS(self) -> int:
        """Number of external CSS files."""
        _, soup = self._fetch_html()
        css_links = soup.find_all('link', rel='stylesheet')
        domain = self.extracted.registered_domain
        external = sum(1 for link in css_links if domain not in link.get('href', ''))
        return external
    
    def ratio_intRedirection(self) -> float:
        """Ratio of internal redirections (placeholder)."""
        return 0
    
    def ratio_extRedirection(self) -> float:
        """Ratio of external redirections (placeholder)."""
        return 0
    
    def ratio_intErrors(self) -> float:
        """Ratio of internal errors (placeholder)."""
        return 0
    
    def ratio_extErrors(self) -> float:
        """Ratio of external errors (placeholder)."""
        return 0
    
    def login_form(self) -> int:
        """Check if page contains login form."""
        _, soup = self._fetch_html()
        forms = soup.find_all('form')
        for form in forms:
            inputs = form.find_all('input')
            has_password = any(inp.get('type', '').lower() == 'password' for inp in inputs)
            has_text = any(inp.get('type', '').lower() in ['text', 'email'] for inp in inputs)
            if has_password and has_text:
                return 1
        return 0
    
    def external_favicon(self) -> int:
        """Check if favicon is from external domain."""
        _, soup = self._fetch_html()
        favicon = soup.find('link', rel=lambda x: x and 'icon' in x.lower())
        if favicon:
            href = favicon.get('href', '')
            if href and self.extracted.registered_domain not in href:
                return 1
        return 0
    
    def links_in_tags(self) -> float:
        """Ratio of links in meta/script/link tags."""
        _, soup = self._fetch_html()
        total = len(soup.find_all(['script', 'link', 'meta']))
        return min(total, 100)  # Cap at 100
    
    def submit_email(self) -> int:
        """Check if form submits to email."""
        _, soup = self._fetch_html()
        forms = soup.find_all('form')
        for form in forms:
            action = form.get('action', '').lower()
            if 'mailto:' in action:
                return 1
        return 0
    
    def ratio_intMedia(self) -> float:
        """Ratio of internal media."""
        _, soup = self._fetch_html()
        media = soup.find_all(['img', 'video', 'audio'])
        if not media:
            return 0
        domain = self.extracted.registered_domain
        internal = sum(1 for m in media if domain in m.get('src', ''))
        return (internal / len(media)) * 100
    
    def ratio_extMedia(self) -> float:
        """Ratio of external media."""
        return 100 - self.ratio_intMedia()
    
    def sfh(self) -> int:
        """Server Form Handler - check if form action is suspicious."""
        _, soup = self._fetch_html()
        forms = soup.find_all('form')
        for form in forms:
            action = form.get('action', '').lower()
            if action in ['', 'about:blank'] or action.startswith('http') and self.extracted.registered_domain not in action:
                return 1
        return 0
    
    def iframe(self) -> int:
        """Check for hidden iframes."""
        _, soup = self._fetch_html()
        iframes = soup.find_all('iframe')
        for iframe in iframes:
            style = iframe.get('style', '')
            if 'hidden' in style.lower() or 'visibility:hidden' in style.lower():
                return 1
            if iframe.get('width') == '0' or iframe.get('height') == '0':
                return 1
        return 0
    
    def popup_window(self) -> int:
        """Check for popup windows in scripts."""
        html, _ = self._fetch_html()
        popup_patterns = ['window.open', 'alert(', 'confirm(', 'prompt(']
        return 1 if any(p in html for p in popup_patterns) else 0
    
    def safe_anchor(self) -> float:
        """Ratio of safe anchors."""
        _, soup = self._fetch_html()
        anchors = soup.find_all('a', href=True)
        if not anchors:
            return 0
        safe = sum(1 for a in anchors if not a.get('href', '').startswith('javascript:'))
        return (safe / len(anchors)) * 100
    
    def onmouseover(self) -> int:
        """Check for onmouseover events that change status bar."""
        html, _ = self._fetch_html()
        return 1 if 'onmouseover' in html.lower() and 'window.status' in html.lower() else 0
    
    def right_clic(self) -> int:
        """Check if right-click is disabled."""
        html, _ = self._fetch_html()
        patterns = ['event.button==2', 'contextmenu', 'oncontextmenu']
        return 1 if any(p in html.lower() for p in patterns) else 0
    
    def empty_title(self) -> int:
        """Check if page title is empty."""
        _, soup = self._fetch_html()
        title = soup.find('title')
        return 1 if not title or not title.string or not title.string.strip() else 0
    
    def domain_in_title(self) -> int:
        """Check if domain appears in title."""
        _, soup = self._fetch_html()
        title = soup.find('title')
        if title and title.string:
            domain = self.extracted.domain.lower()
            return 1 if domain in title.string.lower() else 0
        return 0
    
    def domain_with_copyright(self) -> int:
        """Check if domain appears with copyright."""
        html, _ = self._fetch_html()
        domain = self.extracted.domain.lower()
        copyright_patterns = ['©', 'copyright', '(c)', '&copy;']
        for pattern in copyright_patterns:
            if pattern in html.lower() and domain in html.lower():
                return 1
        return 0
    
    # ==================== WHOIS Features ====================
    
    def whois_registered_domain(self) -> int:
        """Check if domain is registered."""
        try:
            whois_info = self._get_whois()
            return 1 if whois_info.get('domain_name') else 0
        except:
            return 0
    
    def domain_registration_length(self) -> int:
        """Domain registration length in days."""
        try:
            whois_info = self._get_whois()
            creation = whois_info.get('creation_date')
            expiration = whois_info.get('expiration_date')
            
            if isinstance(creation, list):
                creation = creation[0]
            if isinstance(expiration, list):
                expiration = expiration[0]
            
            if creation and expiration:
                delta = expiration - creation
                return delta.days
        except:
            pass
        return 0
    
    def domain_age(self) -> int:
        """Domain age in days."""
        try:
            whois_info = self._get_whois()
            creation = whois_info.get('creation_date')
            
            if isinstance(creation, list):
                creation = creation[0]
            
            if creation:
                now = datetime.now(timezone.utc) if creation.tzinfo else datetime.now()
                delta = now - creation
                return delta.days
        except:
            pass
        return -1
    
    def web_traffic(self) -> int:
        """Web traffic rank (placeholder - requires Alexa API)."""
        return 0
    
    def dns_record(self) -> int:
        """Check if domain has DNS record."""
        try:
            socket.gethostbyname(self.hostname)
            return 1
        except:
            return 0
    
    def google_index(self) -> int:
        """Check if URL is indexed by Google (placeholder)."""
        return 0
    
    def page_rank(self) -> int:
        """Page rank (placeholder)."""
        return 0
    
    def extract_all_features(self) -> dict:
        """Extract all features and return as dictionary."""
        features = {
            # URL-based features
            'length_url': self.length_url(),
            'length_hostname': self.length_hostname(),
            'ip': self.ip(),
            'nb_dots': self.nb_dots(),
            'nb_hyphens': self.nb_hyphens(),
            'nb_at': self.nb_at(),
            'nb_qm': self.nb_qm(),
            'nb_and': self.nb_and(),
            'nb_or': self.nb_or(),
            'nb_eq': self.nb_eq(),
            'nb_underscore': self.nb_underscore(),
            'nb_tilde': self.nb_tilde(),
            'nb_percent': self.nb_percent(),
            'nb_slash': self.nb_slash(),
            'nb_star': self.nb_star(),
            'nb_colon': self.nb_colon(),
            'nb_comma': self.nb_comma(),
            'nb_semicolumn': self.nb_semicolumn(),
            'nb_dollar': self.nb_dollar(),
            'nb_space': self.nb_space(),
            'nb_www': self.nb_www(),
            'nb_com': self.nb_com(),
            'nb_dslash': self.nb_dslash(),
            'http_in_path': self.http_in_path(),
            'https_token': self.https_token(),
            'ratio_digits_url': self.ratio_digits_url(),
            'ratio_digits_host': self.ratio_digits_host(),
            'punycode': self.punycode(),
            'port': self.port(),
            'tld_in_path': self.tld_in_path(),
            'tld_in_subdomain': self.tld_in_subdomain(),
            'abnormal_subdomain': self.abnormal_subdomain(),
            'nb_subdomains': self.nb_subdomains(),
            'prefix_suffix': self.prefix_suffix(),
            'random_domain': self.random_domain(),
            'shortening_service': self.shortening_service(),
            'path_extension': self.path_extension(),
            'nb_redirection': self.nb_redirection(),
            'nb_external_redirection': self.nb_external_redirection(),
            
            # Word-based features
            'length_words_raw': self.length_words_raw(),
            'char_repeat': self.char_repeat(),
            'shortest_words_raw': self.shortest_words_raw(),
            'shortest_word_host': self.shortest_word_host(),
            'shortest_word_path': self.shortest_word_path(),
            'longest_words_raw': self.longest_words_raw(),
            'longest_word_host': self.longest_word_host(),
            'longest_word_path': self.longest_word_path(),
            'avg_words_raw': self.avg_words_raw(),
            'avg_word_host': self.avg_word_host(),
            'avg_word_path': self.avg_word_path(),
            'phish_hints': self.phish_hints(),
            'domain_in_brand': self.domain_in_brand(),
            'brand_in_subdomain': self.brand_in_subdomain(),
            'brand_in_path': self.brand_in_path(),
            'suspecious_tld': self.suspecious_tld(),
            'statistical_report': self.statistical_report(),
            
            # HTML-based features
            'nb_hyperlinks': self.nb_hyperlinks(),
            'ratio_intHyperlinks': self.ratio_intHyperlinks(),
            'ratio_extHyperlinks': self.ratio_extHyperlinks(),
            'ratio_nullHyperlinks': self.ratio_nullHyperlinks(),
            'nb_extCSS': self.nb_extCSS(),
            'ratio_intRedirection': self.ratio_intRedirection(),
            'ratio_extRedirection': self.ratio_extRedirection(),
            'ratio_intErrors': self.ratio_intErrors(),
            'ratio_extErrors': self.ratio_extErrors(),
            'login_form': self.login_form(),
            'external_favicon': self.external_favicon(),
            'links_in_tags': self.links_in_tags(),
            'submit_email': self.submit_email(),
            'ratio_intMedia': self.ratio_intMedia(),
            'ratio_extMedia': self.ratio_extMedia(),
            'sfh': self.sfh(),
            'iframe': self.iframe(),
            'popup_window': self.popup_window(),
            'safe_anchor': self.safe_anchor(),
            'onmouseover': self.onmouseover(),
            'right_clic': self.right_clic(),
            'empty_title': self.empty_title(),
            'domain_in_title': self.domain_in_title(),
            'domain_with_copyright': self.domain_with_copyright(),
            
            # WHOIS features
            'whois_registered_domain': self.whois_registered_domain(),
            'domain_registration_length': self.domain_registration_length(),
            'domain_age': self.domain_age(),
            'web_traffic': self.web_traffic(),
            'dns_record': self.dns_record(),
            'google_index': self.google_index(),
            'page_rank': self.page_rank(),
        }
        
        return features
    
    def extract_features_array(self) -> list:
        """Extract features as array in the correct order for the model."""
        features = self.extract_all_features()
        
        # Feature order must match the training data
        feature_order = [
            'length_url', 'length_hostname', 'ip', 'nb_dots', 'nb_hyphens',
            'nb_at', 'nb_qm', 'nb_and', 'nb_or', 'nb_eq', 'nb_underscore',
            'nb_tilde', 'nb_percent', 'nb_slash', 'nb_star', 'nb_colon',
            'nb_comma', 'nb_semicolumn', 'nb_dollar', 'nb_space', 'nb_www',
            'nb_com', 'nb_dslash', 'http_in_path', 'https_token',
            'ratio_digits_url', 'ratio_digits_host', 'punycode', 'port',
            'tld_in_path', 'tld_in_subdomain', 'abnormal_subdomain',
            'nb_subdomains', 'prefix_suffix', 'random_domain',
            'shortening_service', 'path_extension', 'nb_redirection',
            'nb_external_redirection', 'length_words_raw', 'char_repeat',
            'shortest_words_raw', 'shortest_word_host', 'shortest_word_path',
            'longest_words_raw', 'longest_word_host', 'longest_word_path',
            'avg_words_raw', 'avg_word_host', 'avg_word_path', 'phish_hints',
            'domain_in_brand', 'brand_in_subdomain', 'brand_in_path',
            'suspecious_tld', 'statistical_report', 'nb_hyperlinks',
            'ratio_intHyperlinks', 'ratio_extHyperlinks', 'ratio_nullHyperlinks',
            'nb_extCSS', 'ratio_intRedirection', 'ratio_extRedirection',
            'ratio_intErrors', 'ratio_extErrors', 'login_form',
            'external_favicon', 'links_in_tags', 'submit_email',
            'ratio_intMedia', 'ratio_extMedia', 'sfh', 'iframe',
            'popup_window', 'safe_anchor', 'onmouseover', 'right_clic',
            'empty_title', 'domain_in_title', 'domain_with_copyright',
            'whois_registered_domain', 'domain_registration_length',
            'domain_age', 'web_traffic', 'dns_record', 'google_index',
            'page_rank'
        ]
        
        return [features[f] for f in feature_order]
