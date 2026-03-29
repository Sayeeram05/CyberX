"""
Enhanced URL Threat Analyzer v3.0 - Production Version
Advanced machine learning-based URL threat detection with 35+ features
Improved accuracy and comprehensive validation features for Django integration
"""

import os
import re
import time
import logging
import numpy as np
import pandas as pd
import joblib
from urllib.parse import urlparse, parse_qs
from collections import Counter
from django.conf import settings

logger = logging.getLogger(__name__)

class URLThreatAnalyzer:
    """
    Enhanced URL Threat Analyzer with advanced features and improved accuracy
    Version 3.0 with 35+ feature analysis and comprehensive validation
    Production version optimized for Django integration
    """
    
    def __init__(self):
        """Initialize the enhanced URL threat analyzer"""
        # Comprehensive threat intelligence databases
        self.KNOWN_MALICIOUS_TLDS = {
            '.tk', '.ml', '.ga', '.cf', '.gq', '.pw', '.cc', '.ws', '.info', '.biz',
            '.top', '.click', '.download', '.stream', '.science', '.party', '.racing',
            '.win', '.loan', '.faith', '.accountant', '.cricket', '.date', '.review',
            '.country', '.kim', '.work', '.men', '.trade', '.webcam', '.bid'
        }
        
        self.SUSPICIOUS_KEYWORDS = [
            'login', 'signin', 'account', 'verify', 'secure', 'update', 'confirm',
            'suspended', 'locked', 'limited', 'verification', 'security', 'alert',
            'urgent', 'immediate', 'expire', 'expires', 'click', 'here', 'now',
            'free', 'prize', 'winner', 'congratulations', 'claim', 'bonus',
            'paypal', 'amazon', 'microsoft', 'google', 'apple', 'facebook',
            'bank', 'banking', 'credit', 'card', 'payment', 'transfer'
        ]
        
        self.LEGITIMATE_DOMAINS_EXTENDED = {
            # Major Tech Companies & Services
            'google.com', 'youtube.com', 'gmail.com', 'gstatic.com', 'googl.com',
            'microsoft.com', 'live.com', 'outlook.com', 'office.com', 'msn.com', 'bing.com',
            'apple.com', 'icloud.com', 'itunes.com', 'me.com', 'mac.com',
            'amazon.com', 'aws.amazon.com', 'amazonaws.com', 'amzn.to', 'a.co',
            'facebook.com', 'instagram.com', 'whatsapp.com', 'fb.me', 'fb.com',
            'twitter.com', 'x.com', 't.co', 'twimg.com',
            'linkedin.com', 'licdn.com',
            
            # AI Companies
            'openai.com', 'chatgpt.com', 'anthropic.com', 'claude.ai',
            
            # Development & Tech Platforms
            'github.com', 'gitlab.com', 'bitbucket.org', 'sourceforge.net',
            'stackoverflow.com', 'stackexchange.com', 'serverfault.com', 'superuser.com',
            'npm.org', 'pypi.org', 'crates.io', 'packagist.org',
            'docker.com', 'dockerhub.com', 'kubernetes.io', 'mozilla.org', 'firefox.com',
            'chrome.google.com', 'chromium.org', 'webkit.org',
            
            # Educational & Reference (IMPORTANT: Wikimedia Foundation)
            'wikipedia.org', 'wikimedia.org', 'wikidata.org', 'commons.wikimedia.org',
            'meta.wikimedia.org', 'species.wikimedia.org', 'mediawiki.org',
            'wiktionary.org', 'wikinews.org', 'wikiquote.org', 'wikibooks.org',
            'wikisource.org', 'wikiversity.org', 'wikivoyage.org',
            'scholar.google.com', 'arxiv.org', 'researchgate.net', 'academia.edu',
            'mit.edu', 'stanford.edu', 'harvard.edu', 'berkeley.edu', 'princeton.edu',
            'coursera.org', 'edx.org', 'khanacademy.org', 'udemy.com', 'pluralsight.com',
            
            # News & Media
            'cnn.com', 'bbc.com', 'bbc.co.uk', 'reuters.com', 'ap.org', 'npr.org', 'pbs.org',
            'nytimes.com', 'washingtonpost.com', 'theguardian.com', 'guardian.co.uk', 'wsj.com',
            'bloomberg.com', 'cnbc.com', 'foxnews.com', 'msnbc.com', 'abcnews.go.com',
            
            # Financial Services
            'paypal.com', 'stripe.com', 'square.com', 'visa.com', 'mastercard.com',
            'americanexpress.com', 'discover.com', 'chase.com', 'bankofamerica.com',
            
            # Cloud & Communication Services
            'dropbox.com', 'box.com', 'onedrive.com', 'icloud.com', 'mega.nz',
            'zoom.us', 'teams.microsoft.com', 'slack.com', 'discord.com', 'skype.com',
            'telegram.org', 'signal.org', 'whatsapp.com',
            
            # E-commerce & Shopping
            'ebay.com', 'etsy.com', 'shopify.com', 'walmart.com', 'target.com',
            'bestbuy.com', 'homedepot.com', 'lowes.com', 'costco.com',
            
            # Entertainment & Media
            'netflix.com', 'hulu.com', 'disney.com', 'disneyplus.com', 'hbo.com',
            'spotify.com', 'pandora.com', 'soundcloud.com', 'twitch.tv',
            'reddit.com', 'imgur.com', 'flickr.com', 'vimeo.com',
            
            # Government & Official Organizations
            'whitehouse.gov', 'senate.gov', 'house.gov', 'supremecourt.gov',
            'cdc.gov', 'nih.gov', 'fda.gov', 'fbi.gov', 'cia.gov', 'nasa.gov',
            'usps.com', 'irs.gov', 'ssa.gov', 'medicare.gov',
            'gov.uk', 'gov.ca', 'gov.au', 'europa.eu',
            
            # Search Engines
            'google.com', 'bing.com', 'yahoo.com', 'duckduckgo.com', 'yandex.com',
            'baidu.com', 'ask.com', 'aol.com',
            
            # Productivity & Tools
            'office.com', 'google.com/drive', 'docs.google.com', 'sheets.google.com',
            'slides.google.com', 'forms.google.com', 'calendar.google.com',
            'trello.com', 'asana.com', 'notion.so', 'evernote.com',
            
            # International Domains
            'youtube.co.uk', 'amazon.co.uk', 'amazon.de', 'amazon.fr', 'amazon.jp',
            'google.co.uk', 'google.de', 'google.fr', 'google.ca', 'google.com.au'
        }
        
        self.URL_SHORTENERS_COMPREHENSIVE = {
            'bit.ly', 'tinyurl.com', 'goo.gl', 'ow.ly', 't.co', 'is.gd', 'cli.gs',
            'tiny.cc', 'url4.eu', 'su.pr', 'twurl.nl', 'snipurl.com', 'short.to',
            'ping.fm', 'post.ly', 'just.as', 'bkite.com', 'snipr.com', 'fic.kr',
            'loopt.us', 'doiop.com', 'short.ie', 'kl.am', 'wp.me', 'rubyurl.com',
            'om.ly', 'to.ly', 'bit.do', 'lnkd.in', 'db.tt', 'qr.ae', 'adf.ly',
            'bitly.com', 'cur.lv', 'ity.im', 'q.gs', 'po.st', 'bc.vc', 'u.to',
            'j.mp', 'buzurl.com', 'cutt.us', 'u.bb', 'yourls.org', 'x.co',
            'scrnch.me', 'vzurl.com', 'qr.net', '1url.com', 'tweez.me', 'v.gd',
            'tr.im', 'rebrand.ly', 'buff.ly', 'hootsuite.com', 'shor.by'
        }
        
        self.models = {}
        self.threat_labels = {0: 'Safe', 1: 'Phishing'}
        self._load_models()
    
    def _load_models(self):
        """Load pre-trained ML models"""
        base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        models_dir = os.path.join(base_dir, 'Services', 'URL threat scanning', 'models')
        
        logger.info(f"Looking for models in: {models_dir}")
        
        model_files = {
            'Decision_Tree': 'Decision_Tree_Classifier_URL_Threat_Detection.joblib',
            'Random_Forest': 'Random_Forest_Classifier_URL_Threat_Detection.joblib',
            'Extra_Trees': 'Extra_Trees_Classifier_URL_Threat_Detection.joblib'
        }
        
        for model_name, filename in model_files.items():
            model_path = os.path.join(models_dir, filename)
            if os.path.exists(model_path):
                try:
                    logger.info(f"Loading {model_name} from {model_path}")
                    self.models[model_name] = joblib.load(model_path)
                    logger.info(f"✅ Successfully loaded {model_name} model")
                except Exception as e:
                    logger.error(f"❌ Failed to load {model_name}: {str(e)}")
            else:
                logger.warning(f"❌ Model file not found: {model_path}")
        
        logger.info(f"Loaded {len(self.models)} models total")
        
        if not self.models:
            logger.warning("No models loaded - predictions will use fallback logic")
    
    def extract_advanced_features(self, url):
        """
        Extract comprehensive URL features for enhanced threat detection
        35+ advanced features for better accuracy
        """
        original_url = url
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        
        try:
            parsed = urlparse(url)
            features = {}
            
            # Basic URL metrics (improved)
            features['url_len'] = len(original_url)
            features['domain_len'] = len(parsed.netloc) if parsed.netloc else 0
            features['path_len'] = len(parsed.path) if parsed.path else 0
            features['query_len'] = len(parsed.query) if parsed.query else 0
            
            # Protocol analysis
            features['https'] = 1 if original_url.startswith('https://') else 0
            features['has_port'] = 1 if ':' in parsed.netloc and not parsed.netloc.endswith(':80') and not parsed.netloc.endswith(':443') else 0
            
            # Domain analysis (enhanced)
            domain = parsed.netloc.lower()
            if domain.startswith('www.'):
                domain = domain[4:]
            
            # Subdomain analysis
            domain_parts = domain.split('.')
            features['subdomain_count'] = max(0, len(domain_parts) - 2) if len(domain_parts) > 1 else 0
            features['domain_depth'] = len(domain_parts)
            
            # TLD analysis
            features['tld_suspicious'] = 0
            features['tld_len'] = 0
            try:
                if '.' in domain:
                    tld_part = '.' + domain.split('.')[-1]
                    features['tld_suspicious'] = 1 if tld_part in self.KNOWN_MALICIOUS_TLDS else 0
                    features['tld_len'] = len(tld_part)
            except:
                features['tld_suspicious'] = 0
                features['tld_len'] = 0
            
            # IP address detection (enhanced)
            ip_pattern = r'(([01]?\d\d?|2[0-4]\d|25[0-5])\.){3}([01]?\d\d?|2[0-4]\d|25[0-5])'
            features['having_ip_address'] = 1 if re.search(ip_pattern, domain) else 0
            
            # URL shortener detection (comprehensive)
            features['is_shortener'] = 1 if any(shortener in domain for shortener in self.URL_SHORTENERS_COMPREHENSIVE) else 0
            features['Shortining_Service'] = features['is_shortener']  # Legacy compatibility
            
            # Character analysis (enhanced)
            features['digits'] = sum(1 for c in original_url if c.isdigit())
            features['letters'] = sum(1 for c in original_url if c.isalpha())
            features['digit_ratio'] = features['digits'] / len(original_url) if len(original_url) > 0 else 0
            features['letter_ratio'] = features['letters'] / len(original_url) if len(original_url) > 0 else 0
            
            # Special character counts and analysis
            special_chars = ['@', '?', '-', '=', '.', '#', '%', '+', '$', '!', '*', ',', '//', '&', '_', '~']
            for char in special_chars:
                features[char] = original_url.count(char)
            
            features['special_char_count'] = sum(features.get(char, 0) for char in special_chars)
            features['hyphen_ratio'] = features.get('-', 0) / features['domain_len'] if features['domain_len'] > 0 else 0
            
            # Suspicious pattern detection
            features['suspicious_keywords'] = sum(1 for keyword in self.SUSPICIOUS_KEYWORDS if keyword.lower() in original_url.lower())
            features['multiple_subdomains'] = 1 if features['subdomain_count'] > 2 else 0
            features['long_domain'] = 1 if features['domain_len'] > 20 else 0
            features['many_dots'] = 1 if features.get('.', 0) > 4 else 0
            
            # URL structure analysis
            features['path_depth'] = len([p for p in parsed.path.split('/') if p]) if parsed.path else 0
            features['has_query'] = 1 if parsed.query else 0
            features['query_params'] = len(parse_qs(parsed.query)) if parsed.query else 0
            features['has_fragment'] = 1 if parsed.fragment else 0
            
            # Security indicators
            features['double_slash_redirect'] = 1 if '//' in parsed.path else 0
            features['at_symbol'] = 1 if '@' in original_url else 0
            features['abnormal_url'] = 1 if domain and domain not in original_url.replace(f'//{parsed.netloc}', '') else 0
            
            # Advanced threat indicators
            features['hex_chars'] = len(re.findall(r'[0-9a-fA-F]{8,}', original_url))
            features['random_string'] = 1 if re.search(r'[a-zA-Z0-9]{20,}', domain) else 0
            features['punycode'] = 1 if 'xn--' in domain else 0
            
            # Brand impersonation detection (advanced)
            brand_keywords = ['paypal', 'amazon', 'microsoft', 'google', 'apple', 'facebook', 'netflix', 'bank']
            features['brand_spoofing'] = 1 if any(brand in domain.lower() and domain not in self.LEGITIMATE_DOMAINS_EXTENDED for brand in brand_keywords) else 0
            
            # Simple entropy calculation (randomness measure)
            def simple_entropy(s):
                if not s or len(s) < 2:
                    return 0
                try:
                    entropy = 0
                    for char in set(s):
                        p = s.count(char) / len(s)
                        if p > 0:
                            entropy += p * (-1 * (p * 10))
                    return min(entropy, 10)
                except:
                    return 0
            
            features['domain_entropy'] = simple_entropy(domain) if domain else 0
            features['path_entropy'] = simple_entropy(parsed.path) if parsed.path else 0
            
            return features
            
        except Exception as e:
            logger.error(f"Error extracting features: {e}")
            # Return safe defaults
            default_features = {
                'url_len': len(original_url), 'domain_len': 0, 'path_len': 0, 'query_len': 0,
                'https': 0, 'has_port': 0, 'subdomain_count': 0, 'domain_depth': 0,
                'tld_suspicious': 0, 'tld_len': 0, 'having_ip_address': 0, 'is_shortener': 0,
                'Shortining_Service': 0, 'digits': 0, 'letters': 0, 'digit_ratio': 0,
                'letter_ratio': 0, 'special_char_count': 0, 'hyphen_ratio': 0,
                'suspicious_keywords': 0, 'multiple_subdomains': 0, 'long_domain': 0,
                'many_dots': 0, 'path_depth': 0, 'has_query': 0, 'query_params': 0,
                'has_fragment': 0, 'double_slash_redirect': 0, 'at_symbol': 0,
                'abnormal_url': 0, 'hex_chars': 0, 'random_string': 0, 'punycode': 0,
                'brand_spoofing': 0, 'domain_entropy': 0, 'path_entropy': 0
            }
            # Add special characters
            for char in ['@', '?', '-', '=', '.', '#', '%', '+', '$', '!', '*', ',', '//', '&', '_', '~']:
                default_features[char] = 0
            return default_features
    
    def is_legitimate_domain_advanced(self, url):
        """
        Advanced legitimate domain detection with comprehensive checks
        Enhanced to properly handle Wikimedia and other educational/reference sites
        """
        try:
            if not url.startswith(('http://', 'https://')):
                url = 'http://' + url
            parsed = urlparse(url)
            domain = parsed.netloc.lower().replace('www.', '')
            
            # Remove any port numbers for domain checking
            if ':' in domain:
                domain = domain.split(':')[0]
            
            # Layer 1: Direct exact match check
            if domain in self.LEGITIMATE_DOMAINS_EXTENDED:
                return True, 'exact_match'
            
            # Layer 2: Wikimedia Foundation domains (special handling)
            wikimedia_domains = [
                'wikipedia.org', 'wikimedia.org', 'wikidata.org', 'commons.wikimedia.org',
                'meta.wikimedia.org', 'species.wikimedia.org', 'mediawiki.org',
                'wiktionary.org', 'wikinews.org', 'wikiquote.org', 'wikibooks.org',
                'wikisource.org', 'wikiversity.org', 'wikivoyage.org'
            ]
            
            # Check for any Wikimedia subdomain pattern
            for wiki_domain in wikimedia_domains:
                if domain == wiki_domain or domain.endswith('.' + wiki_domain):
                    return True, 'wikimedia_foundation'
            
            # Check for language-specific Wikipedia domains (e.g., en.wikipedia.org, fr.wikipedia.org)
            if re.match(r'^[a-z]{2,3}\.wikipedia\.org$', domain):
                return True, 'wikipedia_language'
            
            # Layer 3: Government and educational domains (.gov, .edu, .mil)
            trusted_tlds = ['.gov', '.edu', '.mil', '.ac.uk', '.edu.au', '.gov.uk', '.gov.ca']
            if any(domain.endswith(tld) for tld in trusted_tlds):
                return True, 'government_educational'
            
            # Layer 4: Major tech company subdomains
            tech_companies = {
                'google.com': ['accounts', 'drive', 'docs', 'sheets', 'slides', 'forms', 'calendar', 'maps', 'translate', 'scholar', 'chrome', 'play', 'developers'],
                'microsoft.com': ['login', 'account', 'office', 'onedrive', 'teams', 'azure', 'docs', 'support'],
                'apple.com': ['support', 'developer', 'store', 'music', 'tv'],
                'amazon.com': ['aws', 'developer', 'smile'],
                'github.com': ['docs', 'pages', 'api', 'raw', 'gist'],
                'stackoverflow.com': ['meta', 'chat']
            }
            
            for base_domain, subdomains in tech_companies.items():
                if domain == base_domain:
                    return True, 'major_tech_exact'
                for subdomain in subdomains:
                    if domain == f"{subdomain}.{base_domain}":
                        return True, 'major_tech_subdomain'
            
            # Layer 5: Content Delivery Networks and trusted infrastructure
            cdn_domains = [
                'cloudflare.com', 'amazonaws.com', 'azureedge.net', 'googleusercontent.com',
                'fbcdn.net', 'twimg.com', 'licdn.com', 'gstatic.com', 'bootstrapcdn.com',
                'jquery.com', 'cdnjs.com', 'unpkg.com', 'jsdelivr.net'
            ]
            
            for cdn in cdn_domains:
                if domain == cdn or domain.endswith('.' + cdn):
                    return True, 'trusted_cdn'
            
            # Layer 6: International versions of major domains
            international_patterns = [
                r'^google\.(co\.uk|de|fr|ca|com\.au|co\.jp|co\.in)$',
                r'^amazon\.(co\.uk|de|fr|ca|com\.au|co\.jp|in)$',
                r'^microsoft\.(com|co\.uk|de|fr)$',
                r'^apple\.(com|co\.uk|de|fr|ca|com\.au|co\.jp)$'
            ]
            
            for pattern in international_patterns:
                if re.match(pattern, domain):
                    return True, 'international_major'
            
            # Layer 7: Subdomain patterns for legitimate services
            subdomain_patterns = [
                r'^[a-z0-9\-]+\.github\.io$',  # GitHub Pages
                r'^[a-z0-9\-]+\.herokuapp\.com$',  # Heroku apps
                r'^[a-z0-9\-]+\.vercel\.app$',  # Vercel deployments
                r'^[a-z0-9\-]+\.netlify\.app$',  # Netlify sites
                r'^[a-z0-9\-]+\.azurewebsites\.net$',  # Azure websites
                r'^[a-z0-9\-]+\.amazonaws\.com$',  # AWS services
                r'^[a-z0-9\-]+\.cloudfront\.net$'  # CloudFront
            ]
            
            for pattern in subdomain_patterns:
                if re.match(pattern, domain):
                    return True, 'trusted_hosting_platform'
            
            return False, 'unknown_domain'
            
        except Exception as e:
            logger.error(f"Error in legitimate domain check: {e}")
            return False, 'error_in_analysis'
    
    def analyze_url(self, url, confidence_threshold=0.70):
        """
        Main method to analyze URL threat level with enhanced features
        """
        try:
            start_time = time.time()
            
            # Quick legitimate domain check
            is_legit, reason = self.is_legitimate_domain_advanced(url)
            if is_legit:
                validation_features = {
                    'domain_whitelist': True,
                    'ip_address_detected': False,
                    'url_shortener': False,
                    'suspicious_tld': False,
                    'brand_spoofing_risk': False,
                    'multiple_subdomains': False,
                    'suspicious_keywords_count': 0,
                    'domain_entropy': 0,
                    'https_enabled': url.startswith('https://'),
                    'port_analysis': False,
                    'url_length_analysis': 'normal',
                    'risk_score': 0,
                    'government_domain': reason == 'government_educational',
                    'major_tech_domain': reason in ['direct_match', 'major_domain_suffix']
                }
                
                return {
                    'success': True,
                    'url': url,
                    'threat_type': 'Safe',
                    'confidence': 95.0,
                    'ensemble_confidence': 95.0,
                    'is_malicious': False,
                    'reason': f'whitelisted_{reason}',
                    'processing_time': time.time() - start_time,
                    'validation_features': validation_features,
                    'individual_predictions': {},
                    'risk_factors': 0,
                    'final_prediction': 0,
                    'processing_time_ms': round((time.time() - start_time) * 1000, 2),
                    'title': 'URL is Safe',
                    'explanation': 'This URL belongs to a known legitimate domain and is safe to visit.',
                    'status_color': 'success',
                    'status_icon': 'fas fa-shield-check',
                    'features_analyzed': 35,
                    'models_used': len(self.models),
                    'risk_score': 5,
                    'recommendation': 'This URL is safe to visit. It belongs to a trusted domain.',
                    'model_results': []
                }
            
            # Extract advanced features
            features = self.extract_advanced_features(url)
            
            # Create DataFrame with proper structure
            url_df = pd.DataFrame([features])
            
            # Ensure all required columns exist for legacy model compatibility
            legacy_columns = ['url_len', '@', '?', '-', '=', '.', '#', '%', '+', '$', '!', '*', ',', '//', 
                             'abnormal_url', 'https', 'digits', 'letters', 'Shortining_Service', 'having_ip_address']
            
            # Add missing legacy columns and reorder
            for col in legacy_columns:
                if col not in url_df.columns:
                    url_df[col] = 0
            url_df = url_df[legacy_columns]
            
            if not self.models:
                # Fallback logic if no models available
                return self._fallback_analysis(url, features, start_time)
            
            # Model predictions with enhanced logic
            predictions = {}
            all_preds = []
            all_confidences = []
            all_probabilities = []
            model_results = []
            
            for model_name, model in self.models.items():
                try:
                    pred = model.predict(url_df)[0]
                    prob = model.predict_proba(url_df)[0]
                    confidence = max(prob) * 100
                    
                    predictions[model_name] = {
                        'prediction': pred,
                        'threat_type': self.threat_labels.get(pred, 'Unknown'),
                        'confidence': confidence
                    }
                    
                    model_results.append({
                        'model': model_name.replace('_', ' '),
                        'result': self.threat_labels[pred],
                        'confidence': round(confidence, 1),
                        'icon': 'fas fa-tree' if 'Tree' in model_name else 'fas fa-random' if 'Forest' in model_name else 'fas fa-sitemap'
                    })
                    
                    all_preds.append(pred)
                    all_confidences.append(confidence)
                    all_probabilities.append(prob)
                    
                except Exception as e:
                    logger.error(f"Error with {model_name}: {str(e)}")
                    continue
            
            if not all_preds:
                return self._fallback_analysis(url, features, start_time)
            
            # Advanced ensemble voting with probability weighting
            
            # Weighted average of probabilities
            avg_probabilities = np.mean(all_probabilities, axis=0)
            ensemble_pred = np.argmax(avg_probabilities)
            ensemble_confidence = avg_probabilities[ensemble_pred] * 100
            
            # Agreement calculation
            vote_counts = Counter(all_preds)
            agreement = (vote_counts[ensemble_pred] / len(all_preds)) * 100
            
            # Advanced confidence adjustment based on feature analysis
            risk_factors = 0
            if features.get('having_ip_address', 0) == 1:
                risk_factors += 1
            if features.get('is_shortener', 0) == 1:
                risk_factors += 1
            if features.get('suspicious_keywords', 0) > 2:
                risk_factors += 1
            if features.get('brand_spoofing', 0) == 1:
                risk_factors += 2
            if features.get('tld_suspicious', 0) == 1:
                risk_factors += 1
            
            # Adjust confidence based on risk factors
            if ensemble_pred == 1:  # If predicted as phishing
                ensemble_confidence = min(95, ensemble_confidence + (risk_factors * 5))
            else:  # If predicted as safe
                if risk_factors > 2:
                    ensemble_confidence = max(60, ensemble_confidence - (risk_factors * 10))
            
            # Apply stricter threshold for phishing classification
            if ensemble_pred == 1 and ensemble_confidence < confidence_threshold * 100:
                ensemble_pred = 0
                ensemble_confidence = 65.0
            
            processing_time = time.time() - start_time
            
            # Detailed validation features
            validation_features = {
                'domain_whitelist': False,
                'ip_address_detected': features.get('having_ip_address', 0) == 1,
                'url_shortener': features.get('is_shortener', 0) == 1,
                'suspicious_tld': features.get('tld_suspicious', 0) == 1,
                'brand_spoofing_risk': features.get('brand_spoofing', 0) == 1,
                'multiple_subdomains': features.get('multiple_subdomains', 0) == 1,
                'suspicious_keywords_count': features.get('suspicious_keywords', 0),
                'domain_entropy': features.get('domain_entropy', 0),
                'https_enabled': features.get('https', 0) == 1,
                'port_analysis': features.get('has_port', 0) == 1,
                'url_length_analysis': 'long' if features.get('url_len', 0) > 75 else 'normal',
                'risk_score': (risk_factors / 7) * 100,
                'government_domain': False,
                'major_tech_domain': False
            }
            
            # Calculate risk score
            risk_score = min(ensemble_confidence if ensemble_pred == 1 else (100 - ensemble_confidence), 100)
            
            # Prepare response
            is_malicious = ensemble_pred == 1
            threat_type = self.threat_labels[ensemble_pred].lower()
            
            result = {
                'success': True,
                'url': url,
                'threat_type': self.threat_labels[ensemble_pred],
                'confidence': ensemble_confidence,
                'ensemble_confidence': ensemble_confidence,
                'agreement': agreement,
                'individual_predictions': predictions,
                'is_malicious': ensemble_pred == 1,
                'risk_factors': risk_factors,
                'processing_time': processing_time,
                'validation_features': validation_features,
                'final_prediction': ensemble_pred,
                'processing_time_ms': round(processing_time * 1000, 2),
                'title': f"Threat Detected: {self.threat_labels[ensemble_pred]}" if is_malicious else "URL appears Safe",
                'explanation': self._get_threat_explanation(ensemble_pred, ensemble_confidence),
                'status_color': 'danger' if is_malicious else 'success',
                'status_icon': self._get_status_icon(ensemble_pred),
                'features_analyzed': len(features),
                'models_used': len(self.models),
                'risk_score': round(risk_score),
                'recommendation': self._get_recommendation(ensemble_pred, threat_type),
                'model_results': model_results
            }
            
            return result
            
        except Exception as e:
            logger.error(f"Analysis failed: {str(e)}")
            return {
                'success': False,
                'error': f'Analysis failed: {str(e)}',
                'url': url,
                'threat_type': 'Unknown',
                'is_malicious': False,
                'confidence': 0,
                'title': 'Analysis Error',
                'explanation': 'An error occurred during URL analysis. Please try again.',
                'status_color': 'warning',
                'status_icon': 'fas fa-exclamation-triangle'
            }
    
    def _fallback_analysis(self, url, features, start_time):
        """
        Fallback analysis when no models are available
        Uses rule-based logic with advanced features
        """
        risk_score = 0
        
        # Risk factors based on features
        if features.get('having_ip_address', 0) == 1:
            risk_score += 25
        if features.get('is_shortener', 0) == 1:
            risk_score += 20
        if features.get('suspicious_keywords', 0) > 2:
            risk_score += 20
        if features.get('brand_spoofing', 0) == 1:
            risk_score += 30
        if features.get('tld_suspicious', 0) == 1:
            risk_score += 15
        if features.get('abnormal_url', 0) == 1:
            risk_score += 10
        
        is_malicious = risk_score > 50
        threat_type = 'Phishing' if risk_score > 70 else ('Phishing' if is_malicious else 'Safe')
        
        validation_features = {
            'domain_whitelist': False,
            'ip_address_detected': features.get('having_ip_address', 0) == 1,
            'url_shortener': features.get('is_shortener', 0) == 1,
            'suspicious_tld': features.get('tld_suspicious', 0) == 1,
            'brand_spoofing_risk': features.get('brand_spoofing', 0) == 1,
            'multiple_subdomains': features.get('multiple_subdomains', 0) == 1,
            'suspicious_keywords_count': features.get('suspicious_keywords', 0),
            'domain_entropy': features.get('domain_entropy', 0),
            'https_enabled': features.get('https', 0) == 1,
            'port_analysis': features.get('has_port', 0) == 1,
            'url_length_analysis': 'long' if features.get('url_len', 0) > 75 else 'normal',
            'risk_score': risk_score,
            'government_domain': False,
            'major_tech_domain': False
        }
        
        confidence = min(95, max(55, 100 - risk_score))
        
        return {
            'success': True,
            'url': url,
            'threat_type': threat_type,
            'confidence': confidence,
            'ensemble_confidence': confidence,
            'is_malicious': is_malicious,
            'reason': 'fallback_analysis',
            'processing_time': time.time() - start_time,
            'validation_features': validation_features,
            'individual_predictions': {},
            'risk_factors': risk_score // 15,
            'final_prediction': 2 if risk_score > 70 else (3 if risk_score >= 30 else (1 if risk_score >= 15 else 0)),
            'processing_time_ms': round((time.time() - start_time) * 1000, 2),
            'title': f"Threat Detected: {threat_type}" if is_malicious else "URL appears Safe",
            'explanation': f"Rule-based analysis detected potential {threat_type.lower()} threat." if is_malicious else "Rule-based analysis indicates this URL is likely safe.",
            'status_color': 'danger' if is_malicious else 'success',
            'status_icon': 'fas fa-exclamation-triangle' if is_malicious else 'fas fa-check-circle',
            'features_analyzed': len(features),
            'models_used': 0,
            'risk_score': risk_score,
            'recommendation': f"Block this URL - detected risk factors" if is_malicious else "This URL appears to be safe based on rule-based analysis.",
            'model_results': []
        }
    
    def _get_threat_explanation(self, prediction, confidence):
        """Get human-readable explanation for threat level"""
        explanations = {
            0: f"Our AI models analyzed this URL and found it to be safe with {confidence:.1f}% confidence. No malicious patterns were detected.",
            1: f"This URL exhibits phishing patterns with {confidence:.1f}% confidence. It may attempt to steal your credentials or personal information.",
        }
        return explanations.get(prediction, "Unknown threat level detected.")
    
    def _get_status_icon(self, prediction):
        """Get appropriate icon for threat level"""
        icons = {
            0: 'fas fa-shield-check',
            1: 'fas fa-user-shield',
        }
        return icons.get(prediction, 'fas fa-question-circle')
    
    def _get_recommendation(self, prediction, threat_type):
        """Get security recommendation based on threat level"""
        recommendations = {
            0: "This URL appears to be safe. You can proceed with confidence.",
            1: "Do not visit this URL. It appears to be a phishing site designed to steal your credentials or personal information.",
        }
        return recommendations.get(prediction, "Exercise caution when visiting this URL.")

# Global analyzer instance
analyzer = URLThreatAnalyzer()