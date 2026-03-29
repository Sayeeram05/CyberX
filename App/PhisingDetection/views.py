"""
Phishing Detection Views - Production Version
Real-time URL phishing detection using PyTorch neural network
Uses trained scaler for accurate feature normalization
"""

from django.shortcuts import render
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
from django.http import JsonResponse
from django.conf import settings
import torch
import torch.nn as nn
import numpy as np
import time
import json
import os
import logging
import warnings
import joblib
from urllib.parse import urlparse

warnings.filterwarnings('ignore')
logger = logging.getLogger(__name__)

# Import our feature extractor
from .feature_extractor import URLFeatureExtractor


# Define the model architecture (must match training)
class PhishingModel(nn.Module):
    """
    Neural Network model for phishing detection.
    Architecture matches the trained model from Model.ipynb
    """
    def __init__(self, n_input_dim=87):
        super(PhishingModel, self).__init__()
        n_hidden1 = 300
        n_hidden2 = 100
        n_output = 1
        
        self.layer_1 = nn.Linear(n_input_dim, n_hidden1)
        self.layer_2 = nn.Linear(n_hidden1, n_hidden2)
        self.layer_out = nn.Linear(n_hidden2, n_output)
        
        self.relu = nn.ReLU()
        self.sigmoid = nn.Sigmoid()
        self.dropout = nn.Dropout(p=0.1)
        self.batchnorm1 = nn.BatchNorm1d(n_hidden1)
        self.batchnorm2 = nn.BatchNorm1d(n_hidden2)
    
    def forward(self, inputs):
        x = self.relu(self.layer_1(inputs))
        x = self.batchnorm1(x)
        x = self.relu(self.layer_2(x))
        x = self.batchnorm2(x)
        x = self.dropout(x)
        x = self.sigmoid(self.layer_out(x))
        return x


# Global instances
_model = None
_scaler = None
_feature_names = None
_loaded = False


def load_model_and_scaler():
    """
    Load and cache the PyTorch model and scaler.
    Returns tuple of (model, scaler) or (None, None) if loading fails.
    """
    global _model, _scaler, _feature_names, _loaded
    
    if _loaded:
        return _model, _scaler
    
    base_path = os.path.join(settings.BASE_DIR, 'PhisingDetection', 'models')
    
    try:
        # Load the model
        model_path = os.path.join(base_path, 'phishing_model.pth')
        if not os.path.exists(model_path):
            # Try alternate path
            model_path = os.path.join(settings.BASE_DIR, '..', 'Services', 'Phishing-detection', 'phishing_model.pth')
        
        if os.path.exists(model_path):
            logger.info(f"Loading phishing model from: {model_path}")
            _model = PhishingModel(n_input_dim=87)
            state_dict = torch.load(model_path, map_location=torch.device('cpu'), weights_only=True)
            _model.load_state_dict(state_dict)
            _model.eval()
            logger.info("Phishing model loaded successfully")
        else:
            logger.warning("Phishing model not found")
        
        # Load the scaler
        scaler_path = os.path.join(base_path, 'phishing_scaler.joblib')
        if not os.path.exists(scaler_path):
            scaler_path = os.path.join(settings.BASE_DIR, '..', 'Services', 'Phishing-detection', 'phishing_scaler.joblib')
        
        if os.path.exists(scaler_path):
            _scaler = joblib.load(scaler_path)
            logger.info("Scaler loaded successfully")
        else:
            logger.warning("Scaler not found - will use default normalization")
        
        # Load feature names
        feature_path = os.path.join(base_path, 'feature_names.json')
        if not os.path.exists(feature_path):
            feature_path = os.path.join(settings.BASE_DIR, '..', 'Services', 'Phishing-detection', 'feature_names.json')
        
        if os.path.exists(feature_path):
            with open(feature_path, 'r') as f:
                _feature_names = json.load(f)
            logger.info(f"Feature names loaded: {len(_feature_names)} features")
        
    except Exception as e:
        logger.error(f"Error loading model/scaler: {e}")
    
    _loaded = True
    return _model, _scaler


# Known legitimate domains that should never be flagged
TRUSTED_DOMAINS = {
    # Major tech companies
    'google.com', 'microsoft.com', 'apple.com', 'amazon.com', 'facebook.com',
    'twitter.com', 'linkedin.com', 'github.com', 'stackoverflow.com',
    # Wikimedia
    'wikipedia.org', 'wikimedia.org', 'wiktionary.org', 'wikiquote.org',
    'wikibooks.org', 'wikisource.org', 'wikinews.org', 'wikiversity.org',
    'wikidata.org', 'wikivoyage.org', 'mediawiki.org',
    # Government and education
    'gov', 'edu', 'mil',
    # Major services
    'youtube.com', 'netflix.com', 'spotify.com', 'reddit.com', 'twitch.tv',
    'dropbox.com', 'slack.com', 'zoom.us', 'adobe.com', 'oracle.com',
    # Cloud providers
    'aws.amazon.com', 'azure.microsoft.com', 'cloud.google.com',
    # Major news
    'bbc.com', 'cnn.com', 'nytimes.com', 'reuters.com', 'theguardian.com',
    # Banks (these should still be checked carefully)
    'paypal.com', 'chase.com', 'bankofamerica.com', 'wellsfargo.com',
}


def is_trusted_domain(domain: str) -> bool:
    """Check if domain is in trusted list or is a subdomain of trusted domain."""
    domain = domain.lower().strip()
    
    # Direct match
    if domain in TRUSTED_DOMAINS:
        return True
    
    # Check if it's a subdomain of trusted domain
    for trusted in TRUSTED_DOMAINS:
        if domain.endswith('.' + trusted):
            return True
        # Check TLD patterns
        if trusted in ['gov', 'edu', 'mil']:
            if domain.endswith('.' + trusted):
                return True
    
    return False


def normalize_url(url: str) -> str:
    """Normalize and validate URL."""
    url = url.strip()
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    return url


def analyze_url_features(features: dict, domain: str) -> dict:
    """Analyze extracted features to provide detailed insights."""
    risk_factors = []
    security_indicators = []
    
    # Check if trusted domain first
    is_trusted = is_trusted_domain(domain)
    if is_trusted:
        security_indicators.append('Recognized trusted domain')
    
    # Security indicators (positive signals)
    if features.get('https_token', 0) == 0:
        security_indicators.append('HTTPS encryption enabled')
    
    if features.get('dns_record', 0) == 1:
        security_indicators.append('Valid DNS record found')
    
    if features.get('whois_registered_domain', 0) == 1:
        security_indicators.append('Domain is registered')
    
    domain_age = features.get('domain_age', -1)
    if domain_age > 365:
        security_indicators.append(f"Established domain ({domain_age} days old)")
    
    # Risk factors - only add if not a trusted domain
    if features.get('ip', 0) == 1:
        risk_factors.append({
            'severity': 'high',
            'message': 'URL uses IP address instead of domain name',
            'category': 'url_structure'
        })
    
    if features.get('https_token', 0) == 1 and not is_trusted:
        risk_factors.append({
            'severity': 'medium',
            'message': 'Connection is not secured with HTTPS',
            'category': 'security'
        })
    
    if features.get('nb_at', 0) > 0:
        risk_factors.append({
            'severity': 'high',
            'message': 'URL contains @ symbol (potential credential harvesting)',
            'category': 'suspicious_characters'
        })
    
    if features.get('shortening_service', 0) == 1:
        risk_factors.append({
            'severity': 'high',
            'message': 'URL uses a shortening service (hides true destination)',
            'category': 'obfuscation'
        })
    
    if features.get('punycode', 0) == 1 and not is_trusted:
        risk_factors.append({
            'severity': 'high',
            'message': 'Internationalized domain name (punycode) detected',
            'category': 'obfuscation'
        })
    
    if features.get('suspecious_tld', 0) == 1:
        risk_factors.append({
            'severity': 'medium',
            'message': 'Suspicious top-level domain detected',
            'category': 'domain'
        })
    
    if features.get('phish_hints', 0) > 1 and not is_trusted:
        risk_factors.append({
            'severity': 'medium',
            'message': f"Phishing keywords detected in URL ({features.get('phish_hints', 0)} found)",
            'category': 'content'
        })
    
    # Brand impersonation - but not if it's the actual brand
    if (features.get('domain_in_brand', 0) == 1 or features.get('brand_in_subdomain', 0) == 1) and not is_trusted:
        risk_factors.append({
            'severity': 'high',
            'message': 'URL appears to impersonate a known brand',
            'category': 'impersonation'
        })
    
    if features.get('random_domain', 0) == 1 and not is_trusted:
        risk_factors.append({
            'severity': 'medium',
            'message': 'Domain appears to be randomly generated',
            'category': 'domain'
        })
    
    # New domain check - only if not trusted
    if not is_trusted and domain_age >= 0 and domain_age < 30:
        risk_factors.append({
            'severity': 'high',
            'message': f"Very new domain (only {domain_age} days old)",
            'category': 'domain'
        })
    
    # Don't flag external favicon for trusted domains
    if features.get('external_favicon', 0) == 1 and not is_trusted:
        if not any(trusted in domain for trusted in ['wikimedia', 'wikipedia', 'google', 'microsoft']):
            risk_factors.append({
                'severity': 'low',
                'message': 'External favicon detected',
                'category': 'content'
            })
    
    return {
        'risk_factors': risk_factors,
        'security_indicators': security_indicators,
        'risk_score': calculate_risk_score(risk_factors),
        'is_trusted': is_trusted
    }


def calculate_risk_score(risk_factors: list) -> int:
    """Calculate overall risk score based on risk factors."""
    score = 0
    for factor in risk_factors:
        if factor['severity'] == 'high':
            score += 30
        elif factor['severity'] == 'medium':
            score += 15
        elif factor['severity'] == 'low':
            score += 5
    return min(score, 100)


def index(request):
    """Main phishing detection page."""
    model, scaler = load_model_and_scaler()
    
    context = {
        'result': None,
        'model_available': model is not None
    }
    
    if request.method == 'POST':
        url = request.POST.get('url', '').strip()
        
        if url:
            start_time = time.time()
            
            try:
                # Normalize URL
                normalized_url = normalize_url(url)
                parsed = urlparse(normalized_url)
                domain = parsed.netloc
                
                # Check trusted domain first
                is_trusted = is_trusted_domain(domain)
                
                # Extract features
                extractor = URLFeatureExtractor(normalized_url, timeout=5)
                features = extractor.extract_all_features()
                feature_array = extractor.extract_features_array()
                
                # Get model prediction
                if model is not None and scaler is not None:
                    # Use trained scaler for proper normalization
                    feature_array_normalized = scaler.transform([feature_array])[0]
                    feature_tensor = torch.from_numpy(np.array([feature_array_normalized])).float()
                    
                    with torch.no_grad():
                        prediction = model(feature_tensor)
                        probability = prediction.item()
                    
                    # probability > 0.5 means legitimate in training (target=1 was legitimate)
                    is_legitimate = probability > 0.5
                    confidence = probability if is_legitimate else (1 - probability)
                    
                    # Override for trusted domains
                    if is_trusted:
                        is_legitimate = True
                        confidence = max(confidence, 0.95)
                    
                else:
                    # Fallback: heuristic analysis
                    is_legitimate = analyze_url_heuristic(features, domain)
                    confidence = 0.75 if is_legitimate else 0.70
                    probability = 0.75 if is_legitimate else 0.25
                
                # Analyze features for detailed insights
                analysis = analyze_url_features(features, domain)
                
                # Calculate processing time
                processing_time_ms = (time.time() - start_time) * 1000
                
                # Determine status based on model prediction AND risk analysis
                if is_legitimate:
                    if analysis['risk_score'] < 15 or is_trusted:
                        status = 'safe'
                        status_color = 'success'
                        status_icon = 'fas fa-shield-alt'
                        title = 'URL Appears Safe'
                        explanation = 'This URL shows no significant signs of phishing activity.'
                    else:
                        status = 'caution'
                        status_color = 'warning'
                        status_icon = 'fas fa-exclamation-triangle'
                        title = 'Proceed with Caution'
                        explanation = 'This URL is likely legitimate but has some minor risk factors.'
                else:
                    if confidence > 0.85 and analysis['risk_score'] > 30:
                        status = 'danger'
                        status_color = 'danger'
                        status_icon = 'fas fa-skull-crossbones'
                        title = 'High Risk - Likely Phishing'
                        explanation = 'Strong indicators suggest this URL may be a phishing attempt.'
                    else:
                        status = 'warning'
                        status_color = 'warning'
                        status_icon = 'fas fa-exclamation-circle'
                        title = 'Potential Risk Detected'
                        explanation = 'This URL shows some characteristics that warrant caution.'
                
                # Build result
                context['result'] = {
                    'url': url,
                    'normalized_url': normalized_url,
                    'domain': domain,
                    'scheme': parsed.scheme.upper(),
                    'path': parsed.path or '/',
                    
                    'is_phishing': not is_legitimate,
                    'is_safe': is_legitimate and analysis['risk_score'] < 15,
                    'is_trusted': is_trusted,
                    'confidence': round(confidence * 100, 1),
                    'probability': round(probability * 100, 1),
                    
                    'status': status,
                    'status_color': status_color,
                    'status_icon': status_icon,
                    'title': title,
                    'explanation': explanation,
                    
                    'risk_score': analysis['risk_score'],
                    'risk_factors': analysis['risk_factors'],
                    'security_indicators': analysis['security_indicators'],
                    
                    'features': {
                        'url_length': features['length_url'],
                        'hostname_length': features['length_hostname'],
                        'num_dots': features['nb_dots'],
                        'num_subdomains': features['nb_subdomains'],
                        'uses_https': features['https_token'] == 0,
                        'uses_ip': features['ip'] == 1,
                        'has_at_symbol': features['nb_at'] > 0,
                        'is_shortening_service': features['shortening_service'] == 1,
                        'has_suspicious_tld': features['suspecious_tld'] == 1,
                        'phishing_keywords': features['phish_hints'],
                        'domain_age_days': features['domain_age'],
                        'has_login_form': features['login_form'] == 1,
                    },
                    
                    'processing_time_ms': processing_time_ms,
                    'model_used': model is not None,
                }
                
                # Generate recommendation
                context['result']['recommendation'] = generate_recommendation(status, is_trusted, analysis)
                    
            except Exception as e:
                logger.error(f"Error analyzing URL: {e}", exc_info=True)
                context['result'] = {
                    'error': True,
                    'error_message': f"Error analyzing URL: {str(e)}",
                    'url': url
                }
    
    return render(request, 'PhishingDetection.html', context)


def generate_recommendation(status: str, is_trusted: bool, analysis: dict) -> str:
    """Generate appropriate recommendation based on analysis."""
    if is_trusted:
        return (
            "This is a recognized trusted domain. The website appears to be safe for browsing. "
            "However, always verify you're on the correct URL and look for the padlock icon in your browser."
        )
    
    if status == 'danger':
        return (
            "We strongly advise against visiting this URL. It exhibits multiple characteristics "
            "of phishing websites. If you received this link via email or message, report it as spam "
            "and delete the message. Never enter personal information on suspicious websites."
        )
    elif status == 'warning':
        return (
            "Exercise caution with this URL. While it may be legitimate, it has some concerning "
            "characteristics. Verify the sender if you received this via email, and avoid entering "
            "sensitive information unless you can confirm the website's authenticity."
        )
    elif status == 'caution':
        return (
            "This URL appears mostly safe but has minor risk factors. Proceed if you trust the source, "
            "but remain vigilant for any suspicious behavior on the website."
        )
    else:
        return (
            "This URL appears to be safe and shows no significant indicators of phishing activity. "
            "However, always remain cautious when entering personal information online."
        )


def analyze_url_heuristic(features: dict, domain: str) -> bool:
    """
    Fallback heuristic analysis when model is not available.
    Returns True if URL appears legitimate, False if suspicious.
    """
    # Check trusted domain first
    if is_trusted_domain(domain):
        return True
    
    score = 0
    
    # Strong positive indicators
    if features.get('https_token', 1) == 0:
        score += 3
    if features.get('dns_record', 0) == 1:
        score += 2
    if features.get('whois_registered_domain', 0) == 1:
        score += 2
    if features.get('domain_age', -1) > 365:
        score += 3
    if features.get('domain_age', -1) > 1000:
        score += 2
    
    # Negative indicators
    if features.get('ip', 0) == 1:
        score -= 5
    if features.get('shortening_service', 0) == 1:
        score -= 4
    if features.get('nb_at', 0) > 0:
        score -= 5
    if features.get('suspecious_tld', 0) == 1:
        score -= 3
    if features.get('phish_hints', 0) > 1:
        score -= features.get('phish_hints', 0) * 2
    if features.get('domain_in_brand', 0) == 1:
        score -= 4
    if features.get('brand_in_subdomain', 0) == 1:
        score -= 3
    if features.get('random_domain', 0) == 1:
        score -= 3
    if features.get('domain_age', -1) >= 0 and features.get('domain_age', -1) < 30:
        score -= 5
    if features.get('punycode', 0) == 1:
        score -= 4
    
    return score >= 0


@csrf_exempt
@require_http_methods(["POST"])
def api_analyze(request):
    """API endpoint for URL analysis."""
    try:
        data = json.loads(request.body)
        url = data.get('url', '').strip()
        
        if not url:
            return JsonResponse({
                'success': False,
                'error': 'URL is required'
            }, status=400)
        
        start_time = time.time()
        normalized_url = normalize_url(url)
        parsed = urlparse(normalized_url)
        domain = parsed.netloc
        
        # Check trusted domain
        is_trusted = is_trusted_domain(domain)
        
        # Extract features
        extractor = URLFeatureExtractor(normalized_url, timeout=5)
        features = extractor.extract_all_features()
        feature_array = extractor.extract_features_array()
        
        # Get model prediction
        model, scaler = load_model_and_scaler()
        
        if model is not None and scaler is not None:
            feature_array_normalized = scaler.transform([feature_array])[0]
            feature_tensor = torch.from_numpy(np.array([feature_array_normalized])).float()
            
            with torch.no_grad():
                prediction = model(feature_tensor)
                probability = prediction.item()
            
            is_legitimate = probability > 0.5
            confidence = probability if is_legitimate else (1 - probability)
            
            if is_trusted:
                is_legitimate = True
                confidence = max(confidence, 0.95)
        else:
            is_legitimate = analyze_url_heuristic(features, domain)
            confidence = 0.75 if is_legitimate else 0.70
        
        analysis = analyze_url_features(features, domain)
        processing_time_ms = (time.time() - start_time) * 1000
        
        return JsonResponse({
            'success': True,
            'url': url,
            'domain': domain,
            'is_phishing': not is_legitimate,
            'is_trusted': is_trusted,
            'confidence': round(confidence * 100, 1),
            'risk_score': analysis['risk_score'],
            'risk_factors': [f['message'] for f in analysis['risk_factors']],
            'security_indicators': analysis['security_indicators'],
            'processing_time_ms': round(processing_time_ms, 2),
            'model_used': model is not None
        })
        
    except json.JSONDecodeError:
        return JsonResponse({
            'success': False,
            'error': 'Invalid JSON'
        }, status=400)
    except Exception as e:
        logger.error(f"API error: {e}", exc_info=True)
        return JsonResponse({
            'success': False,
            'error': str(e)
        }, status=500)
