"""
URL Threat Detection System v3.0
=====================================================
6-Step Analysis Pipeline:
  1. URL Normalization        — parse · clean · decode
  2. Blocklist & IP Check     — known-bad patterns, shorteners, IP-in-URL
  3. Domain Analysis          — trusted whitelist + WHOIS age + DNS
  4. URL Structure Analysis   — length · depth · entropy · special chars
  5. Reputation Heuristics    — brand spoofing · keywords · TLD
  6. ML Classification        — 3-model ensemble (DT / RF / ET)

Risk Score = ml×0.4 + domain×0.2 + reputation×0.2 + structure×0.2
"""

from django.shortcuts import render
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods

import re
import os
import time
import json
import math
import socket
import logging
from urllib.parse import urlparse, unquote, parse_qs, urlunparse
from collections import Counter
from datetime import datetime

try:
    import whois as python_whois
    HAS_WHOIS = True
except ImportError:
    HAS_WHOIS = False

try:
    import dns.resolver
    HAS_DNS = True
except ImportError:
    HAS_DNS = False

# Import the ML analyzer
try:
    from .url_analyzer_production import analyzer
except ImportError:
    analyzer = None

logger = logging.getLogger('UrlThreatDetection')


# ═══════════════════════════════════════════════════════════════════
#  STEP 1 — URL NORMALIZATION
# ═══════════════════════════════════════════════════════════════════

def step_normalize(raw_url):
    """Parse, clean, and normalize the URL."""
    result = {
        'status': 'valid', 'message': '', 'url': raw_url,
        'normalized_url': raw_url, 'domain': '', 'raw_domain': '',
        'protocol': 'https', 'path': '/', 'query': '', 'fragment': '',
    }
    try:
        url = unquote(raw_url.strip())
        if not url.startswith(('http://', 'https://', 'ftp://')):
            url = 'https://' + url

        parsed = urlparse(url)
        domain = (parsed.netloc or '').lower().strip()
        display = domain[4:] if domain.startswith('www.') else domain
        domain = re.sub(r':(80|443)$', '', domain)

        path = re.sub(r'/+', '/', parsed.path or '/')
        if path != '/' and path.endswith('/'):
            path = path.rstrip('/')

        normalized = urlunparse((parsed.scheme, domain, path,
                                 parsed.params, parsed.query, ''))
        result.update({
            'url': url, 'normalized_url': normalized,
            'domain': display, 'raw_domain': domain,
            'protocol': parsed.scheme or 'https', 'path': path,
            'query': parsed.query or '', 'fragment': parsed.fragment or '',
            'status': 'valid',
            'message': f'Parsed — domain: {display}, protocol: {(parsed.scheme or "https").upper()}',
        })
    except Exception as e:
        result['status'] = 'warning'
        result['message'] = f'Parse issue: {e}'
    return result


# ═══════════════════════════════════════════════════════════════════
#  STEP 2 — BLOCKLIST & SHORTENER CHECK
# ═══════════════════════════════════════════════════════════════════

SHORTENER_DOMAINS = {
    'bit.ly', 'tinyurl.com', 'goo.gl', 'ow.ly', 't.co', 'is.gd',
    'tiny.cc', 'short.to', 'cutt.ly', 'rebrand.ly', 'buff.ly',
    'adf.ly', 'shorte.st', 'bc.vc', 'po.st', 'j.mp', 'v.gd',
    'tr.im', 'cli.gs', 'u.to', 'x.co', 'lnkd.in', 'db.tt',
    'qr.ae', 'bitly.com', 'shor.by', 'yourls.org', 'rb.gy',
    's.id', 'shorturl.at', 'clck.ru', 'zpr.io', 'amzn.to',
}

BLOCKED_PATTERNS = [
    ('data:', 'Data URI — can embed executable content'),
    ('javascript:', 'JavaScript URI — potential XSS'),
    ('vbscript:', 'VBScript URI — script injection'),
]


def step_blocklist(domain, url, features):
    """Check against blocklists and shortener databases."""
    result = {
        'status': 'clear', 'is_blocked': False, 'is_shortener': False,
        'block_reason': None, 'message': 'Not in any blocklist',
        'risk_contribution': 0,
    }
    dl = domain.lower()
    for s in SHORTENER_DOMAINS:
        if dl == s or dl.endswith('.' + s):
            result.update(is_shortener=True, status='warning',
                          message=f'URL shortener ({s}) — destination hidden',
                          risk_contribution=25)
            break

    for pat, reason in BLOCKED_PATTERNS:
        if pat in url.lower():
            result.update(is_blocked=True, status='blocked',
                          block_reason=reason,
                          message=f'Dangerous: {reason}',
                          risk_contribution=90)
            break

    if 'xn--' in dl:
        result['status'] = 'warning'
        result['message'] = 'Punycode domain — potential homograph attack'
        result['risk_contribution'] = max(result['risk_contribution'], 30)

    if result['status'] == 'clear':
        result['message'] = 'Domain not in blocklist or shortener database'
    return result


# ═══════════════════════════════════════════════════════════════════
#  STEP 3 — TRUSTED DOMAIN CHECK
# ═══════════════════════════════════════════════════════════════════

def step_trusted_domain(url, domain):
    """7-layer trusted domain whitelist."""
    result = {
        'status': 'unknown', 'is_trusted': False, 'trust_reason': None,
        'trust_layer': None, 'message': 'Not in trusted database',
        'risk_contribution': 50,
    }
    if not analyzer:
        result['message'] = 'Analyzer unavailable — whitelist skipped'
        return result
    try:
        full = url if url.startswith(('http://', 'https://')) else f'https://{url}'
        ok, reason = analyzer.is_legitimate_domain_advanced(full)
        LABELS = {
            'exact_match':              ('Exact Match',                 'Layer 1'),
            'wikimedia_foundation':     ('Wikimedia Foundation',        'Layer 2'),
            'wikipedia_language':       ('Wikipedia Language Site',     'Layer 2'),
            'government_educational':   ('Government / Educational',   'Layer 3'),
            'major_tech_exact':         ('Major Tech Company',         'Layer 4'),
            'major_tech_subdomain':     ('Tech Subdomain',             'Layer 4'),
            'trusted_cdn':              ('Trusted CDN',                'Layer 5'),
            'international_major':      ('International Domain',       'Layer 6'),
            'trusted_hosting_platform': ('Hosting Platform',           'Layer 7'),
        }
        if ok:
            label, layer = LABELS.get(reason, (reason.replace('_', ' ').title(), '?'))
            result.update(status='trusted', is_trusted=True,
                          trust_reason=label, trust_layer=layer,
                          message=f'Verified — {label} ({layer})',
                          risk_contribution=5)
    except Exception as e:
        logger.warning(f"Whitelist error: {e}")
        result['message'] = 'Whitelist check error'
    return result


# ═══════════════════════════════════════════════════════════════════
#  STEP 4 — DOMAIN INTELLIGENCE (WHOIS / DNS)
# ═══════════════════════════════════════════════════════════════════

def step_domain_intel(domain):
    """WHOIS age / registrar + DNS resolution."""
    result = {
        'status': 'unknown', 'age_days': None, 'creation_date': None,
        'registrar': None, 'dns_resolves': None, 'dns_ips': [],
        'risk_level': 'unknown',
        'message': 'Domain intelligence unavailable',
        'risk_contribution': 50,
    }
    clean = domain.split(':')[0] if ':' in domain else domain
    if not clean or re.match(r'^\d{1,3}(\.\d{1,3}){3}$', clean):
        result.update(message='IP address — WHOIS not applicable', status='skipped')
        return result

    # WHOIS
    if HAS_WHOIS:
        try:
            w = python_whois.whois(clean)
            creation = w.creation_date
            if isinstance(creation, list):
                creation = creation[0]
            if creation:
                if not isinstance(creation, datetime):
                    from datetime import datetime as dt
                    creation = dt.combine(creation, dt.min.time())
                age = (datetime.now() - creation).days
                result['age_days'] = age
                result['creation_date'] = creation.strftime('%Y-%m-%d')
                if age < 30:
                    result.update(risk_level='high', risk_contribution=80,
                                  message=f'Only {age} days old — very new')
                elif age < 90:
                    result.update(risk_level='medium', risk_contribution=55,
                                  message=f'{age} days old — relatively new')
                elif age < 365:
                    result.update(risk_level='low', risk_contribution=25,
                                  message=f'{age} days ({age // 30} months)')
                else:
                    y = age // 365
                    result.update(risk_level='safe', risk_contribution=10,
                                  message=f'Established — {y}+ year{"s" if y != 1 else ""}')
                result['status'] = 'checked'
            else:
                result.update(message='WHOIS: no creation date', status='partial')
            if w.registrar:
                result['registrar'] = str(w.registrar)
        except Exception as e:
            logger.debug(f"WHOIS error {clean}: {e}")
            result.update(message='WHOIS failed — privacy-protected?', status='error')

    # DNS
    if HAS_DNS:
        try:
            ans = dns.resolver.resolve(clean, 'A', lifetime=5)
            result['dns_resolves'] = True
            result['dns_ips'] = [str(r) for r in ans]
            if result['status'] not in ('checked',):
                result['status'] = 'partial'
                if 'unavailable' in result['message']:
                    result['message'] = f'DNS resolves to {len(result["dns_ips"])} IP(s)'
        except Exception:
            result['dns_resolves'] = False
            if result['status'] not in ('checked',):
                result.update(message='Domain does not resolve', risk_contribution=70)
    return result


# ═══════════════════════════════════════════════════════════════════
#  STEP 5 — URL STRUCTURE ANALYSIS
# ═══════════════════════════════════════════════════════════════════

def step_structure(url, features):
    """URL structural analysis — length, depth, entropy, chars."""
    issues = []
    score = 0
    url_len  = features.get('url_len', len(url))
    path_dep = features.get('path_depth', 0)
    sub_cnt  = features.get('subdomain_count', 0)
    q_params = features.get('query_params', 0)
    specials = features.get('special_char_count', 0)
    entropy  = features.get('domain_entropy', 0)

    if url_len > 200:   issues.append('Extremely long URL (>200 chars)'); score += 25
    elif url_len > 100: issues.append('Long URL (>100 chars)');           score += 10
    if path_dep > 5:    issues.append(f'Deep nesting ({path_dep} levels)');score += 15
    elif path_dep > 3:  issues.append(f'Moderate depth ({path_dep})');     score += 5
    if sub_cnt > 3:     issues.append(f'Excess subdomains ({sub_cnt})');   score += 20
    elif sub_cnt > 1:   issues.append(f'Multiple subdomains ({sub_cnt})'); score += 5
    if q_params > 5:    issues.append(f'Many query params ({q_params})');  score += 10
    if specials > 15:   issues.append(f'Special-char density ({specials})'); score += 15
    elif specials > 8:  issues.append(f'Elevated specials ({specials})');  score += 5
    if entropy > 4:     issues.append('High domain entropy');              score += 15
    if features.get('double_slash_redirect', 0):
        issues.append('Double-slash redirect'); score += 10
    if features.get('at_symbol', 0):
        issues.append('@ symbol (redirect trick)'); score += 20
    if features.get('hex_chars', 0):
        issues.append('Hex-encoded segments'); score += 10

    score = min(score, 100)
    if score == 0:       st, msg = 'clean',      'Structure normal'
    elif score <= 20:    st, msg = 'minor',      f'{len(issues)} minor note{"s" if len(issues)!=1 else ""}'
    elif score <= 50:    st, msg = 'concerning',  f'{len(issues)} anomal{"ies" if len(issues)!=1 else "y"}'
    else:                st, msg = 'suspicious',  f'{len(issues)} suspicious characteristics'

    return {
        'status': st, 'score': score, 'issues': issues,
        'issue_count': len(issues), 'message': msg,
        'risk_contribution': score,
        'details': {
            'url_length': url_len, 'path_depth': path_dep,
            'subdomain_count': sub_cnt, 'query_params': q_params,
            'special_chars': specials, 'entropy': round(entropy, 2),
        },
    }


# ═══════════════════════════════════════════════════════════════════
#  STEP 6 — REPUTATION HEURISTICS
# ═══════════════════════════════════════════════════════════════════

BRAND_DOMAINS = {
    'paypal': 'paypal.com', 'amazon': 'amazon.com', 'microsoft': 'microsoft.com',
    'google': 'google.com', 'apple': 'apple.com', 'facebook': 'facebook.com',
    'netflix': 'netflix.com', 'instagram': 'instagram.com', 'twitter': 'twitter.com',
    'linkedin': 'linkedin.com', 'dropbox': 'dropbox.com', 'ebay': 'ebay.com',
    'chase': 'chase.com', 'wellsfargo': 'wellsfargo.com',
    'bankofamerica': 'bankofamerica.com',
}

SUSPICIOUS_TLDS = {
    '.tk', '.ml', '.ga', '.cf', '.gq', '.pw', '.cc', '.ws', '.info', '.biz',
    '.top', '.click', '.download', '.stream', '.science', '.party', '.racing',
    '.win', '.loan', '.faith', '.accountant', '.cricket', '.date', '.review',
    '.country', '.kim', '.work', '.men', '.trade', '.webcam', '.bid', '.xyz',
}

PHISHING_KEYWORDS = [
    'login', 'signin', 'sign-in', 'account', 'verify', 'secure', 'update',
    'confirm', 'suspended', 'locked', 'limited', 'verification', 'security',
    'alert', 'urgent', 'immediate', 'expire', 'password', 'credential',
    'authenticate', 'validate', 'unlock', 'recover', 'restore',
]


def step_reputation(url, domain, features):
    """Brand spoofing, keywords, TLD analysis."""
    flags, score = [], 0
    url_l, dom_l = url.lower(), domain.lower()

    brand_spoofed = None
    for brand, legit in BRAND_DOMAINS.items():
        if brand in dom_l and dom_l != legit and not dom_l.endswith('.' + legit):
            brand_spoofed = brand
            flags.append(f'Potential {brand.title()} impersonation')
            score += 35
            break

    tld = ('.' + dom_l.split('.')[-1]) if '.' in dom_l else ''
    if tld in SUSPICIOUS_TLDS:
        flags.append(f'Suspicious TLD ({tld})'); score += 20

    kw = sum(1 for k in PHISHING_KEYWORDS if k in url_l)
    if kw >= 3:   flags.append(f'{kw} phishing keywords'); score += 25
    elif kw >= 1: flags.append(f'{kw} phishing keyword{"s" if kw>1 else ""}'); score += 10

    https = url.startswith('https://')
    if not https: flags.append('No HTTPS'); score += 10

    h = dom_l.count('-')
    if h > 3:     flags.append(f'Excess hyphens ({h})'); score += 15
    elif h > 1:   flags.append(f'Multiple hyphens ({h})'); score += 5

    if features.get('random_string', 0):
        flags.append('Random-looking domain'); score += 20
    if features.get('punycode', 0):
        flags.append('IDN / punycode homograph risk'); score += 25

    score = min(score, 100)
    if score == 0:    st, msg = 'clean',  'No reputation concerns'
    elif score <= 20: st, msg = 'low',    f'{len(flags)} minor flag{"s" if len(flags)!=1 else ""}'
    elif score <= 50: st, msg = 'medium', f'{len(flags)} concern{"s" if len(flags)!=1 else ""}'
    else:             st, msg = 'high',   f'{len(flags)} significant issue{"s" if len(flags)!=1 else ""}'

    return {
        'status': st, 'score': score, 'flags': flags,
        'flag_count': len(flags), 'brand_spoofed': brand_spoofed,
        'keyword_count': kw, 'https_enabled': https,
        'suspicious_tld': tld in SUSPICIOUS_TLDS,
        'message': msg, 'risk_contribution': score,
    }


# ═══════════════════════════════════════════════════════════════════
#  STEP 7 — IP INTELLIGENCE
# ═══════════════════════════════════════════════════════════════════

PRIVATE_RANGES = [
    (r'^10\.',                        'Class-A private'),
    (r'^172\.(1[6-9]|2\d|3[01])\.',  'Class-B private'),
    (r'^192\.168\.',                   'Class-C private'),
    (r'^127\.',                        'Loopback'),
    (r'^0\.',                          'Current network'),
    (r'^169\.254\.',                    'Link-local'),
]


def step_ip_intel(url, domain, features):
    """IP detection, resolution, private-range check."""
    result = {
        'status': 'clean', 'has_ip_in_url': False, 'resolved_ip': None,
        'is_private_ip': False, 'ip_warning': None,
        'message': 'No IP concerns', 'risk_contribution': 0,
    }
    ip_match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', domain)
    if ip_match:
        ip = ip_match.group(1)
        result.update(has_ip_in_url=True, resolved_ip=ip, status='suspicious',
                      message=f'Raw IP ({ip}) instead of domain', risk_contribution=40)
        for pat, label in PRIVATE_RANGES:
            if re.match(pat, ip):
                result.update(is_private_ip=True,
                              ip_warning=f'{label} — not routable',
                              risk_contribution=60,
                              message=f'{label} IP ({ip})')
                break
        return result

    clean = domain.split(':')[0]
    try:
        ip = socket.gethostbyname(clean)
        result['resolved_ip'] = ip
        for pat, label in PRIVATE_RANGES:
            if re.match(pat, ip):
                result.update(is_private_ip=True, status='warning',
                              ip_warning=f'Resolves to {label.lower()} ({ip})',
                              risk_contribution=30,
                              message=f'Resolves to {label.lower()} IP')
                break
        if not result['is_private_ip']:
            result['message'] = f'Resolves to {ip}'
    except socket.gaierror:
        result.update(status='warning', message='Cannot resolve domain',
                      risk_contribution=35)
    except Exception:
        result['message'] = 'IP resolution unavailable'
    return result


# ═══════════════════════════════════════════════════════════════════
#  STEP 8 — ML CLASSIFICATION
# ═══════════════════════════════════════════════════════════════════

def step_ml_classify(url):
    """3-model ensemble classification."""
    result = {
        'status': 'unavailable', 'prediction': 'Unknown', 'prediction_code': -1,
        'confidence': 0, 'agreement': 0, 'models': [], 'models_used': 0,
        'message': 'ML models not available', 'risk_contribution': 50,
    }
    if not analyzer or not analyzer.models:
        result['message'] = 'Models not loaded — heuristic only'
        return result
    try:
        a = analyzer.analyze_url(url, confidence_threshold=0.70)
        mrs = a.get('model_results', [])
        if not mrs:
            for n, info in a.get('individual_predictions', {}).items():
                if isinstance(info, dict):
                    mrs.append({
                        'model': n.replace('_', ' '),
                        'result': info.get('threat_type', 'Unknown'),
                        'confidence': round(info.get('confidence', 0), 1),
                        'icon': ('fas fa-tree' if 'Tree' in n
                                 else 'fas fa-random' if 'Forest' in n
                                 else 'fas fa-sitemap'),
                    })
        mal = a.get('is_malicious', False)
        tt  = a.get('threat_type', 'Safe')
        c   = a.get('ensemble_confidence', a.get('confidence', 0))
        ag  = a.get('agreement', 0)
        CODES = {'Safe': 0, 'Phishing': 1}
        result.update(
            status='malicious' if mal else 'safe',
            prediction=tt, prediction_code=CODES.get(tt, 0),
            confidence=round(c, 1), agreement=round(ag, 1),
            models=mrs, models_used=len(mrs),
            message=(f'Ensemble: {tt} ({c:.1f}%)' if mal
                     else f'{tt} — {c:.1f}% confidence'),
            risk_contribution=min(95, c) if mal else max(5, 100 - c),
        )
    except Exception as e:
        logger.error(f"ML error: {e}")
        result['message'] = 'ML classification error'
    return result


# ═══════════════════════════════════════════════════════════════════
#  STEP 9 — RISK SCORING
# ═══════════════════════════════════════════════════════════════════

WEIGHTS = {
    'ml': 0.40, 'domain': 0.20, 'structure': 0.20, 'reputation': 0.20,
}


def step_risk_scoring(steps):
    """Weighted composite risk 0-100 using 4 components."""
    c, factors = {}, []

    # Domain score = merge of Trusted + Domain Intel
    td_risk = steps.get('trusted', {}).get('risk_contribution', 0)
    di_risk = steps.get('domain_intel', {}).get('risk_contribution', 0)
    # If trusted, use low risk; otherwise use domain intel
    if steps.get('trusted', {}).get('is_trusted'):
        domain_risk = min(td_risk, 10)
    else:
        domain_risk = max(td_risk, di_risk)
    c['Domain'] = domain_risk

    st_risk = steps.get('structure', {}).get('risk_contribution', 0)
    c['Structure'] = st_risk

    rp_risk = steps.get('reputation', {}).get('risk_contribution', 0)
    c['Reputation'] = rp_risk

    ml_risk = steps.get('ml', {}).get('risk_contribution', 0)
    c['ML Classification'] = ml_risk

    for label, v in c.items():
        if v > 10:
            wk = {'Domain': 'domain', 'Structure': 'structure',
                  'Reputation': 'reputation', 'ML Classification': 'ml'}[label]
            factors.append({'factor': label, 'score': v,
                            'weight': f'{WEIGHTS[wk]:.0%}'})

    w = (c['ML Classification'] * WEIGHTS['ml']
       + c['Domain']            * WEIGHTS['domain']
       + c['Structure']         * WEIGHTS['structure']
       + c['Reputation']        * WEIGHTS['reputation'])

    # Override guards (Blocklist/IP are pre-filters)
    if steps.get('trusted', {}).get('is_trusted'):  w = min(w, 15)
    if steps.get('blocklist', {}).get('is_blocked'): w = max(w, 80)
    bl_ip = steps.get('blocklist_ip', {})  # merged step
    if bl_ip.get('is_blocked'): w = max(w, 80)
    if bl_ip.get('has_ip_in_url') and not steps.get('trusted', {}).get('is_trusted'):
        w = max(w, 50)

    risk = int(min(max(round(w), 0), 100))
    if risk < 25:    lvl, msg = 'low',      f'{risk}/100 — Low risk'
    elif risk < 50:  lvl, msg = 'medium',   f'{risk}/100 — Medium risk'
    elif risk < 75:  lvl, msg = 'high',     f'{risk}/100 — High risk'
    else:            lvl, msg = 'critical', f'{risk}/100 — Critical risk'

    factors.sort(key=lambda x: x['score'], reverse=True)
    return {'status': lvl, 'score': risk, 'level': lvl,
            'component_scores': c, 'contributing_factors': factors[:5],
            'message': msg}


# ═══════════════════════════════════════════════════════════════════
#  UI HELPERS
# ═══════════════════════════════════════════════════════════════════

def _title(level, pred):
    if level == 'safe': return 'URL Appears Safe'
    if level == 'suspicious':
        return f'Suspicious URL{" — " + pred if pred != "Safe" else ""}'
    return f'Malicious URL Detected{" — " + pred if pred != "Safe" else ""}'


def _explanation(level, risk, conf):
    if level == 'safe':
        return (f'Risk score {risk}/100. '
                f'No significant threats detected across all 6 pipeline steps.')
    if level == 'suspicious':
        return (f'Risk score {risk}/100. '
                f'Some concerning characteristics — proceed with caution.')
    return (f'Risk score {risk}/100 · {conf:.0f}% ML confidence. '
            f'Multiple threat indicators detected.')


def _color(lvl):
    return {'safe': 'success', 'suspicious': 'warning',
            'malicious': 'danger'}.get(lvl, 'warning')


def _icon(lvl):
    return {'safe': 'fas fa-shield-alt',
            'suspicious': 'fas fa-exclamation-triangle',
            'malicious': 'fas fa-skull-crossbones'}.get(lvl, 'fas fa-question-circle')


def _recommendation(lvl, pred, facs):
    if lvl == 'safe':
        return ('This URL appears safe. Always verify you are on the correct '
                'site before entering sensitive information.')
    if lvl == 'suspicious':
        extra = f' Concerns: {", ".join(facs[:3])}.' if facs else ''
        return f'Exercise caution.{extra} Verify the destination before providing data.'
    recs = {
        'Phishing': 'Do NOT visit — likely a phishing site designed to steal credentials.',
    }
    return recs.get(pred, 'Do NOT visit. Multiple threat indicators detected.')


# ═══════════════════════════════════════════════════════════════════
#  BUILD THREAT INDICATORS
# ═══════════════════════════════════════════════════════════════════

def _indicators(steps, features):
    out = []
    bl = steps.get('blocklist', {})
    if bl.get('is_shortener'):
        out.append({'name': 'URL Shortener', 'description': 'Hides destination — common in phishing',
                     'severity': 'medium', 'icon': 'fas fa-compress-arrows-alt'})
    if bl.get('is_blocked'):
        out.append({'name': 'Blocklisted', 'description': bl.get('message', ''),
                     'severity': 'high', 'icon': 'fas fa-ban'})

    td = steps.get('trusted', {})
    if td.get('is_trusted'):
        out.append({'name': 'Trusted Domain',
                     'description': f'{td.get("trust_reason","")} ({td.get("trust_layer","")})',
                     'severity': 'safe', 'icon': 'fas fa-check-circle'})

    di = steps.get('domain_intel', {})
    age = di.get('age_days')
    if age is not None and age < 30:
        out.append({'name': 'New Domain', 'description': f'Only {age} days old',
                     'severity': 'high', 'icon': 'fas fa-calendar-times'})
    elif age is not None and age < 90:
        out.append({'name': 'Young Domain', 'description': f'{age} days old',
                     'severity': 'medium', 'icon': 'fas fa-calendar-minus'})

    rp = steps.get('reputation', {})
    if rp.get('brand_spoofed'):
        out.append({'name': f'{rp["brand_spoofed"].title()} Impersonation',
                     'description': 'Impersonates a known brand',
                     'severity': 'high', 'icon': 'fas fa-user-slash'})
    if rp.get('suspicious_tld'):
        out.append({'name': 'Suspicious TLD', 'description': 'Commonly abused TLD',
                     'severity': 'medium', 'icon': 'fas fa-globe-americas'})
    if rp.get('keyword_count', 0) >= 2:
        out.append({'name': 'Phishing Keywords',
                     'description': f'{rp["keyword_count"]} keywords found',
                     'severity': 'medium' if rp['keyword_count'] < 4 else 'high',
                     'icon': 'fas fa-key'})
    if rp.get('https_enabled'):
        out.append({'name': 'HTTPS', 'description': 'Encrypted (not a safety guarantee)',
                     'severity': 'safe', 'icon': 'fas fa-lock'})
    else:
        out.append({'name': 'No HTTPS', 'description': 'Unencrypted connection',
                     'severity': 'medium', 'icon': 'fas fa-unlock'})

    ip = steps.get('ip_intel', {})
    if ip.get('has_ip_in_url'):
        out.append({'name': 'IP in URL', 'description': 'Raw IP — phishing technique',
                     'severity': 'high', 'icon': 'fas fa-network-wired'})
    if ip.get('is_private_ip'):
        out.append({'name': 'Private IP', 'description': ip.get('ip_warning', ''),
                     'severity': 'high', 'icon': 'fas fa-home'})

    st = steps.get('structure', {})
    if st.get('score', 0) > 40:
        out.append({'name': 'Suspicious Structure',
                     'description': f'{st["issue_count"]} anomalies',
                     'severity': 'medium', 'icon': 'fas fa-code'})

    ml = steps.get('ml', {})
    if ml.get('prediction_code', 0) == 1:
        out.append({'name': f'ML: {ml["prediction"]}',
                     'description': f'{ml["confidence"]:.0f}% confidence',
                     'severity': 'high', 'icon': 'fas fa-brain'})
    return out


def _risk_factors(steps):
    out = []
    bl = steps.get('blocklist', {})
    if bl.get('is_shortener'): out.append('URL shortener hides destination')
    if bl.get('is_blocked'):   out.append('Matches blocklisted pattern')
    if not steps.get('trusted', {}).get('is_trusted'):
        out.append('Domain not in trusted database')
    di = steps.get('domain_intel', {})
    if di.get('age_days') is not None and di['age_days'] < 90:
        out.append(f'Domain only {di["age_days"]} days old')
    if di.get('dns_resolves') is False:
        out.append('Domain does not resolve via DNS')
    for i in steps.get('structure', {}).get('issues', [])[:3]: out.append(i)
    for f in steps.get('reputation', {}).get('flags', [])[:3]: out.append(f)
    ip = steps.get('ip_intel', {})
    if ip.get('has_ip_in_url'): out.append('Raw IP in URL')
    if ip.get('is_private_ip'): out.append('Private IP range')
    ml = steps.get('ml', {})
    if ml.get('prediction_code', 0) == 1:
        out.append(f'ML classifies as {ml["prediction"]}')
    return out


# ═══════════════════════════════════════════════════════════════════
#  PIPELINE ORCHESTRATOR
# ═══════════════════════════════════════════════════════════════════

def run_url_pipeline(raw_url):
    """Execute 6-step URL threat detection pipeline."""
    start = time.time()

    s1 = step_normalize(raw_url)
    url, domain = s1['url'], s1.get('domain', '')

    features = {}
    if analyzer:
        try:
            features = analyzer.extract_advanced_features(url)
        except Exception as e:
            logger.warning(f"Feature extraction: {e}")

    # Step 2 — Blocklist & IP (merged, pre-filter)
    s2_bl = step_blocklist(domain, url, features)
    s2_ip = step_ip_intel(url, domain, features)
    s2 = {
        'status': 'blocked' if s2_bl.get('is_blocked') else (
            'warning' if s2_bl.get('is_shortener') or s2_ip.get('has_ip_in_url') else 'clear'),
        'is_blocked': s2_bl.get('is_blocked', False),
        'is_shortener': s2_bl.get('is_shortener', False),
        'has_ip_in_url': s2_ip.get('has_ip_in_url', False),
        'is_private_ip': s2_ip.get('is_private_ip', False),
        'resolved_ip': s2_ip.get('resolved_ip'),
        'block_reason': s2_bl.get('block_reason'),
        'message': s2_bl['message'] if s2_bl.get('is_blocked') or s2_bl.get('is_shortener')
                   else (s2_ip['message'] if s2_ip.get('has_ip_in_url') else 'No blocklist or IP concerns'),
        'risk_contribution': max(s2_bl.get('risk_contribution', 0), s2_ip.get('risk_contribution', 0)),
    }

    # Step 3 — Domain Analysis (merged Trusted + Domain Intel)
    s3_td = step_trusted_domain(url, domain)
    s3_di = step_domain_intel(domain)
    s3 = {
        'status': s3_td['status'] if s3_td.get('is_trusted') else s3_di['status'],
        'is_trusted': s3_td.get('is_trusted', False),
        'trust_reason': s3_td.get('trust_reason'),
        'trust_layer': s3_td.get('trust_layer'),
        'age_days': s3_di.get('age_days'),
        'creation_date': s3_di.get('creation_date'),
        'registrar': s3_di.get('registrar'),
        'dns_resolves': s3_di.get('dns_resolves'),
        'dns_ips': s3_di.get('dns_ips', []),
        'risk_level': 'safe' if s3_td.get('is_trusted') else s3_di.get('risk_level', 'unknown'),
        'message': s3_td['message'] if s3_td.get('is_trusted')
                   else f'{s3_di["message"]}' + (' · Not in trusted database' if not s3_td.get('is_trusted') else ''),
        'risk_contribution': s3_td['risk_contribution'] if s3_td.get('is_trusted')
                             else max(s3_td.get('risk_contribution', 50), s3_di.get('risk_contribution', 50)),
    }

    # Step 4 — Structure
    s4 = step_structure(url, features)

    # Step 5 — Reputation
    s5 = step_reputation(url, domain, features)

    # Step 6 — ML
    s6 = step_ml_classify(url)

    # Build steps dict for risk scoring (keep old keys for compatibility)
    all_steps = dict(
        blocklist_ip=s2, blocklist=s2_bl, trusted=s3_td,
        domain_intel=s3_di, structure=s4, reputation=s5,
        ip_intel=s2_ip, ml=s6,
    )
    scoring = step_risk_scoring(all_steps)

    ms = (time.time() - start) * 1000
    risk = scoring['score']

    if s3_td.get('is_trusted') and risk < 65: level = 'safe'
    elif risk < 65:  level = 'safe'
    elif risk < 80:  level = 'suspicious'
    else:            level = 'malicious'

    pred = s6.get('prediction', 'Safe')
    conf = s6.get('confidence', 0)
    inds = _indicators(all_steps, features)
    rfac = _risk_factors(all_steps)

    return {
        'url': url, 'normalized_url': s1.get('normalized_url', url),
        'domain': domain, 'protocol': s1.get('protocol', 'https'),
        'path': s1.get('path', '/'), 'url_length': len(url),

        'threat_level': level, 'threat_score': risk,
        'confidence_score': round(conf, 1), 'risk_level': scoring['level'],
        'is_malicious': level == 'malicious', 'ml_prediction': pred,

        'processing_time_ms': round(ms, 1),

        'title': _title(level, pred),
        'explanation': _explanation(level, risk, conf),
        'status_color': _color(level),
        'status_icon': _icon(level),
        'recommendation': _recommendation(level, pred, rfac),

        'validation_steps': {
            'normalization': s1, 'blocklist_ip': s2,
            'domain_analysis': s3, 'structure': s4,
            'reputation': s5, 'ml': s6, 'risk_scoring': scoring,
        },

        'threat_indicators': inds, 'risk_factors': rfac,
        'model_predictions': s6.get('models', []),

        'risk_details': {
            'component_scores': scoring.get('component_scores', {}),
            'contributing_factors': scoring.get('contributing_factors', []),
        },

        'url_features': {
            'has_ip': s2_ip.get('has_ip_in_url', False),
            'has_shortener': s2_bl.get('is_shortener', False),
            'suspicious_tld': s5.get('suspicious_tld', False),
            'brand_spoofing': s5.get('brand_spoofed') is not None,
            'https_enabled': s5.get('https_enabled', False),
            'phishing_keywords': s5.get('keyword_count', 0),
            'structure_score': s4.get('score', 0),
        },

        'domain_info': {
            'age_days': s3_di.get('age_days'), 'creation_date': s3_di.get('creation_date'),
            'registrar': s3_di.get('registrar'), 'dns_resolves': s3_di.get('dns_resolves'),
            'dns_ips': s3_di.get('dns_ips', []),
        },
    }


# ═══════════════════════════════════════════════════════════════════
#  DJANGO VIEWS
# ═══════════════════════════════════════════════════════════════════

def url_threat_detection_view(request):
    """GET → form, POST → 6-step pipeline."""
    if request.method != 'POST':
        return render(request, 'URLThreatDetection.html')

    raw = request.POST.get('url', '').strip()
    if not raw:
        return render(request, 'URLThreatDetection.html',
                      {'error': 'Please enter a URL to analyze.'})
    if len(raw) < 4:
        return render(request, 'URLThreatDetection.html',
                      {'error': 'URL too short. Enter a valid URL.'})
    try:
        result = run_url_pipeline(raw)
        logger.info(f"Scan: {raw} → {result['threat_level']} "
                    f"(score={result['threat_score']}, {result['processing_time_ms']:.0f}ms)")
        return render(request, 'URLThreatDetection.html', {'result': result})
    except Exception as e:
        logger.error(f"Pipeline error {raw}: {e}")
        return render(request, 'URLThreatDetection.html',
                      {'error': f'Analysis error: {e}. Try a different URL.'})


@csrf_exempt
@require_http_methods(["POST"])
def analyze_url_api(request):
    """JSON API for URL threat analysis."""
    try:
        if request.content_type == 'application/json':
            raw = json.loads(request.body).get('url', '').strip()
        else:
            raw = request.POST.get('url', '').strip()
        if not raw:
            return JsonResponse({'success': False, 'error': 'No URL provided'}, status=400)
        result = run_url_pipeline(raw)
        result['success'] = True
        return JsonResponse(result)
    except json.JSONDecodeError:
        return JsonResponse({'success': False, 'error': 'Invalid JSON'}, status=400)
    except Exception as e:
        logger.error(f"API error: {e}")
        return JsonResponse({'success': False, 'error': str(e)}, status=500)
