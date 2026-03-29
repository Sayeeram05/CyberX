"""
Enhanced Email Validation System v3.0
=====================================================
9-Layer validation with:
  1. Format validation (regex)
  2. Library validation (email-validator)
  3. Blacklist check (5,100+ disposable domains)
  4. Temporary email heuristics (patterns / keywords / TLD)
  5. Domain age check (WHOIS via python-whois, cached 7 days)
  6. SPF record check
  7. DKIM check (common selectors)
  8. DMARC policy check
  9. MX / DNS deliverability check
  + Weighted risk scoring engine
  + Behavioral monitoring & anomaly detection
"""

from django.shortcuts import render
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
from django.http import JsonResponse
from django.utils import timezone
from django.core.cache import cache

import re
import os
import time
import json
import logging
import whois
import dns.resolver
from pathlib import Path
from datetime import timedelta
from collections import Counter
from email_validator import validate_email, EmailNotValidError

from .models import EmailValidationLog, DomainCache, BehavioralFlag

logger = logging.getLogger('EmailValidation')

# ---------------------------------------------------------------------------
#  LOAD DISPOSABLE DOMAIN BLOCKLIST  (5,100+ domains from GitHub repo)
# ---------------------------------------------------------------------------
_BLOCKLIST_PATH = Path(__file__).resolve().parent / 'disposable_domains.txt'


def _load_disposable_domains() -> frozenset:
    """Load the disposable-email-domains blocklist from the local text file."""
    try:
        with open(_BLOCKLIST_PATH, 'r', encoding='utf-8') as fh:
            domains = frozenset(
                line.strip().lower()
                for line in fh
                if line.strip() and not line.startswith('#')
            )
        logger.info(f"Loaded {len(domains)} disposable domains from blocklist")
        return domains
    except FileNotFoundError:
        logger.warning("disposable_domains.txt not found — using empty set")
        return frozenset()


DISPOSABLE_DOMAINS: frozenset = _load_disposable_domains()

# ---------------------------------------------------------------------------
#  STATIC HEURISTIC DATA
# ---------------------------------------------------------------------------
TEMPORARY_EMAIL_PATTERNS = [
    r'^temp\d*mail\d*\.(com|org|net|email)$',
    r'^\d+m(in|inute)mail\.(com|org|net)$',
    r'^disposable.*\.(ml|tk|ga|cf|gq)$',
    r'^temp.*\.(ml|tk|ga|cf|gq)$',
    r'^fake.*mail.*\.(com|org|net|ml|tk)$',
    r'^trash.*mail.*\.(com|org|net|ws)$',
    r'^guerrilla.*mail.*\.(com|org|net|de|biz|info)$',
    r'.*tempmail.*\.(com|org|net|email|dev|xyz)$',
    r'.*throwaway.*\.(com|org|net|email)$',
    r'.*burner.*\.(com|org|net|email|io|kiwi)$',
    r'.*disposable.*\.(com|org|net|email|ml)$',
    r'.*ephemeral.*\.(com|org|net|email)$',
    r'.*instant.*mail.*\.(com|org|net|fr)$',
    r'.*quick.*mail.*\.(com|org|net|email)$',
]

SUSPICIOUS_TLDS = {'.tk', '.ml', '.ga', '.cf', '.gq', '.pw', '.cc', '.top', '.click'}

TEMP_EMAIL_KEYWORDS = [
    'temp', 'temporary', 'disposable', 'throwaway', 'burner', 'fake',
    'trash', 'spam', 'guerrilla', 'guerilla', 'anonymous', 'anon',
    'ephemeral', 'instant', 'quick', 'fast', 'minute', 'hour', 'daily',
]

DKIM_SELECTORS = [
    'default', 'google', 'selector1', 'selector2',
    'k1', 'dkim', 'mail', 's1', 's2', 'mx', 'email',
]

# ===================================================================
#  LAYER 1 — Format Validation (regex)
# ===================================================================

def check_format(email: str) -> dict:
    """RFC 5322 regex format check with extra sanity rules."""
    pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
    issues = []
    is_valid = bool(re.match(pattern, email))

    if '..' in email:
        is_valid = False
        issues.append("Contains consecutive dots")
    if email.startswith(('.', '@')) or email.endswith(('.', '@')):
        is_valid = False
        issues.append("Invalid start / end character")
    if '@' in email and len(email.split('@')[0]) < 1:
        is_valid = False
        issues.append("Local part too short")

    return {
        'status': 'valid' if is_valid else 'invalid',
        'is_valid': is_valid,
        'message': 'Email format is valid' if is_valid else 'Invalid email format',
        'technical_info': (
            'Passes enhanced RFC 5322 pattern validation' if is_valid
            else f"Format issues: {', '.join(issues) if issues else 'Basic format validation failed'}"
        ),
        'issues': issues,
    }


# ===================================================================
#  LAYER 2 — Library Validation (email-validator)
# ===================================================================

def check_library(email: str) -> dict:
    """Comprehensive validation using the email-validator library."""
    try:
        valid = validate_email(email, check_deliverability=False, test_environment=False)
        return {
            'status': 'valid',
            'is_valid': True,
            'message': 'Email is syntactically valid',
            'normalized_email': valid.email,
            'local_part': valid.local_part,
            'domain': valid.domain,
            'technical_info': 'Passes comprehensive RFC compliance validation',
        }
    except EmailNotValidError as exc:
        return {
            'status': 'invalid',
            'is_valid': False,
            'message': f'Validation failed: {exc}',
            'normalized_email': None,
            'local_part': None,
            'domain': email.split('@')[1].lower() if '@' in email else None,
            'technical_info': str(exc),
        }


# ===================================================================
#  LAYER 3 — Blacklist Check  (5,100+ disposable domains)
# ===================================================================

def check_blacklist(domain: str) -> dict:
    """Check domain (and parent domain) against the disposable blocklist."""
    domain = domain.lower().strip()

    # Direct match
    if domain in DISPOSABLE_DOMAINS:
        return {
            'is_blacklisted': True,
            'source': 'disposable_blocklist',
            'confidence': 99,
            'message': f'"{domain}" is a confirmed disposable email provider',
            'risk_level': 'critical',
        }

    # Parent-domain match (sub.netoiu.com -> netoiu.com)
    parts = domain.split('.')
    if len(parts) > 2:
        parent = '.'.join(parts[-2:])
        if parent in DISPOSABLE_DOMAINS:
            return {
                'is_blacklisted': True,
                'source': 'disposable_blocklist_parent',
                'confidence': 97,
                'message': f'Parent domain "{parent}" is a confirmed disposable provider',
                'risk_level': 'critical',
            }

    return {
        'is_blacklisted': False,
        'source': 'not_listed',
        'confidence': 0,
        'message': f'"{domain}" is not in the disposable domain blocklist',
        'risk_level': 'safe',
    }


# ===================================================================
#  LAYER 4 — Temporary Email Heuristics  (patterns / keywords / TLD)
# ===================================================================

def check_temp_heuristics(domain: str) -> dict:
    """Pattern matching, keyword analysis, suspicious-TLD, and heuristic scoring."""
    domain = domain.lower().strip()

    # Pattern matching
    for pat in TEMPORARY_EMAIL_PATTERNS:
        if re.match(pat, domain):
            return {
                'is_temporary': True,
                'detection_method': 'pattern_matching',
                'confidence': 85,
                'message': f'"{domain}" follows temporary email naming patterns',
                'risk_level': 'high',
            }

    # Keyword analysis
    domain_parts = re.split(r'[.\-]', domain)
    found_keywords = [kw for kw in TEMP_EMAIL_KEYWORDS if any(kw in p for p in domain_parts)]
    if found_keywords:
        return {
            'is_temporary': True,
            'detection_method': 'keyword_analysis',
            'confidence': 75,
            'message': f'Contains temp-email keywords: {", ".join(found_keywords)}',
            'risk_level': 'medium',
        }

    # Suspicious TLD
    tld = '.' + domain.split('.')[-1] if '.' in domain else ''
    if tld in SUSPICIOUS_TLDS:
        return {
            'is_temporary': True,
            'detection_method': 'suspicious_tld',
            'confidence': 60,
            'message': f'Uses suspicious TLD "{tld}"',
            'risk_level': 'medium',
        }

    # Heuristic scoring
    score = 0
    warnings = []
    if len(domain.split('.')[0]) <= 3:
        score += 20
        warnings.append("very short domain name")
    if sum(c.isdigit() for c in domain) > 3:
        score += 15
        warnings.append("many digits in domain")
    if tld in {'.ml', '.tk', '.ga', '.cf', '.gq'}:
        score += 25
        warnings.append("free domain extension")

    if score >= 40:
        return {
            'is_temporary': True,
            'detection_method': 'heuristic_analysis',
            'confidence': min(60 + score, 85),
            'message': f'Heuristic flags: {", ".join(warnings)}',
            'risk_level': 'medium',
        }

    return {
        'is_temporary': False,
        'detection_method': 'comprehensive_analysis',
        'confidence': 0,
        'message': f'"{domain}" shows no temporary email characteristics',
        'risk_level': 'safe',
    }


# ===================================================================
#  LAYER 5 — Domain Age Check  (WHOIS, cached 7 days)
# ===================================================================

def check_domain_age(domain: str) -> dict:
    """WHOIS domain-age lookup with DB caching (7-day TTL)."""
    domain = domain.lower().strip()

    # Try cache first
    try:
        cached = DomainCache.objects.filter(domain=domain).first()
        if cached and not cached.is_expired and cached.creation_date is not None:
            age = cached.age_days
            return _age_result(age, cached.creation_date, cached.registrar, source='cache')
    except Exception:
        pass

    # Live WHOIS lookup
    try:
        w = whois.whois(domain)
        creation = w.creation_date
        if isinstance(creation, list):
            creation = creation[0]
        registrar = w.registrar or 'Unknown'

        if creation:
            from django.utils.timezone import make_aware, is_naive
            import datetime
            if isinstance(creation, datetime.datetime):
                if is_naive(creation):
                    creation = make_aware(creation)
            DomainCache.objects.update_or_create(
                domain=domain,
                defaults={
                    'creation_date': creation,
                    'registrar': registrar,
                    'whois_country': getattr(w, 'country', None),
                },
            )
            age = (timezone.now() - creation).days
            return _age_result(age, creation, registrar, source='whois')

        return {
            'age_days': None, 'creation_date': None, 'registrar': registrar,
            'risk_level': 'unknown', 'score': 50,
            'message': 'WHOIS data available but creation date missing',
            'source': 'whois',
        }

    except Exception as exc:
        logger.debug(f"WHOIS lookup failed for {domain}: {exc}")
        return {
            'age_days': None, 'creation_date': None, 'registrar': None,
            'risk_level': 'unknown', 'score': 50,
            'message': f'WHOIS lookup unavailable',
            'source': 'error',
        }


def _age_result(age_days, creation_date, registrar, source='whois'):
    if age_days is not None and age_days < 30:
        risk, score = 'high', 90
        msg = f'Domain is only {age_days} days old — very new'
    elif age_days is not None and age_days < 90:
        risk, score = 'medium', 60
        msg = f'Domain is {age_days} days old — relatively new'
    elif age_days is not None and age_days < 365:
        risk, score = 'low', 25
        msg = f'Domain is {age_days} days old — less than a year'
    elif age_days is not None:
        risk, score = 'safe', 5
        years = age_days // 365
        msg = f'Domain is ~{years} year(s) old — established'
    else:
        risk, score = 'unknown', 50
        msg = 'Could not determine domain age'

    return {
        'age_days': age_days,
        'creation_date': str(creation_date) if creation_date else None,
        'registrar': registrar,
        'risk_level': risk,
        'score': score,
        'message': msg,
        'source': source,
    }


# ===================================================================
#  LAYER 6 / 7 / 8 — SPF, DKIM, DMARC Checks
# ===================================================================

def check_spf(domain: str) -> dict:
    """Query TXT records for SPF (v=spf1)."""
    try:
        answers = dns.resolver.resolve(domain, 'TXT')
        for rdata in answers:
            txt = rdata.to_text().strip('"')
            if txt.lower().startswith('v=spf1'):
                strictness = 'unknown'
                if '-all' in txt:
                    strictness = 'strict'
                elif '~all' in txt:
                    strictness = 'softfail'
                elif '?all' in txt:
                    strictness = 'neutral'
                elif '+all' in txt:
                    strictness = 'permissive'

                return {
                    'found': True,
                    'record': txt,
                    'strictness': strictness,
                    'score': 0 if strictness == 'strict' else 30 if strictness == 'softfail' else 60,
                    'message': f'SPF record found ({strictness})',
                }
    except Exception:
        pass

    return {
        'found': False, 'record': None, 'strictness': None, 'score': 80,
        'message': 'No SPF record found — domain does not publish sender policy',
    }


def check_dkim(domain: str) -> dict:
    """Try common DKIM selectors to see if a public key is published."""
    for selector in DKIM_SELECTORS:
        try:
            qname = f'{selector}._domainkey.{domain}'
            answers = dns.resolver.resolve(qname, 'TXT')
            for rdata in answers:
                txt = rdata.to_text().strip('"')
                if 'p=' in txt:
                    return {
                        'found': True,
                        'selector': selector,
                        'score': 0,
                        'message': f'DKIM public key found (selector: {selector})',
                    }
        except Exception:
            continue

    return {
        'found': False, 'selector': None, 'score': 70,
        'message': 'No DKIM record found for common selectors',
    }


def check_dmarc(domain: str) -> dict:
    """Query _dmarc.<domain> TXT for DMARC policy."""
    try:
        answers = dns.resolver.resolve(f'_dmarc.{domain}', 'TXT')
        for rdata in answers:
            txt = rdata.to_text().strip('"')
            if 'v=dmarc1' in txt.lower():
                policy = 'none'
                m = re.search(r'p\s*=\s*(reject|quarantine|none)', txt, re.I)
                if m:
                    policy = m.group(1).lower()

                if policy == 'reject':
                    score = 0
                elif policy == 'quarantine':
                    score = 30
                else:
                    score = 60

                return {
                    'found': True,
                    'record': txt,
                    'policy': policy,
                    'score': score,
                    'message': f'DMARC policy found: p={policy}',
                }
    except Exception:
        pass

    return {
        'found': False, 'record': None, 'policy': None, 'score': 80,
        'message': 'No DMARC record found',
    }


# ===================================================================
#  LAYER 9 — MX / DNS Deliverability Check
# ===================================================================

def check_mx(domain: str) -> dict:
    """MX record lookup with A-record fallback."""
    start = time.time()
    try:
        mx_answers = dns.resolver.resolve(domain, 'MX')
        elapsed = round((time.time() - start) * 1000, 2)

        records = sorted(
            [{'priority': r.preference, 'exchange': str(r.exchange).rstrip('.')} for r in mx_answers],
            key=lambda r: r['priority'],
        )
        return {
            'status': 'valid',
            'has_mx': True,
            'mx_count': len(records),
            'mx_records': records,
            'primary_mx': records[0]['exchange'] if records else None,
            'response_time_ms': elapsed,
            'message': f'Domain has {len(records)} MX record(s) and can receive email',
        }
    except dns.resolver.NoAnswer:
        try:
            a = dns.resolver.resolve(domain, 'A')
            elapsed = round((time.time() - start) * 1000, 2)
            return {
                'status': 'fallback',
                'has_mx': False, 'has_a_record': True,
                'mx_count': 0, 'mx_records': [],
                'fallback_ips': [str(r) for r in a],
                'response_time_ms': elapsed,
                'message': 'No MX records; domain exists via A record (RFC fallback)',
            }
        except Exception:
            pass
    except dns.resolver.NXDOMAIN:
        elapsed = round((time.time() - start) * 1000, 2)
        return {
            'status': 'domain_not_found',
            'has_mx': False, 'mx_count': 0, 'mx_records': [],
            'response_time_ms': elapsed,
            'message': 'Domain does not exist (NXDOMAIN)',
        }
    except dns.resolver.Timeout:
        elapsed = round((time.time() - start) * 1000, 2)
        return {
            'status': 'timeout',
            'has_mx': None, 'mx_count': 0, 'mx_records': [],
            'response_time_ms': elapsed,
            'message': 'DNS lookup timed out',
        }
    except Exception as exc:
        elapsed = round((time.time() - start) * 1000, 2)
        return {
            'status': 'dns_error',
            'has_mx': None, 'mx_count': 0, 'mx_records': [],
            'response_time_ms': elapsed,
            'message': f'DNS error: {exc}',
        }

    elapsed = round((time.time() - start) * 1000, 2)
    return {
        'status': 'no_records',
        'has_mx': False, 'mx_count': 0, 'mx_records': [],
        'response_time_ms': elapsed,
        'message': 'Domain has no MX or A records — cannot receive email',
    }


# ===================================================================
#  RISK SCORING ENGINE  (weighted composite 0-100)
# ===================================================================

def calculate_risk_score(checks: dict) -> dict:
    """
    Weighted risk score from all validation layers.
    0 = perfectly safe / 100 = maximum risk

    Weights:
        Blacklist / temp      30%
        Domain age            15%
        SPF                   15%
        DKIM                  10%
        DMARC                 10%
        MX deliverability     10%
        Heuristics            10%
    """
    weights = {
        'blacklist':   0.30,
        'domain_age':  0.15,
        'spf':         0.15,
        'dkim':        0.10,
        'dmarc':       0.10,
        'mx':          0.10,
        'heuristics':  0.10,
    }

    scores = {}

    # Blacklist
    bl = checks.get('blacklist', {})
    scores['blacklist'] = 100 if bl.get('is_blacklisted') else 0

    # Domain age
    age = checks.get('domain_age', {})
    scores['domain_age'] = age.get('score', 50)

    # SPF / DKIM / DMARC
    scores['spf'] = checks.get('spf', {}).get('score', 80)
    scores['dkim'] = checks.get('dkim', {}).get('score', 70)
    scores['dmarc'] = checks.get('dmarc', {}).get('score', 80)

    # MX
    mx = checks.get('dns', {})
    if mx.get('has_mx') is True:
        scores['mx'] = 0
    elif mx.get('has_mx') is False:
        scores['mx'] = 100
    else:
        scores['mx'] = 50

    # Heuristics
    heur = checks.get('heuristics', {})
    scores['heuristics'] = heur.get('confidence', 0) if heur.get('is_temporary') else 0

    # Weighted sum
    risk = sum(scores[k] * weights[k] for k in weights)
    risk = round(min(max(risk, 0), 100), 1)

    # Classify
    if risk >= 80:
        level = 'critical'
    elif risk >= 60:
        level = 'high'
    elif risk >= 40:
        level = 'medium'
    elif risk >= 20:
        level = 'low'
    else:
        level = 'safe'

    # Build contributing factors
    factors = []
    for k, v in sorted(scores.items(), key=lambda x: -x[1]):
        if v > 20:
            factors.append({'factor': k, 'score': v, 'weight': f"{weights[k]*100:.0f}%"})

    return {
        'risk_score': risk,
        'risk_level': level,
        'component_scores': scores,
        'contributing_factors': factors,
    }


# ===================================================================
#  BEHAVIORAL MONITORING
# ===================================================================

def _get_client_ip(request):
    xff = request.META.get('HTTP_X_FORWARDED_FOR')
    return xff.split(',')[0].strip() if xff else request.META.get('REMOTE_ADDR')


def track_and_analyze(request, domain, result_data):
    """
    1. Log the validation to the DB.
    2. Rate-limit check (cache-based, per IP, 10-min window).
    3. Pattern detection (bulk temp-email checking, domain abuse).
    """
    ip = _get_client_ip(request)
    behavioral = {
        'ip_address': ip,
        'queries_this_session': 0,
        'is_rate_limited': False,
        'behavioral_flags': [],
        'domain_query_count': 0,
    }

    # --- 1. Log to DB ---
    try:
        EmailValidationLog.objects.create(
            email=result_data.get('email', ''),
            domain=domain or '',
            ip_address=ip,
            is_valid=result_data.get('is_valid', False),
            is_temporary=result_data.get('is_temporary', False),
            is_deliverable=result_data.get('is_deliverable', False),
            risk_score=result_data.get('risk_score', 0),
            risk_level=result_data.get('risk_level', 'unknown'),
            spf_status=result_data.get('spf_status', ''),
            dkim_status=result_data.get('dkim_status', ''),
            dmarc_status=result_data.get('dmarc_status', ''),
            domain_age_days=result_data.get('domain_age_days'),
            processing_time_ms=result_data.get('processing_time_ms', 0),
        )
    except Exception as exc:
        logger.warning(f"Failed to log validation: {exc}")

    # --- 2. Rate-limit check (cache) ---
    try:
        cache_key = f'ev_rate_{ip}'
        count = cache.get(cache_key, 0) + 1
        cache.set(cache_key, count, 600)  # 10-min window
        behavioral['queries_this_session'] = count

        if count > 20:
            behavioral['is_rate_limited'] = True
            behavioral['behavioral_flags'].append('Rate limit exceeded (>20 queries in 10 min)')
            BehavioralFlag.objects.create(
                ip_address=ip, flag_type='rate_limit', severity='high',
                details=f'{count} queries in 10-min window',
            )
    except Exception:
        pass

    # --- 3. Pattern detection ---
    try:
        one_hour_ago = timezone.now() - timedelta(hours=1)

        # Bulk temp-email checking from same IP
        recent_temp = EmailValidationLog.objects.filter(
            ip_address=ip, is_temporary=True, timestamp__gte=one_hour_ago,
        ).count()
        if recent_temp >= 5:
            behavioral['behavioral_flags'].append(
                f'{recent_temp} temporary emails checked in 1 hour'
            )
            BehavioralFlag.objects.get_or_create(
                ip_address=ip, flag_type='bulk_temp_check',
                timestamp__gte=one_hour_ago,
                defaults={
                    'severity': 'medium',
                    'details': f'{recent_temp} temp-email lookups in 1h',
                },
            )

        # Domain abuse: same domain queried > 50 times overall
        if domain:
            domain_total = EmailValidationLog.objects.filter(domain=domain).count()
            behavioral['domain_query_count'] = domain_total
            if domain_total > 50:
                behavioral['behavioral_flags'].append(
                    f'Domain "{domain}" queried {domain_total} times total'
                )
    except Exception:
        pass

    return behavioral


# ===================================================================
#  MAIN ORCHESTRATOR
# ===================================================================

def validate_email_comprehensive(email: str) -> dict:
    """Run all 9 layers and compute the composite risk score."""
    start_time = time.time()
    results = {
        'email': email,
        'is_valid': False,
        'is_deliverable': False,
        'is_temporary': False,
        'risk_score': 0,
        'risk_level': 'unknown',
        'confidence_score': 0,
        'warnings': [],
        'errors': [],
        'details': {},
    }

    # ---- Layer 1: Format ----
    fmt = check_format(email)
    results['details']['format'] = fmt
    if not fmt['is_valid']:
        results['errors'].append("Invalid email format")
        results['processing_time_ms'] = round((time.time() - start_time) * 1000, 2)
        risk = calculate_risk_score(results['details'])
        results.update(risk_score=risk['risk_score'], risk_level=risk['risk_level'])
        results['risk_details'] = risk
        return results

    # ---- Layer 2: Library ----
    lib = check_library(email)
    results['details']['library'] = lib
    if not lib['is_valid']:
        results['errors'].append(lib['message'])
        results['processing_time_ms'] = round((time.time() - start_time) * 1000, 2)
        risk = calculate_risk_score(results['details'])
        results.update(risk_score=risk['risk_score'], risk_level=risk['risk_level'])
        results['risk_details'] = risk
        return results

    domain = lib.get('domain') or email.split('@')[1].lower()
    results['domain'] = domain
    results['normalized_email'] = lib.get('normalized_email')

    # ---- Layer 3: Blacklist ----
    bl = check_blacklist(domain)
    results['details']['blacklist'] = bl
    if bl['is_blacklisted']:
        results['is_temporary'] = True
        results['warnings'].append(bl['message'])

    # ---- Layer 4: Heuristics ----
    heur = check_temp_heuristics(domain)
    results['details']['heuristics'] = heur
    if heur['is_temporary'] and not bl['is_blacklisted']:
        results['is_temporary'] = True
        results['warnings'].append(heur['message'])

    # ---- Layer 5: Domain Age ----
    age = check_domain_age(domain)
    results['details']['domain_age'] = age

    # ---- Layer 6: SPF ----
    spf = check_spf(domain)
    results['details']['spf'] = spf

    # ---- Layer 7: DKIM ----
    dkim_result = check_dkim(domain)
    results['details']['dkim'] = dkim_result

    # ---- Layer 8: DMARC ----
    dmarc = check_dmarc(domain)
    results['details']['dmarc'] = dmarc

    # Cache auth results in DomainCache
    try:
        DomainCache.objects.update_or_create(
            domain=domain,
            defaults={
                'spf_found': spf['found'],
                'spf_record': spf.get('record'),
                'spf_strictness': spf.get('strictness'),
                'dkim_found': dkim_result['found'],
                'dkim_selector': dkim_result.get('selector'),
                'dmarc_found': dmarc['found'],
                'dmarc_record': dmarc.get('record'),
                'dmarc_policy': dmarc.get('policy'),
            },
        )
    except Exception:
        pass

    # ---- Layer 9: MX ----
    mx = check_mx(domain)
    results['details']['dns'] = mx
    results['is_deliverable'] = mx.get('has_mx') is True or mx.get('has_a_record', False)

    if not results['is_deliverable'] and mx.get('has_mx') is False:
        results['errors'].append(mx.get('message', 'Domain cannot receive email'))

    # ---- Final decisions ----
    results['is_valid'] = True  # passed format + library

    # ---- Risk scoring ----
    risk = calculate_risk_score(results['details'])
    results['risk_score'] = risk['risk_score']
    results['risk_level'] = risk['risk_level']
    results['risk_details'] = risk

    # Derive a user-friendly confidence score (inverse of risk)
    results['confidence_score'] = round(100 - risk['risk_score'], 1)

    results['processing_time_ms'] = round((time.time() - start_time) * 1000, 2)
    return results


# ===================================================================
#  UI HELPER FUNCTIONS
# ===================================================================

def get_validation_title(r):
    if not r['is_valid']:
        return "Invalid Email Address"
    if r.get('risk_level') == 'critical':
        return "Critical Risk Email"
    if r['is_temporary']:
        return "Temporary / Disposable Email Detected"
    if r.get('risk_level') == 'high':
        return "High Risk Email Address"
    if not r['is_deliverable']:
        return "Email May Not Be Deliverable"
    if r['warnings']:
        return "Valid Email with Warnings"
    return "Valid Email Address"


def get_validation_message(r):
    if not r['is_valid']:
        return f"This email address is not valid. {' '.join(r['errors'])}"
    if r['is_temporary']:
        return "This is a temporary/disposable email. It should not be trusted for important communications."
    if r.get('risk_level') in ('critical', 'high'):
        return f"This email has a risk score of {r['risk_score']}/100. Proceed with extreme caution."
    if not r['is_deliverable']:
        return f"This email may not be deliverable. {' '.join(r['errors'])}"
    if r['warnings']:
        return f"Valid email with concerns: {' '.join(r['warnings'])}"
    return f"This email is valid and appears deliverable with {r['confidence_score']}% confidence."


def get_status_color(r):
    if not r['is_valid']:
        return 'danger'
    level = r.get('risk_level', 'safe')
    if level in ('critical', 'high') or r['is_temporary']:
        return 'warning'
    if level == 'medium' or r['warnings']:
        return 'info'
    return 'success'


def get_status_icon(r):
    if not r['is_valid']:
        return 'fas fa-times-circle'
    if r['is_temporary']:
        return 'fas fa-clock'
    level = r.get('risk_level', 'safe')
    if level in ('critical', 'high'):
        return 'fas fa-exclamation-triangle'
    if level == 'medium':
        return 'fas fa-info-circle'
    return 'fas fa-check-circle'


def get_recommendation(r):
    if not r['is_valid']:
        return "Please correct the email address format and try again."
    if r['is_temporary']:
        return "This is a known disposable email provider. Use a permanent email for important accounts."
    level = r.get('risk_level', 'safe')
    if level == 'critical':
        return "CRITICAL: This email shows multiple severe risk indicators. Do not trust it."
    if level == 'high':
        return "HIGH RISK: This email has concerning characteristics. Verify the sender through other means."
    if level == 'medium':
        return "MODERATE RISK: Some concerns detected. Exercise caution with sensitive information."
    if not r['is_deliverable']:
        return "The domain cannot receive emails. Verify the address or contact through alternative means."
    if r['confidence_score'] < 70:
        return "This email may have deliverability issues. Double-check the address."
    return "This email address appears safe and trustworthy for communication."


# ===================================================================
#  DJANGO VIEWS
# ===================================================================

@csrf_exempt
@require_http_methods(["GET", "POST"])
def email_validation_view(request):
    """Main page view — handles form GET and POST."""
    result = None

    if request.method == 'POST':
        try:
            if request.content_type == 'application/json':
                data = json.loads(request.body)
                email = data.get('email', '').strip()
            else:
                email = request.POST.get('email', '').strip()

            if email:
                validation = validate_email_comprehensive(email)

                # Build template context
                result = {
                    # Core
                    'email': validation['email'],
                    'normalized_email': validation.get('normalized_email'),
                    'domain': validation.get('domain'),
                    'is_valid': validation['is_valid'],
                    'is_deliverable': validation['is_deliverable'],
                    'is_temporary': validation['is_temporary'],
                    'confidence_score': validation['confidence_score'],
                    'risk_score': validation['risk_score'],
                    'risk_level': validation['risk_level'],
                    'warnings': validation['warnings'],
                    'errors': validation['errors'],
                    'processing_time_ms': validation['processing_time_ms'],

                    # UI
                    'title': get_validation_title(validation),
                    'explanation': get_validation_message(validation),
                    'status_color': get_status_color(validation),
                    'status_icon': get_status_icon(validation),
                    'recommendation': get_recommendation(validation),

                    # Validation step details
                    'validation_steps': validation['details'],

                    # Domain info (MX records)
                    'domain_info': validation['details'].get('dns', {}),

                    # Auth checks
                    'spf_check': validation['details'].get('spf', {}),
                    'dkim_check': validation['details'].get('dkim', {}),
                    'dmarc_check': validation['details'].get('dmarc', {}),

                    # Domain age
                    'domain_age_info': validation['details'].get('domain_age', {}),

                    # Blacklist
                    'blacklist_check': validation['details'].get('blacklist', {}),

                    # Risk details
                    'risk_details': validation.get('risk_details', {}),

                    # Risk factors list for template
                    'risk_factors': [],

                    # DNS warning
                    'dns_warning': None,
                }

                # Populate risk factors
                if validation['is_temporary']:
                    result['risk_factors'].append("Uses temporary / disposable email service")
                if not validation['is_deliverable']:
                    result['risk_factors'].append("Domain cannot receive emails")

                age_info = validation['details'].get('domain_age', {})
                if age_info.get('risk_level') in ('high', 'medium'):
                    result['risk_factors'].append(age_info.get('message', 'Domain is very new'))

                spf_info = validation['details'].get('spf', {})
                if not spf_info.get('found'):
                    result['risk_factors'].append("No SPF record published")

                dkim_info = validation['details'].get('dkim', {})
                if not dkim_info.get('found'):
                    result['risk_factors'].append("No DKIM record found")

                dmarc_info = validation['details'].get('dmarc', {})
                if not dmarc_info.get('found'):
                    result['risk_factors'].append("No DMARC policy configured")

                if validation['warnings']:
                    result['risk_factors'].extend(validation['warnings'])

                dns_info = validation['details'].get('dns', {})
                if dns_info.get('status') in ('domain_not_found', 'timeout', 'dns_error'):
                    result['dns_warning'] = dns_info.get('message')

                # Behavioral monitoring
                behavioral = track_and_analyze(request, validation.get('domain'), {
                    'email': validation['email'],
                    'is_valid': validation['is_valid'],
                    'is_temporary': validation['is_temporary'],
                    'is_deliverable': validation['is_deliverable'],
                    'risk_score': validation['risk_score'],
                    'risk_level': validation['risk_level'],
                    'spf_status': 'found' if spf_info.get('found') else 'missing',
                    'dkim_status': 'found' if dkim_info.get('found') else 'missing',
                    'dmarc_status': dmarc_info.get('policy') or 'missing',
                    'domain_age_days': age_info.get('age_days'),
                    'processing_time_ms': validation['processing_time_ms'],
                })
                result['behavioral_info'] = behavioral

                if behavioral.get('behavioral_flags'):
                    result['risk_factors'].extend(behavioral['behavioral_flags'])

                # AJAX
                if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                    return JsonResponse({'success': True, 'result': result})

        except json.JSONDecodeError:
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return JsonResponse({'success': False, 'error': 'Invalid JSON'})
        except Exception as exc:
            logger.error(f"Validation error: {exc}", exc_info=True)
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return JsonResponse({'success': False, 'error': str(exc)})

    return render(request, 'EmailValidation.html', {'result': result})


@csrf_exempt
@require_http_methods(["POST"])
def validate_email_api(request):
    """REST API endpoint — always returns JSON."""
    try:
        if request.content_type == 'application/json':
            data = json.loads(request.body)
            email = data.get('email', '').strip()
        else:
            email = request.POST.get('email', '').strip()

        if not email:
            return JsonResponse({'success': False, 'error': 'No email provided'}, status=400)

        validation = validate_email_comprehensive(email)

        return JsonResponse({
            'success': True,
            'email': validation['email'],
            'is_valid': validation['is_valid'],
            'is_deliverable': validation['is_deliverable'],
            'is_temporary': validation['is_temporary'],
            'risk_score': validation['risk_score'],
            'risk_level': validation['risk_level'],
            'confidence_score': validation['confidence_score'],
            'processing_time_ms': validation['processing_time_ms'],
            'domain': validation.get('domain'),
            'warnings': validation['warnings'],
            'errors': validation['errors'],
            'details': {
                'blacklist': validation['details'].get('blacklist', {}),
                'domain_age': validation['details'].get('domain_age', {}),
                'spf': validation['details'].get('spf', {}),
                'dkim': validation['details'].get('dkim', {}),
                'dmarc': validation['details'].get('dmarc', {}),
                'dns': validation['details'].get('dns', {}),
            },
            'risk_details': validation.get('risk_details', {}),
        })

    except Exception as exc:
        return JsonResponse({'success': False, 'error': str(exc)}, status=500)
