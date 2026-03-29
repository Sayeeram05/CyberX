"""
CyberX — Network Intrusion Detection System (NIDS)
===================================================
Views providing:
  • /networkids/             — main page (GET)
  • /networkids/start/       — start analysis (POST → JSON {session_id})
  • /networkids/status/<id>/ — polling endpoint (GET → JSON progress)
  • /networkids/results/<id>/— full results page (GET)
  • /networkids/api/analyze/ — synchronous JSON API (POST)

Analysis runs in a daemon background thread so the browser can poll
/status/<id>/ every 2 seconds for live progress updates.
"""

import os
import sys
import json
import uuid
import logging
import tempfile
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import numpy as np
from django.shortcuts import render, get_object_or_404
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
from django.utils import timezone as dj_timezone

try:
    import joblib
    JOBLIB_AVAILABLE = True
except ImportError:
    JOBLIB_AVAILABLE = False

from .models import AnalysisSession
from .flow_extractor import PacketFlowExtractor, SCAPY_AVAILABLE

logger = logging.getLogger('NetworkIDS')

# ---------------------------------------------------------------------------
# Model loader (lazy, same pattern as PhisingDetection)
# ---------------------------------------------------------------------------

_model         = None
_scaler        = None
_feature_names = None   # list[str] — ordered
_label_map     = None   # dict {int → str}
_loaded        = False
_load_lock     = threading.Lock()

BASE_APP_DIR  = Path(__file__).resolve().parent
SERVICES_DIR  = BASE_APP_DIR.parent.parent / 'Services' / 'NetworkIDS'

MODEL_PATHS = [
    BASE_APP_DIR  / 'models',
    SERVICES_DIR  / 'models',
]

LABEL_DEFAULTS = {
    0: 'Benign',
    1: 'DoS',
    2: 'DDoS',
    3: 'PortScan',
    4: 'BruteForce',
    5: 'WebAttack',
    6: 'Botnet/C2',
}

# Threat colours for the UI
THREAT_COLOURS = {
    'Benign':     'green',
    'DoS':        'red',
    'DDoS':       'red',
    'PortScan':   'orange',
    'BruteForce': 'orange',
    'WebAttack':  'yellow',
    'Botnet/C2':  'red',
    'Unknown':    'grey',
}


def _find_model_dir() -> Optional[Path]:
    for p in MODEL_PATHS:
        if (p / 'nids_model.joblib').exists():
            return p
    return None


# ---------------------------------------------------------------------------
# Network interface helpers (Windows-aware)
# ---------------------------------------------------------------------------

def _get_interfaces() -> list:
    """
    Returns a list of dicts: [{name, guid}]
    On Windows, reads the registry to resolve GUID strings to friendly
    names (e.g. 'Wi-Fi', 'Ethernet').  Falls back to raw GUIDs on error.
    Uses psutil as a fallback when netifaces is not installed.
    """
    raw = []
    try:
        import netifaces
        raw = netifaces.interfaces()
    except ImportError:
        # psutil fallback — available as a project dependency
        try:
            import psutil
            raw = list(psutil.net_if_addrs().keys())
        except Exception:
            return []

    if sys.platform != 'win32':
        return [{'name': iface, 'guid': iface} for iface in raw]

    # Windows: map GUIDs → friendly names via registry
    result = []
    try:
        import winreg
        NET_KEY = (
            r'SYSTEM\CurrentControlSet\Control\Network'
            r'\{4D36E972-E325-11CE-BFC1-08002BE10318}'
        )
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, NET_KEY) as base:
            for guid in raw:
                friendly = guid   # default
                try:
                    with winreg.OpenKey(base, guid + r'\Connection') as conn:
                        friendly, _ = winreg.QueryValueEx(conn, 'Name')
                except OSError:
                    pass
                result.append({'name': friendly, 'guid': guid})
    except Exception:
        # Registry fallback — show raw GUIDs
        result = [{'name': g, 'guid': g} for g in raw]

    return result


def _pcap_available() -> bool:
    """
    Returns True when Npcap/WinPcap (Windows) or libpcap (Linux/macOS)
    is installed so scapy can perform Layer-2 promiscuous capture.
    On Windows we probe for wpcap.dll; elsewhere we check scapy's iface list.
    """
    if not SCAPY_AVAILABLE:
        return False
    if sys.platform == 'win32':
        try:
            import ctypes
            ctypes.windll.LoadLibrary('wpcap')   # Npcap/WinPcap ships this DLL
            return True
        except OSError:
            return False
    else:
        try:
            from scapy.interfaces import conf as _sc
            return len(_sc.ifaces) > 0
        except Exception:
            return False


# Keep the old name as an alias so existing call-sites still work
_npcap_available = _pcap_available


def _resolve_scapy_iface(guid: str) -> str:
    """
    Convert a Windows GUID string such as {9ACDE3CF-DCFD-4DF6-993F-9135B1BD3E90}
    to the Npcap device path that scapy expects:  \\Device\\NPF_{...}
    On non-Windows systems the value is returned unchanged.
    """
    if sys.platform != 'win32':
        return guid
    if guid.upper().startswith(r'\DEVICE\NPF_'):
        return guid                         # already in the right format
    g = guid.strip('{}')
    return fr'\Device\NPF_{{{g}}}'


def load_nids_model() -> bool:
    """Thread-safe lazy loader. Returns True on success."""
    global _model, _scaler, _feature_names, _label_map, _loaded

    with _load_lock:
        if _loaded:
            return True

        if not JOBLIB_AVAILABLE:
            logger.error("joblib not installed — cannot load NIDS model")
            return False

        model_dir = _find_model_dir()
        if model_dir is None:
            logger.warning(
                "NIDS model files not found. Train the model first using "
                "Services/NetworkIDS/model.ipynb, then copy the .joblib files "
                "to App/NetworkIDS/models/."
            )
            return False

        try:
            _model  = joblib.load(model_dir / 'nids_model.joblib')
            _scaler = joblib.load(model_dir / 'nids_scaler.joblib')

            feat_path = model_dir / 'nids_feature_names.json'
            if feat_path.exists():
                with open(feat_path) as f:
                    _feature_names = json.load(f)
            else:
                logger.warning("nids_feature_names.json not found — using default order")
                _feature_names = None   # will be handled at inference time

            lbl_path = model_dir / 'nids_label_encoder.json'
            if lbl_path.exists():
                with open(lbl_path) as f:
                    raw = json.load(f)
                    # Keys may be stored as strings in JSON
                    _label_map = {int(k): v for k, v in raw.items()}
            else:
                _label_map = LABEL_DEFAULTS

            _loaded = True
            logger.info("NIDS model loaded from %s", model_dir)
            return True

        except Exception as exc:
            logger.error("Failed to load NIDS model: %s", exc)
            return False


# Eagerly load the model at Django startup so the index page reflects the
# correct state immediately — the lock inside load_nids_model() prevents
# any double-loading if the worker thread also calls it later.
try:
    load_nids_model()
except Exception as _e:
    logger.warning("Startup model load skipped: %s", _e)


# ---------------------------------------------------------------------------
# Inference helper
# ---------------------------------------------------------------------------

def _run_inference(feature_vectors: list) -> list:
    """
    Takes a list of feature dicts (from PacketFlowExtractor.get_feature_vectors())
    and returns a list of result dicts ready for JSON serialisation.
    """
    if not feature_vectors:
        return []

    model_ready = load_nids_model()

    results = []

    if not model_ready:
        # Heuristic fallback — simple rule-based classification
        for fv in feature_vectors:
            label, confidence = _heuristic_classify(fv)
            results.append(_build_result(fv, label, confidence))
        return results

    # Build ordered feature array
    if _feature_names:
        keys = _feature_names
    else:
        # Use all non-metadata keys (those not starting with '_')
        keys = [k for k in feature_vectors[0].keys() if not k.startswith('_')]

    X = []
    for fv in feature_vectors:
        row = [float(fv.get(k, 0.0)) for k in keys]
        X.append(row)

    X_arr = np.array(X, dtype=np.float32)

    # Replace NaN/Inf (can occur from zero-duration flows)
    X_arr = np.nan_to_num(X_arr, nan=0.0, posinf=1e9, neginf=0.0)

    try:
        X_scaled = _scaler.transform(X_arr)
        preds     = _model.predict(X_scaled)
        probas    = _model.predict_proba(X_scaled)   # shape (n, n_classes)

        for i, fv in enumerate(feature_vectors):
            pred_int   = int(preds[i])
            label      = (_label_map or LABEL_DEFAULTS).get(pred_int, 'Unknown')
            confidence = float(np.max(probas[i])) * 100
            results.append(_build_result(fv, label, confidence))

    except Exception as exc:
        logger.error("Inference error: %s", exc)
        for fv in feature_vectors:
            label, confidence = _heuristic_classify(fv)
            results.append(_build_result(fv, label, confidence))

    return results


def _build_result(fv: dict, label: str, confidence: float) -> dict:
    """Serialise one flow result for DB storage / JSON response."""
    threat_level = 'HIGH' if label in ('DoS', 'DDoS', 'Botnet/C2') else \
                   'MEDIUM' if label in ('PortScan', 'BruteForce', 'WebAttack') else 'LOW'
    return {
        'src_ip':       fv.get('_src_ip',   '?'),
        'dst_ip':       fv.get('_dst_ip',   '?'),
        'src_port':     fv.get('_src_port', 0),
        'dst_port':     fv.get('_dst_port', 0),
        'protocol':     _proto_name(fv.get('_protocol', 0)),
        'label':        label,
        'confidence':   round(confidence, 1),
        'threat_level': threat_level,
        'colour':       THREAT_COLOURS.get(label, 'grey'),
    }


def _proto_name(proto_int) -> str:
    _map = {1: 'ICMP', 6: 'TCP', 17: 'UDP', 58: 'ICMPv6'}
    return _map.get(int(proto_int), str(proto_int))


def _heuristic_classify(fv: dict):
    """Minimal rule-based fallback when the ML model is not available."""
    syn   = fv.get('SYN Flag Count', 0)
    bps   = fv.get('Flow Bytes/s', 0)
    pps   = fv.get('Flow Packets/s', 0)
    dur   = fv.get('Flow Duration', 1)
    proto = fv.get('_protocol', 0)

    if bps > 1_000_000 or pps > 1000:
        return 'DDoS' if bps > 5_000_000 else 'DoS', 70.0
    if syn > 20 and dur < 1_000_000:  # many SYN in short time
        return 'PortScan', 65.0
    return 'Benign', 90.0


# ---------------------------------------------------------------------------
# Session registry for live-capture threads
# ---------------------------------------------------------------------------

_active_sessions: dict = {}   # {str(session_id): {'thread', 'stop_event', 'extractor'}}
_sessions_lock = threading.Lock()


def _finalize_session(session_id: str, extractor: PacketFlowExtractor) -> None:
    """Run inference on collected flows and save results to DB."""
    try:
        session = AnalysisSession.objects.get(session_id=session_id)
        session.status = 'analyzing'
        session.save(update_fields=['status'])

        feature_vectors = extractor.get_feature_vectors()
        results         = _run_inference(feature_vectors)

        malicious = sum(1 for r in results if r['label'] != 'Benign')

        session.total_flows     = len(results)
        session.malicious_flows = malicious
        session.results_json    = json.dumps(results)
        session.status          = 'complete'
        session.completed_at    = dj_timezone.now()
        session.save()

        logger.info("Session %s complete — %d flows, %d malicious",
                    session_id, len(results), malicious)

    except Exception as exc:
        logger.error("Finalize error for session %s: %s", session_id, exc)
        try:
            session = AnalysisSession.objects.get(session_id=session_id)
            session.status        = 'error'
            session.error_message = str(exc)
            session.completed_at  = dj_timezone.now()
            session.save()
        except Exception:
            pass

    finally:
        with _sessions_lock:
            _active_sessions.pop(session_id, None)


def _pcap_worker(session_id: str, pcap_path: str) -> None:
    """Background thread: parse PCAP → extract flows → run inference → save."""
    extractor = PacketFlowExtractor()
    try:
        session = AnalysisSession.objects.get(session_id=session_id)
        session.status = 'analyzing'
        session.save(update_fields=['status'])

        extractor.extract_from_pcap(pcap_path)

    except Exception as exc:
        logger.error("PCAP worker error: %s", exc)
        try:
            session = AnalysisSession.objects.get(session_id=session_id)
            session.status        = 'error'
            session.error_message = str(exc)
            session.completed_at  = dj_timezone.now()
            session.save()
        except Exception:
            pass
        return
    finally:
        # Always clean up the temp file
        try:
            os.unlink(pcap_path)
        except Exception:
            pass

    _finalize_session(session_id, extractor)


def _capture_worker(session_id: str, interface: str, duration: int,
                    stop_event: threading.Event) -> None:
    """
    Background thread: sniff live packets → extract flows → run inference → save.

    Two modes:
      L2 (promiscuous) — requires Npcap/WinPcap on Windows; full traffic visibility.
      L3 (raw socket)  — built into the OS; sees only IP packets addressed to this
                         host.  Used automatically when Npcap is absent.
    """
    if not SCAPY_AVAILABLE:
        try:
            session = AnalysisSession.objects.get(session_id=session_id)
            session.status        = 'error'
            session.error_message = 'Scapy not installed. Run: pip install scapy'
            session.completed_at  = dj_timezone.now()
            session.save()
        except Exception:
            pass
        return

    import warnings
    from scapy.all import sniff, conf as scapy_conf   # deferred import

    l2_ok = _pcap_available()

    extractor = PacketFlowExtractor()
    try:
        session = AnalysisSession.objects.get(session_id=session_id)
        session.status = 'capturing'
        session.save(update_fields=['status'])

        sniff_kwargs = dict(
            prn=extractor.add_packet,
            timeout=duration,
            stop_filter=lambda _p: stop_event.is_set(),
            store=False,
        )

        if l2_ok:
            # Full promiscuous capture via Npcap/libpcap
            logger.info("L2 capture on %s for %ds (session %s)", interface, duration, session_id)
            sniff(iface=interface, **sniff_kwargs)
        else:
            # Npcap absent — fall back to OS raw socket (L3)
            # Captures IP-layer packets routed to this host on all interfaces.
            logger.info(
                "Npcap not available — L3 raw-socket capture for %ds (session %s)",
                duration, session_id
            )
            with warnings.catch_warnings():
                warnings.simplefilter('ignore')     # suppress the WinPcap warning
                sock = scapy_conf.L3socket()        # OS raw IP socket — no pcap needed
                try:
                    sniff(opened_socket=sock, **sniff_kwargs)
                finally:
                    try:
                        sock.close()
                    except Exception:
                        pass

    except Exception as exc:
        logger.error("Capture worker error for session %s: %s", session_id, exc)
        # Produce a helpful message for the two most common Windows failures
        msg = str(exc)
        if 'administrator' in msg.lower() or 'admin' in msg.lower():
            msg = (
                'Live capture requires elevated privileges on Windows. '
                'Fix (choose one): '
                '① Run Command Prompt / VS Code as Administrator and restart Django, '
                'OR ② Install Npcap (npcap.com, enable WinPcap-compatible mode) '
                'for full promiscuous capture without needing admin rights.'
            )
        elif 'winpcap' in msg.lower() or 'npcap' in msg.lower() or 'layer 2' in msg.lower():
            msg = (
                'Packet capture unavailable — Npcap is not installed. '
                'Download from npcap.com, enable WinPcap-compatible mode, '
                'then restart Django as Administrator.'
            )
        try:
            session = AnalysisSession.objects.get(session_id=session_id)
            session.status        = 'error'
            session.error_message = msg
            session.completed_at  = dj_timezone.now()
            session.save()
        except Exception:
            pass
        return

    _finalize_session(session_id, extractor)


# ---------------------------------------------------------------------------
# Views
# ---------------------------------------------------------------------------

def index(request):
    """GET /networkids/ — renders the main NIDS page."""
    interfaces     = _get_interfaces()        # [{name, guid}, …]
    npcap_ready    = _npcap_available()
    recent_sessions = AnalysisSession.objects.order_by('-started_at')[:5]

    return render(request, 'NetworkIDS.html', {
        'interfaces':       interfaces,
        'npcap_available':  npcap_ready,
        'scapy_available':  SCAPY_AVAILABLE,
        'model_loaded':     _loaded,
        'recent_sessions':  recent_sessions,
    })


@csrf_exempt
@require_http_methods(['POST'])
def start_analysis(request):
    """
    POST /networkids/start/
    Form data:
      source_type  = 'pcap_upload' | 'live_capture'
      pcap_file    = <file>         (pcap_upload only)
      interface    = 'eth0'         (live_capture only)
      duration     = 10             (live_capture only, seconds 5–60)
    Returns: JSON {session_id}
    """
    source_type = request.POST.get('source_type', 'pcap_upload')

    if source_type == 'pcap_upload':
        pcap_file = request.FILES.get('pcap_file')
        if not pcap_file:
            return JsonResponse({'error': 'No PCAP file uploaded.'}, status=400)

        allowed_exts = {'.pcap', '.pcapng', '.cap'}
        ext = Path(pcap_file.name).suffix.lower()
        if ext not in allowed_exts:
            return JsonResponse({'error': f'Unsupported file type: {ext}. Use .pcap/.pcapng'}, status=400)

        if pcap_file.size > 104_857_600:  # 100 MB
            return JsonResponse({'error': 'File too large (max 100 MB).'}, status=400)

        # Save to a temp file the background thread can read
        tmp = tempfile.NamedTemporaryFile(delete=False, suffix=ext)
        for chunk in pcap_file.chunks():
            tmp.write(chunk)
        tmp.close()

        session = AnalysisSession.objects.create(
            source_type    = 'pcap_upload',
            status         = 'pending',
            pcap_file_name = pcap_file.name,
        )

        t = threading.Thread(
            target=_pcap_worker,
            args=(str(session.session_id), tmp.name),
            daemon=True,
            name=f'nids-pcap-{session.session_id}',
        )
        with _sessions_lock:
            _active_sessions[str(session.session_id)] = {'thread': t}
        t.start()

        return JsonResponse({'session_id': str(session.session_id)})

    elif source_type == 'live_capture':
        if not SCAPY_AVAILABLE:
            return JsonResponse({
                'error': 'Live capture requires Scapy. Install with: pip install scapy'
            }, status=503)

        interface = request.POST.get('interface', '').strip()
        if not interface:
            return JsonResponse({'error': 'Network interface name is required.'}, status=400)

        # Only convert GUID → \Device\NPF_... when Npcap is present (L2 mode).
        # In L3 mode the interface argument is ignored by the opened_socket path.
        scapy_iface = _resolve_scapy_iface(interface) if _pcap_available() else interface

        try:
            duration = int(request.POST.get('duration', 10))
            duration = max(5, min(duration, 60))
        except ValueError:
            duration = 10

        session = AnalysisSession.objects.create(
            source_type      = 'live_capture',
            status           = 'pending',
            interface_name   = interface,
            capture_duration = duration,
        )

        stop_event = threading.Event()
        t = threading.Thread(
            target=_capture_worker,
            args=(str(session.session_id), scapy_iface, duration, stop_event),
            daemon=True,
            name=f'nids-capture-{session.session_id}',
        )
        with _sessions_lock:
            _active_sessions[str(session.session_id)] = {
                'thread':     t,
                'stop_event': stop_event,
            }
        t.start()

        return JsonResponse({'session_id': str(session.session_id)})

    return JsonResponse({'error': 'Invalid source_type.'}, status=400)


def get_status(request, session_id):
    """
    GET /networkids/status/<uuid>/
    Returns JSON progress update — polled every 2 seconds by the frontend.
    """
    try:
        session = AnalysisSession.objects.get(session_id=session_id)
    except AnalysisSession.DoesNotExist:
        return JsonResponse({'error': 'Session not found.'}, status=404)

    # Return a preview of the first 20 results for the live table
    results_preview = []
    if session.status == 'complete' and session.results_json:
        try:
            all_results = json.loads(session.results_json)
            results_preview = all_results[:20]
        except (json.JSONDecodeError, Exception):
            pass

    return JsonResponse({
        'status':          session.status,
        'source_type':     session.source_type,
        'total_flows':     session.total_flows,
        'malicious_flows': session.malicious_flows,
        'benign_flows':    session.total_flows - session.malicious_flows,
        'threat_score':    (
            round(session.malicious_flows / session.total_flows * 100, 1)
            if session.total_flows > 0 else 0
        ),
        'error_message':   session.error_message,
        'results_preview': results_preview,
        'completed_at':    (
            session.completed_at.isoformat() if session.completed_at else None
        ),
    })


@require_http_methods(['POST'])
def stop_capture(request, session_id):
    """POST /networkids/stop/<uuid>/ — request early termination of live capture."""
    with _sessions_lock:
        entry = _active_sessions.get(str(session_id))
    if entry and 'stop_event' in entry:
        entry['stop_event'].set()
        return JsonResponse({'message': 'Stop signal sent.'})
    return JsonResponse({'message': 'Session not active or already complete.'})


def get_results(request, session_id):
    """GET /networkids/results/<uuid>/ — full results page."""
    session = get_object_or_404(AnalysisSession, session_id=session_id)
    results = []
    if session.results_json:
        try:
            results = json.loads(session.results_json)
        except json.JSONDecodeError:
            pass

    # Summary stats per attack type
    label_counts: dict = {}
    for r in results:
        lbl = r.get('label', 'Unknown')
        label_counts[lbl] = label_counts.get(lbl, 0) + 1

    benign_flows = session.total_flows - session.malicious_flows
    threat_score = round(
        session.malicious_flows / session.total_flows * 100, 1
    ) if session.total_flows else 0

    return render(request, 'NetworkIDS.html', {
        'session':       session,
        'results':       results,
        'results_json':  session.results_json or '[]',
        'label_counts':  label_counts,
        'benign_flows':  benign_flows,
        'threat_score':  threat_score,
        'show_results':  True,
    })


@csrf_exempt
@require_http_methods(['POST'])
def api_analyze(request):
    """
    POST /networkids/api/analyze/
    Synchronous JSON API — accepts a PCAP file, returns full results immediately.
    Intended for programmatic use / testing.
    """
    pcap_file = request.FILES.get('pcap_file')
    if not pcap_file:
        return JsonResponse({'error': 'Provide pcap_file in multipart form.'}, status=400)

    ext = Path(pcap_file.name).suffix.lower()
    if ext not in {'.pcap', '.pcapng', '.cap'}:
        return JsonResponse({'error': f'Unsupported file type: {ext}'}, status=400)

    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=ext)
    try:
        for chunk in pcap_file.chunks():
            tmp.write(chunk)
        tmp.close()

        extractor = PacketFlowExtractor()
        extractor.extract_from_pcap(tmp.name)
        feature_vectors = extractor.get_feature_vectors()
        results         = _run_inference(feature_vectors)

        malicious = sum(1 for r in results if r['label'] != 'Benign')

        return JsonResponse({
            'status':          'complete',
            'total_flows':     len(results),
            'malicious_flows': malicious,
            'benign_flows':    len(results) - malicious,
            'threat_score':    round(malicious / len(results) * 100, 1) if results else 0,
            'results':         results,
        })

    except Exception as exc:
        logger.error("api_analyze error: %s", exc)
        return JsonResponse({'error': str(exc)}, status=500)
    finally:
        try:
            os.unlink(tmp.name)
        except Exception:
            pass
