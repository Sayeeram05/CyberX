"""
NetworkIDS — Packet Flow Feature Extractor
==========================================
Converts raw Scapy packets into CICFlowMeter-compatible feature vectors
(78 numerical features per bidirectional flow) for ML inference.

Usage:
    extractor = PacketFlowExtractor()
    extractor.add_packet(pkt)          # called per Scapy packet
    vectors = extractor.get_feature_vectors()  # list[dict]

    # Or from a PCAP file:
    extractor.extract_from_pcap('/path/to/capture.pcap')
    vectors = extractor.get_feature_vectors()
"""

import math
import logging
from collections import defaultdict
from typing import List, Dict, Optional, Tuple, Any

logger = logging.getLogger('NetworkIDS')

# Graceful Scapy import — Scapy may not be available in all environments.
# On Windows without Npcap the import emits a runtime warning (not ImportError),
# so we suppress all warnings during the import and catch broadly.
import warnings as _warnings
try:
    with _warnings.catch_warnings():
        _warnings.simplefilter('ignore')
        from scapy.all import rdpcap, IP, IPv6, TCP, UDP, ICMP
    SCAPY_AVAILABLE = True
except Exception:
    SCAPY_AVAILABLE = False
    logger.warning("Scapy not installed — PCAP/live capture unavailable. "
                   "Install with: pip install scapy")


# ---------------------------------------------------------------------------
# Helper statistics
# ---------------------------------------------------------------------------

def _safe_div(a: float, b: float, default: float = 0.0) -> float:
    return a / b if b != 0 else default


def _stats(values: List[float]) -> Tuple[float, float, float, float]:
    """Return (mean, std, max, min) for a list; returns 0s if empty."""
    if not values:
        return 0.0, 0.0, 0.0, 0.0
    n   = len(values)
    mu  = sum(values) / n
    std = math.sqrt(sum((x - mu) ** 2 for x in values) / n) if n > 1 else 0.0
    return mu, std, max(values), min(values)


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = defaultdict(int)
    for b in data:
        freq[b] += 1
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in freq.values() if c > 0)


# ---------------------------------------------------------------------------
# Flow record
# ---------------------------------------------------------------------------

class FlowRecord:
    """Accumulates per-packet statistics for one bidirectional 5-tuple flow."""

    __slots__ = [
        'src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol',
        'start_time', 'last_time',
        'fwd_pkts', 'bwd_pkts',
        'fwd_bytes', 'bwd_bytes',
        'fwd_pkt_lengths', 'bwd_pkt_lengths',
        'fwd_iats', 'bwd_iats', 'flow_iats',
        'fwd_last_time', 'bwd_last_time', 'flow_last_time',
        'tcp_flags_fwd', 'tcp_flags_bwd',
        'fwd_init_win', 'bwd_init_win',
        'fwd_header_lengths', 'bwd_header_lengths',
        'active_times', 'idle_times',
        '_active_start', '_last_active',
        'fwd_act_data_pkts',
        'fwd_min_seg_size',
        'subflow_fwd_pkts', 'subflow_bwd_pkts',
        'subflow_fwd_bytes', 'subflow_bwd_bytes',
    ]

    def __init__(self, src_ip, dst_ip, src_port, dst_port, protocol):
        self.src_ip   = src_ip
        self.dst_ip   = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.protocol = protocol

        self.start_time = None
        self.last_time  = None

        self.fwd_pkts  = 0
        self.bwd_pkts  = 0
        self.fwd_bytes = 0
        self.bwd_bytes = 0

        self.fwd_pkt_lengths: List[int]   = []
        self.bwd_pkt_lengths: List[int]   = []
        self.fwd_iats:        List[float] = []
        self.bwd_iats:        List[float] = []
        self.flow_iats:       List[float] = []

        self.fwd_last_time:  Optional[float] = None
        self.bwd_last_time:  Optional[float] = None
        self.flow_last_time: Optional[float] = None

        # TCP flag counters (FIN SYN RST PSH ACK URG CWE ECE)
        self.tcp_flags_fwd = defaultdict(int)
        self.tcp_flags_bwd = defaultdict(int)

        self.fwd_init_win: Optional[int] = None
        self.bwd_init_win: Optional[int] = None

        self.fwd_header_lengths: List[int] = []
        self.bwd_header_lengths: List[int] = []

        self.active_times: List[float] = []
        self.idle_times:   List[float] = []

        self._active_start: Optional[float] = None
        self._last_active:  Optional[float] = None

        self.fwd_act_data_pkts = 0
        self.fwd_min_seg_size  = 0

        self.subflow_fwd_pkts  = 0
        self.subflow_bwd_pkts  = 0
        self.subflow_fwd_bytes = 0
        self.subflow_bwd_bytes = 0


# ---------------------------------------------------------------------------
# TCP flag helpers
# ---------------------------------------------------------------------------

_FLAG_NAMES = {0x001: 'FIN', 0x002: 'SYN', 0x004: 'RST',
               0x008: 'PSH', 0x010: 'ACK', 0x020: 'URG',
               0x040: 'CWE', 0x080: 'ECE'}


def _record_tcp_flags(flag_store: dict, flags_int: int) -> None:
    for bit, name in _FLAG_NAMES.items():
        if flags_int & bit:
            flag_store[name] += 1


# ---------------------------------------------------------------------------
# Main extractor
# ---------------------------------------------------------------------------

class PacketFlowExtractor:
    """
    Groups Scapy packets into bidirectional flows and computes 78 numerical
    features per flow matching the CICIDS2017 column ordering.
    """

    # Threshold for considering a gap as "idle" (100 ms) — mimics CICFlowMeter
    IDLE_THRESHOLD = 5.0   # seconds

    def __init__(self):
        # Key: canonical 5-tuple (lower IP first for bidirectionality)
        self._flows: Dict[tuple, FlowRecord] = {}
        self._pkt_count = 0

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def add_packet(self, pkt) -> None:
        """Process a single Scapy packet into its flow bucket."""
        if not SCAPY_AVAILABLE:
            return

        try:
            self._process_packet(pkt)
        except Exception as exc:
            logger.debug("Packet processing error (skipping): %s", exc)

    def extract_from_pcap(self, filepath: str) -> None:
        """Read all packets from a PCAP/PCAPNG file and process them."""
        if not SCAPY_AVAILABLE:
            raise RuntimeError("Scapy is not installed. Run: pip install scapy")
        logger.info("Reading PCAP: %s", filepath)
        pkts = rdpcap(filepath)
        logger.info("  → %d packets loaded", len(pkts))
        for pkt in pkts:
            self.add_packet(pkt)
        logger.info("  → %d flows extracted", len(self._flows))

    def get_feature_vectors(self) -> List[Dict[str, Any]]:
        """Finalise all flows and return list of feature dicts."""
        results = []
        for key, flow in self._flows.items():
            try:
                vec = self._compute_features(flow)
                results.append(vec)
            except Exception as exc:
                logger.debug("Feature computation error for flow %s: %s", key, exc)
        return results

    @property
    def flow_count(self) -> int:
        return len(self._flows)

    # ------------------------------------------------------------------
    # Internal — packet routing
    # ------------------------------------------------------------------

    def _get_flow_key(self, src_ip, dst_ip, src_port, dst_port, proto) -> Tuple:
        """
        Returns a canonical key so that fwd = src_ip→dst_ip,
        keeping the two directions in the same FlowRecord.
        The key always has the "smaller" IP first so we route
        packet direction correctly.
        """
        if (src_ip, src_port) < (dst_ip, dst_port):
            return (src_ip, dst_ip, src_port, dst_port, proto)
        else:
            return (dst_ip, src_ip, dst_port, src_port, proto)

    def _is_forward(self, pkt_src, pkt_src_port, flow_key) -> bool:
        """True when packet is in the forward direction of the flow."""
        return pkt_src == flow_key[0] and pkt_src_port == flow_key[2]

    def _process_packet(self, pkt) -> None:
        if not (pkt.haslayer(IP) or pkt.haslayer(IPv6)):
            return

        ip_layer = pkt[IP] if pkt.haslayer(IP) else pkt[IPv6]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst

        proto     = ip_layer.proto if pkt.haslayer(IP) else ip_layer.nh
        src_port  = 0
        dst_port  = 0
        tcp_flags = 0
        header_len = 0
        win_size   = None
        payload_len = 0

        if pkt.haslayer(TCP):
            tcp = pkt[TCP]
            src_port  = tcp.sport
            dst_port  = tcp.dport
            tcp_flags = int(tcp.flags)
            header_len = tcp.dataofs * 4 if tcp.dataofs else 20
            win_size   = tcp.window
            payload_len = len(tcp.payload)
        elif pkt.haslayer(UDP):
            udp = pkt[UDP]
            src_port  = udp.sport
            dst_port  = udp.dport
            header_len = 8
            payload_len = len(udp.payload)
        elif pkt.haslayer(ICMP):
            proto = 1
            payload_len = len(pkt[ICMP].payload)

        pkt_len = len(pkt)
        ts      = float(pkt.time)

        key = self._get_flow_key(src_ip, dst_ip, src_port, dst_port, proto)

        if key not in self._flows:
            flow = FlowRecord(key[0], key[1], key[2], key[3], proto)
            self._flows[key] = flow
        else:
            flow = self._flows[key]

        is_fwd = self._is_forward(src_ip, src_port, key)

        # Timestamps
        if flow.start_time is None:
            flow.start_time = ts
            flow._active_start = ts
        flow.last_time = ts

        # IAT
        if flow.flow_last_time is not None:
            iat = ts - flow.flow_last_time
            flow.flow_iats.append(iat)
            # Active/idle detection
            if iat > self.IDLE_THRESHOLD:
                if flow._last_active is not None:
                    flow.active_times.append(flow._last_active - flow._active_start)
                flow.idle_times.append(iat)
                flow._active_start = ts
        flow.flow_last_time = ts
        flow._last_active = ts

        if is_fwd:
            flow.fwd_pkts  += 1
            flow.fwd_bytes += pkt_len
            flow.fwd_pkt_lengths.append(pkt_len)
            flow.fwd_header_lengths.append(header_len)
            if flow.fwd_last_time is not None:
                flow.fwd_iats.append(ts - flow.fwd_last_time)
            flow.fwd_last_time = ts
            if tcp_flags:
                _record_tcp_flags(flow.tcp_flags_fwd, tcp_flags)
            if win_size is not None and flow.fwd_init_win is None:
                flow.fwd_init_win = win_size
            if payload_len > 0:
                flow.fwd_act_data_pkts += 1
            if header_len:
                flow.fwd_min_seg_size = (
                    min(flow.fwd_min_seg_size, header_len)
                    if flow.fwd_min_seg_size > 0 else header_len
                )
        else:
            flow.bwd_pkts  += 1
            flow.bwd_bytes += pkt_len
            flow.bwd_pkt_lengths.append(pkt_len)
            flow.bwd_header_lengths.append(header_len)
            if flow.bwd_last_time is not None:
                flow.bwd_iats.append(ts - flow.bwd_last_time)
            flow.bwd_last_time = ts
            if tcp_flags:
                _record_tcp_flags(flow.tcp_flags_bwd, tcp_flags)
            if win_size is not None and flow.bwd_init_win is None:
                flow.bwd_init_win = win_size

        flow.subflow_fwd_pkts  = flow.fwd_pkts
        flow.subflow_bwd_pkts  = flow.bwd_pkts
        flow.subflow_fwd_bytes = flow.fwd_bytes
        flow.subflow_bwd_bytes = flow.bwd_bytes

        self._pkt_count += 1

    # ------------------------------------------------------------------
    # Internal — feature computation (78 features, CICIDS2017 order)
    # ------------------------------------------------------------------

    def _compute_features(self, flow: FlowRecord) -> Dict[str, Any]:
        duration = max((flow.last_time or 0) - (flow.start_time or 0), 1e-9)

        total_pkts  = flow.fwd_pkts + flow.bwd_pkts
        total_bytes = flow.fwd_bytes + flow.bwd_bytes

        fwd_m, fwd_std, fwd_max, fwd_min = _stats(flow.fwd_pkt_lengths)
        bwd_m, bwd_std, bwd_max, bwd_min = _stats(flow.bwd_pkt_lengths)

        all_lens  = flow.fwd_pkt_lengths + flow.bwd_pkt_lengths
        all_m, all_std, all_max, all_min = _stats(all_lens)

        fwd_iat_m, fwd_iat_std, fwd_iat_max, fwd_iat_min = _stats(flow.fwd_iats)
        bwd_iat_m, bwd_iat_std, bwd_iat_max, bwd_iat_min = _stats(flow.bwd_iats)
        flow_iat_m, flow_iat_std, flow_iat_max, flow_iat_min = _stats(flow.flow_iats)

        act_m, act_std, act_max, act_min = _stats(flow.active_times)
        idl_m, idl_std, idl_max, idl_min = _stats(flow.idle_times)

        fwd_hdr_m = sum(flow.fwd_header_lengths) / max(len(flow.fwd_header_lengths), 1)
        bwd_hdr_m = sum(flow.bwd_header_lengths) / max(len(flow.bwd_header_lengths), 1)

        ff = flow.tcp_flags_fwd
        fb = flow.tcp_flags_bwd

        features = {
            # Metadata (not used as ML features but returned for display)
            '_src_ip':   flow.src_ip,
            '_dst_ip':   flow.dst_ip,
            '_src_port': flow.src_port,
            '_dst_port': flow.dst_port,
            '_protocol': flow.protocol,

            # ---- 78 CICIDS2017 features ----
            'Flow Duration':              duration * 1e6,          # microseconds
            'Total Fwd Packets':          float(flow.fwd_pkts),
            'Total Backward Packets':     float(flow.bwd_pkts),
            'Total Length of Fwd Packets':float(flow.fwd_bytes),
            'Total Length of Bwd Packets':float(flow.bwd_bytes),
            'Fwd Packet Length Max':      float(fwd_max),
            'Fwd Packet Length Min':      float(fwd_min),
            'Fwd Packet Length Mean':     float(fwd_m),
            'Fwd Packet Length Std':      float(fwd_std),
            'Bwd Packet Length Max':      float(bwd_max),
            'Bwd Packet Length Min':      float(bwd_min),
            'Bwd Packet Length Mean':     float(bwd_m),
            'Bwd Packet Length Std':      float(bwd_std),
            'Flow Bytes/s':               _safe_div(total_bytes, duration),
            'Flow Packets/s':             _safe_div(total_pkts,  duration),
            'Flow IAT Mean':              float(flow_iat_m)  * 1e6,
            'Flow IAT Std':               float(flow_iat_std)* 1e6,
            'Flow IAT Max':               float(flow_iat_max)* 1e6,
            'Flow IAT Min':               float(flow_iat_min)* 1e6,
            'Fwd IAT Total':              sum(flow.fwd_iats) * 1e6,
            'Fwd IAT Mean':               float(fwd_iat_m)   * 1e6,
            'Fwd IAT Std':                float(fwd_iat_std) * 1e6,
            'Fwd IAT Max':                float(fwd_iat_max) * 1e6,
            'Fwd IAT Min':                float(fwd_iat_min) * 1e6,
            'Bwd IAT Total':              sum(flow.bwd_iats) * 1e6,
            'Bwd IAT Mean':               float(bwd_iat_m)   * 1e6,
            'Bwd IAT Std':                float(bwd_iat_std) * 1e6,
            'Bwd IAT Max':                float(bwd_iat_max) * 1e6,
            'Bwd IAT Min':                float(bwd_iat_min) * 1e6,
            'Fwd PSH Flags':              float(ff.get('PSH', 0)),
            'Bwd PSH Flags':              float(fb.get('PSH', 0)),
            'Fwd URG Flags':              float(ff.get('URG', 0)),
            'Bwd URG Flags':              float(fb.get('URG', 0)),
            'Fwd Header Length':          float(sum(flow.fwd_header_lengths)),
            'Bwd Header Length':          float(sum(flow.bwd_header_lengths)),
            'Fwd Packets/s':              _safe_div(flow.fwd_pkts, duration),
            'Bwd Packets/s':              _safe_div(flow.bwd_pkts, duration),
            'Packet Length Min':          float(all_min),
            'Packet Length Max':          float(all_max),
            'Packet Length Mean':         float(all_m),
            'Packet Length Std':          float(all_std),
            'Packet Length Variance':     float(all_std ** 2),
            'FIN Flag Count':             float(ff.get('FIN', 0) + fb.get('FIN', 0)),
            'SYN Flag Count':             float(ff.get('SYN', 0) + fb.get('SYN', 0)),
            'RST Flag Count':             float(ff.get('RST', 0) + fb.get('RST', 0)),
            'PSH Flag Count':             float(ff.get('PSH', 0) + fb.get('PSH', 0)),
            'ACK Flag Count':             float(ff.get('ACK', 0) + fb.get('ACK', 0)),
            'URG Flag Count':             float(ff.get('URG', 0) + fb.get('URG', 0)),
            'CWE Flag Count':             float(ff.get('CWE', 0) + fb.get('CWE', 0)),
            'ECE Flag Count':             float(ff.get('ECE', 0) + fb.get('ECE', 0)),
            'Down/Up Ratio':              _safe_div(flow.bwd_pkts, max(flow.fwd_pkts, 1)),
            'Average Packet Size':        _safe_div(total_bytes, total_pkts),
            'Avg Fwd Segment Size':       float(fwd_m),
            'Avg Bwd Segment Size':       float(bwd_m),
            'Fwd Header Length.1':        float(fwd_hdr_m),
            'Fwd Avg Bytes/Bulk':         0.0,   # bulk analysis not implemented
            'Fwd Avg Packets/Bulk':       0.0,
            'Fwd Avg Bulk Rate':          0.0,
            'Bwd Avg Bytes/Bulk':         0.0,
            'Bwd Avg Packets/Bulk':       0.0,
            'Bwd Avg Bulk Rate':          0.0,
            'Subflow Fwd Packets':        float(flow.subflow_fwd_pkts),
            'Subflow Fwd Bytes':          float(flow.subflow_fwd_bytes),
            'Subflow Bwd Packets':        float(flow.subflow_bwd_pkts),
            'Subflow Bwd Bytes':          float(flow.subflow_bwd_bytes),
            'Init_Win_bytes_forward':     float(flow.fwd_init_win or 0),
            'Init_Win_bytes_backward':    float(flow.bwd_init_win or 0),
            'act_data_pkt_fwd':           float(flow.fwd_act_data_pkts),
            'min_seg_size_forward':       float(flow.fwd_min_seg_size),
            'Active Mean':                float(act_m)   * 1e6,
            'Active Std':                 float(act_std) * 1e6,
            'Active Max':                 float(act_max) * 1e6,
            'Active Min':                 float(act_min) * 1e6,
            'Idle Mean':                  float(idl_m)   * 1e6,
            'Idle Std':                   float(idl_std) * 1e6,
            'Idle Max':                   float(idl_max) * 1e6,
            'Idle Min':                   float(idl_min) * 1e6,
        }

        return features
