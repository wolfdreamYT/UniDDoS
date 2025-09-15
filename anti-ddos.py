import time
import argparse
import threading
import logging
import subprocess
import json
from collections import deque, defaultdict
from statistics import mean
from dataclasses import dataclass, field

try:
    from scapy.all import sniff, IP, TCP, UDP, Raw, conf
except Exception as e:
    raise SystemExit("scapy is required. Install with: pip install scapy") from e

GEOIP_AVAILABLE = True
try:
    import geoip2.database
except Exception:
    GEOIP_AVAILABLE = False

# ------------------ CONFIG ------------------
INTERFACE = None 
SNAPLEN = 65535
CAPTURE_FILTER = "" 

ENFORCE_BLOCKING = False      
BLOCK_DURATION = 300     
DRY_RUN = True                  
ALERT_WEBHOOK = None           

SHORT_WINDOW_SEC = 10         
LONG_WINDOW_SEC = 60           
MOVING_AVG_SAMPLES = 200         
SPIKE_RATIO = 3.0              
FIXED_INTERVAL_TOLERANCE = 0.0005  
PERIODIC_DETECTION_MIN_COUNT = 5  

DEFAULT_TOKENS_PER_SEC = 100
BURST_SIZE = 200

GEOIP_DB_PATH = "/usr/local/share/GeoLite2-Country.mmdb"

CDN_WHITELIST_FILE = "cdn_whitelist.txt"

# Logging
logging.basicConfig(level=logging.INFO, format="[%(asctime)s] %(levelname)s: %(message)s")
logger = logging.getLogger("ddos_defender")
from logging.handlers import RotatingFileHandler
handler = RotatingFileHandler("ddos_defender.log", maxBytes=5_000_000, backupCount=3)
handler.setFormatter(logging.Formatter("[%(asctime)s] %(levelname)s: %(message)s"))
logger.addHandler(handler)

# ------------------ DATA STRUCTURES ------------------
@dataclass
class IPStats:
    sizes: deque = field(default_factory=lambda: deque(maxlen=MOVING_AVG_SAMPLES))
    timestamps: deque = field(default_factory=lambda: deque(maxlen=MOVING_AVG_SAMPLES))
    protocols: defaultdict = field(default_factory=lambda: defaultdict(int)) 
    last_seen: float = field(default_factory=time.time)
    tokens: float = BURST_SIZE
    last_token_time: float = field(default_factory=time.time)
    blocked_until: float = 0.0
    periodic_intervals: deque = field(default_factory=lambda: deque(maxlen=50)) 

ip_stats = defaultdict(IPStats)  
global_sizes = deque(maxlen=MOVING_AVG_SAMPLES)
global_timestamps = deque(maxlen=MOVING_AVG_SAMPLES)

blocked_ips = {}  

geo_reader = None
if GEOIP_AVAILABLE and GEOIP_DB_PATH:
    try:
        geo_reader = geoip2.database.Reader(GEOIP_DB_PATH)
        logger.info("GeoIP DB loaded.")
    except Exception:
        geo_reader = None
        logger.info("GeoIP DB not available or unreadable; country checks disabled.")

cdn_whitelist = set()
try:
    with open(CDN_WHITELIST_FILE, "r") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"): continue
            cdn_whitelist.add(line)
    logger.info(f"Loaded CDN whitelist ({len(cdn_whitelist)} entries).")
except FileNotFoundError:
    logger.info("No CDN whitelist file found; proceed without CDN exceptions.")

# ------------------ UTILITIES ------------------
def send_alert(msg):
    logger.warning(msg)
    if ALERT_WEBHOOK:
        try:
            import requests
            requests.post(ALERT_WEBHOOK, json={"text": msg}, timeout=3)
        except Exception as e:
            logger.exception("Failed to post alert webhook: %s", e)

def is_cdn(ip):
    return ip in cdn_whitelist

def get_country(ip):
    if not geo_reader:
        return None
    try:
        rec = geo_reader.country(ip)
        return rec.country.iso_code
    except Exception:
        return None

def system_block_ip(ip):
    if DRY_RUN:
        logger.info("[DRY RUN] Would block IP: %s", ip)
        return True
    try:
        subprocess.check_call(["/sbin/iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"])
        logger.info("Blocked IP via iptables: %s", ip)
        return True
    except Exception as e:
        logger.exception("Failed to block IP %s: %s", ip, e)
        return False

def system_unblock_ip(ip):
    if DRY_RUN:
        logger.info("[DRY RUN] Would unblock IP: %s", ip)
        return True
    try:
        subprocess.check_call(["/sbin/iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"])
        logger.info("Unblocked IP via iptables: %s", ip)
        return True
    except Exception as e:
        logger.exception("Failed to unblock IP %s: %s", ip, e)
        return False

# ------------------ DETECTION LOGIC ------------------
def update_token_bucket(stats: IPStats):
    now = time.time()
    elapsed = now - stats.last_token_time
    stats.tokens = min(BURST_SIZE, stats.tokens + elapsed * DEFAULT_TOKENS_PER_SEC)
    stats.last_token_time = now

def consume_token(stats: IPStats, amount=1):
    update_token_bucket(stats)
    if stats.tokens >= amount:
        stats.tokens -= amount
        return True
    return False

def moving_average(sizes):
    if not sizes:
        return 0.0
    return sum(sizes)/len(sizes)

def short_long_window_rates(timestamps):
    if len(timestamps) < 2:
        return 0.0, 0.0
    now = time.time()
    short_cutoff = now - SHORT_WINDOW_SEC
    long_cutoff = now - LONG_WINDOW_SEC
    short_count = sum(1 for t in timestamps if t >= short_cutoff)
    long_count = sum(1 for t in timestamps if t >= long_cutoff)
    short_rate = short_count / SHORT_WINDOW_SEC
    long_rate = long_count / LONG_WINDOW_SEC if LONG_WINDOW_SEC>0 else 0
    return short_rate, long_rate

def detect_periodicity(stats: IPStats):
    if len(stats.periodic_intervals) < PERIODIC_DETECTION_MIN_COUNT:
        return False, None
    med = sorted(stats.periodic_intervals)[len(stats.periodic_intervals)//2]
    close = sum(1 for iv in stats.periodic_intervals if abs(iv - med) <= FIXED_INTERVAL_TOLERANCE)
    if close / len(stats.periodic_intervals) > 0.8:
        return True, med
    return False, None

def handle_packet(pkt):
    if not pkt.haslayer(IP):
        return
    ip_layer = pkt.getlayer(IP)
    src = ip_layer.src
    proto = None
    length = len(pkt)
    now = time.time()

    stats = ip_stats[src]
    stats.sizes.append(length)
    stats.timestamps.append(now)
    stats.last_seen = now

    if pkt.haslayer(UDP):
        proto = "UDP"
        stats.protocols["UDP"] += 1
    elif pkt.haslayer(TCP):
        proto = "TCP"
        stats.protocols["TCP"] += 1
    else:
        proto = "OTHER"
        stats.protocols["OTHER"] += 1

    global_sizes.append(length)
    global_timestamps.append(now)

    if len(stats.timestamps) >= 2:
        iv = stats.timestamps[-1] - stats.timestamps[-2]
        stats.periodic_intervals.append(iv)

    ip_avg = moving_average(stats.sizes)
    global_avg = moving_average(global_sizes)
    lower = 0.5 * ip_avg
    upper = 1.5 * ip_avg

    if length < lower or length > upper:
        send_alert(f"[SIZE_ANOMALY] src={src} len={length} ip_avg={ip_avg:.1f} (band {lower:.1f}-{upper:.1f})")

    short_rate, long_rate = short_long_window_rates(stats.timestamps)
    if long_rate > 0 and short_rate > SPIKE_RATIO * long_rate:
        send_alert(f"[SPIKE] src={src} short_rate={short_rate:.1f}/s long_rate={long_rate:.1f}/s")
        if not is_cdn(src):
            take_mitigation_action(src, reason="spike")

    allowed = consume_token(stats, amount=1)
    if not allowed:
        send_alert(f"[RATE_LIMIT] src={src} tokens_exhausted")
        take_mitigation_action(src, reason="rate_limit")
        return 

    country = get_country(src) if geo_reader else None
    if country:
        expected_local_country = "CA"
        if country != expected_local_country and country not in ("US",):
            send_alert(f"[GEO_MISMATCH] src={src} country={country}")

    periodic, period = detect_periodicity(stats)
    if periodic:
        send_alert(f"[PERIODIC] src={src} period={period:.6f}s; flagging as automated bot")
        take_mitigation_action(src, reason="periodic")

    total_proto = sum(stats.protocols.values()) or 1
    udp_frac = stats.protocols.get("UDP", 0) / total_proto
    tcp_frac = stats.protocols.get("TCP", 0) / total_proto
    if udp_frac > 0.8:
        send_alert(f"[PROTO_DOMINANT] src={src} UDP-dominant ({udp_frac*100:.1f}%) - apply UDP throttle")
        take_mitigation_action(src, reason="udp_dominant")
    if tcp_frac > 0.9:
        send_alert(f"[PROTO_DOMINANT] src={src} TCP-dominant ({tcp_frac*100:.1f}%)")

def take_mitigation_action(ip, reason="unknown"):
    stats = ip_stats[ip]
    now = time.time()
    if ip in blocked_ips and blocked_ips[ip] > now:
        return
    if is_cdn(ip):
        logger.info("Skipping mitigation for CDN IP: %s", ip)
        return

    if reason in ("spike", "rate_limit", "periodic"):
        stats.tokens = max(0, stats.tokens - DEFAULT_TOKENS_PER_SEC*10)
        send_alert(f"[MITIGATION] Applied soft throttle to {ip} for reason={reason}")

        if ENFORCE_BLOCKING:
            ok = system_block_ip(ip)
            if ok:
                blocked_until = time.time() + BLOCK_DURATION
                blocked_ips[ip] = blocked_until
                logger.info("IP %s blocked until %s", ip, time.ctime(blocked_until))
                send_alert(f"[BLOCK] {ip} blocked for {BLOCK_DURATION}s due to {reason}")
    elif reason == "udp_dominant":
        stats.tokens = max(0, stats.tokens - DEFAULT_TOKENS_PER_SEC*20)
        send_alert(f"[MITIGATION] Aggressive UDP throttle for {ip}")
    else:
        send_alert(f"[MITIGATION] fallback soft action for {ip}")
def unblock_worker():
    while True:
        now = time.time()
        to_unblock = [ip for ip, until in blocked_ips.items() if until <= now]
        for ip in to_unblock:
            system_unblock_ip(ip)
            del blocked_ips[ip]
            send_alert(f"[UNBLOCK] {ip} unblocked after timer")
        time.sleep(5)

def global_detector():
    while True:
        if len(global_timestamps) >= 2:
            short_rate, long_rate = short_long_window_rates(global_timestamps)
            if long_rate>0 and short_rate > SPIKE_RATIO * long_rate:
                send_alert(f"[GLOBAL_SPIKE] short_rate={short_rate:.1f}/s long_rate={long_rate:.1f}/s")
        now = time.time()
        stale = [ip for ip, s in ip_stats.items() if now - s.last_seen > 3600]
        for ip in stale:
            del ip_stats[ip]
        time.sleep(2)

# ------------------ CLI & STARTUP ------------------
def main():
    global ENFORCE_BLOCKING, DRY_RUN, INTERFACE, CAPTURE_FILTER

    parser = argparse.ArgumentParser(description="Defensive DDoS defender (monitoring + optional blocking)")
    parser.add_argument("--iface", "-i", default=INTERFACE, help="Interface to sniff (default: system default)")
    parser.add_argument("--filter", "-f", default=CAPTURE_FILTER, help="BPF capture filter")
    parser.add_argument("--enforce", action="store_true", help="Enable system-level blocking (iptables) - requires root")
    parser.add_argument("--dry-run", dest="dry", action="store_true", default=DRY_RUN, help="Enable dry-run mode (no iptables changes)")
    args = parser.parse_args()

    ENFORCE_BLOCKING = args.enforce
    DRY_RUN = args.dry
    INTERFACE = args.iface or INTERFACE
    CAPTURE_FILTER = args.filter or CAPTURE_FILTER

    if ENFORCE_BLOCKING and not DRY_RUN:
        logger.warning("ENFORCE_BLOCKING enabled. This will modify iptables. Run as root and be careful.")

    threading.Thread(target=unblock_worker, daemon=True).start()
    threading.Thread(target=global_detector, daemon=True).start()

    logger.info("Starting packet capture on %s (filter=%r). Dry-run=%s. Enforcement=%s", INTERFACE or "default", CAPTURE_FILTER, DRY_RUN, ENFORCE_BLOCKING)

    sniff(iface=INTERFACE, prn=handle_packet, store=0, filter=CAPTURE_FILTER)

if __name__ == "__main__":
    main()
