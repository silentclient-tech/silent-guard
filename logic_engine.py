import csv
import os
import uuid
from datetime import datetime, timedelta

LOG_DIR = "data"
LOG_FILE = os.path.join(LOG_DIR, "logs.csv")
BLOCKED_IPS = {}
SUSPICIOUS_AGENTS = ["sqlmap", "nikto", "curl", "wget", "dirb", "gobuster", "python-requests", "postman", "burp", "fuzz"]


def init_system():
    if not os.path.exists(LOG_DIR):
        os.makedirs(LOG_DIR)
    if not os.path.exists(LOG_FILE):
        with open(LOG_FILE, mode="w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(
                [
                    "id",
                    "timestamp",
                    "ip",
                    "endpoint",
                    "service",
                    "method",
                    "user_agent",
                    "payload_summary",
                    "is_canary",
                    "attempt_count_1min",
                    "rule_triggered",
                    "risk_level",
                ]
            )


def is_ip_blocked(ip):
    if ip in BLOCKED_IPS:
        block_time = BLOCKED_IPS[ip]
        if datetime.now() < block_time:
            return True
        else:
            del BLOCKED_IPS[ip]
    return False


def get_ip_stats(target_ip):
    if not os.path.exists(LOG_FILE):
        return 0
    count = 0
    one_minute_ago = datetime.now() - timedelta(minutes=1)
    try:
        with open(LOG_FILE, mode="r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                if row.get("ip") == target_ip:
                    try:
                        log_time = datetime.fromisoformat(row["timestamp"])
                        if log_time > one_minute_ago:
                            count += 1
                    except Exception:
                        continue
    except Exception:
        return 0
    return count


def evaluate_risk(ip, is_canary, recent_count, user_agent, endpoint, flags=None):
    ua_lower = (user_agent or "").lower()
    ua_flag = any(tool in ua_lower for tool in SUSPICIOUS_AGENTS)
    flags = flags or []
    if is_canary == 1 or "trap" in flags:
        BLOCKED_IPS[ip] = datetime.now() + timedelta(minutes=10)
        return "Critical", "Canary Trap - IP BLOCKED 10m"
    if ua_flag and recent_count >= 5:
        BLOCKED_IPS[ip] = datetime.now() + timedelta(minutes=5)
        return "High", "Scanner Detected - IP BLOCKED 5m"
    if "fast_submit" in flags and recent_count >= 3:
        BLOCKED_IPS[ip] = datetime.now() + timedelta(minutes=3)
        return "High", "Automation Suspected - IP BLOCKED 3m"
    if recent_count >= 15:
        BLOCKED_IPS[ip] = datetime.now() + timedelta(minutes=3)
        return "High", "Brute Force - IP BLOCKED 3m"
    if recent_count >= 8 or ua_flag or "suspicious_input" in flags:
        return "Medium", "Suspicious Activity"
    return "Low", "Normal Access"


def log_activity(ip, endpoint, service, method, user_agent, payload_summary, is_canary=0, flags=None):
    init_system()
    if is_ip_blocked(ip):
        return {"id": "blocked", "risk_level": "Blocked", "rule": "IP in Blacklist"}
    recent_count = get_ip_stats(ip)
    current_count = recent_count + 1
    risk_level, rule_triggered = evaluate_risk(
        ip=ip,
        is_canary=is_canary,
        recent_count=recent_count,
        user_agent=user_agent,
        endpoint=endpoint,
        flags=flags,
    )
    request_id = str(uuid.uuid4())
    timestamp = datetime.now().isoformat()
    try:
        with open(LOG_FILE, mode="a", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(
                [
                    request_id,
                    timestamp,
                    ip,
                    endpoint,
                    service,
                    method,
                    user_agent,
                    payload_summary,
                    is_canary,
                    current_count,
                    rule_triggered,
                    risk_level,
                ]
            )
    except Exception:
        pass
    return {"id": request_id, "risk_level": risk_level, "rule": rule_triggered}
