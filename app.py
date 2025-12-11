from flask import Flask, render_template, request, jsonify, session
from collections import Counter
from logic_engine import log_activity, is_ip_blocked, BLOCKED_IPS, LOG_FILE
import google.generativeai as genai
import csv
import time
import os

app = Flask(__name__)
app.secret_key = "silent-guard-ultra-key"

GEMINI_API_KEY = "AIzaSyDZLrZHyau46i78Lidj4Uui51JZqbycEDY"

genai.configure(api_key=GEMINI_API_KEY)
gemini_model = genai.GenerativeModel("gemini-2.5-flash")

HONEY_USERS = ["admin","root_admin", "backup_admin", "sys_super", "supervisor_sys"]
EXPECTED_SG_TOKEN = "CANARY-SILENT-GUARD-1"
ADMIN_DASHBOARD_KEY = "sg-ultra-999"


def get_client_ip():
    xff = request.headers.get("X-Forwarded-For", "")
    if xff:
        parts = [p.strip() for p in xff.split(",") if p.strip()]
        if parts:
            return parts[0]
    xri = request.headers.get("X-Real-IP")
    if xri:
        return xri
    return request.remote_addr or "0.0.0.0"


def load_recent_events(max_rows=80):
    events = []
    if os.path.exists(LOG_FILE):
        try:
            with open(LOG_FILE, "r", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                events = list(reader)
        except Exception:
            events = []
    if len(events) > max_rows:
        events = events[-max_rows:]
    return events


def build_logs_context(events):
    if not events:
        return "لا توجد سجلات حالياً."
    lines = []
    for e in events:
        line = f"[{e.get('timestamp')}] ip={e.get('ip')} endpoint={e.get('endpoint')} service={e.get('service')} method={e.get('method')} risk={e.get('risk_level')} rule={e.get('rule_triggered')}"
        lines.append(line)
    return "\n".join(lines)


def chat_with_ai(user_message):
    events = load_recent_events()
    logs_text = build_logs_context(events)
    prompt = f"""أنت مساعد أمن سيبراني ذكي خاص بنظام يسمى Silent Guard Ultra.

لديك فقط المعلومات التالية القادمة من سجلات النظام، وهي مصدر المعرفة الأساسي لك، ولا يجب أن تعتمد على أي مصادر خارجية أو معلومات من الإنترنت أو من نماذج أخرى. إذا لم تجد في هذه السجلات ما يكفي للإجابة عن سؤال معين، قل للمستخدم بوضوح أنك لا تملك معلومات كافية في السجلات للإجابة.

سجلات الأحداث:
{logs_text}

سؤال المستخدم:
{user_message}

أجب بالعربية الفصحى قدر الإمكان، وبأسلوب واضح ومباشر، وبناءً على ما تراه في السجلات فقط، مع إمكان إضافة شرح عام بسيط في الأمن السيبراني بدون ادعاء الاعتماد على مصادر خارجية."""
    response = gemini_model.generate_content(prompt)
    text = response.text if hasattr(response, "text") else str(response)
    return text, len(events)


@app.before_request
def check_block_list():
    if request.endpoint == "static":
        return
    ip = get_client_ip()
    if is_ip_blocked(ip):
        return render_template("banned.html"), 403


@app.route("/", methods=["GET"])
def index():
    return render_template("index.html", dashboard_key=ADMIN_DASHBOARD_KEY)


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        session["login_opened_at"] = time.time()
        return render_template("login.html")

    data = request.json or request.form
    username = data.get("username", "")
    password = data.get("password", "")
    ip = get_client_ip()
    user_agent = request.headers.get("User-Agent", "")
    is_honey = 1 if username in HONEY_USERS else 0

    opened_at = session.get("login_opened_at")
    flags = []
    if opened_at and time.time() - opened_at < 0.4:
        flags.append("fast_submit")

    payload = "login_user:" + username

    result = log_activity(
        ip=ip,
        endpoint="/login",
        service="Login Service",
        method="POST",
        user_agent=user_agent,
        payload_summary=payload,
        is_canary=is_honey,
        flags=flags,
    )

    if is_honey:
        return jsonify({"status": "failed", "message": "تم رصد محاولة وصول غير مصرح بها.", "risk": result["risk_level"]}), 403

    if username == "user" and password == "1234":
        return jsonify({"status": "success", "message": "تم تسجيل الدخول بنجاح", "risk": result["risk_level"]}), 200

    return jsonify({"status": "failed", "message": "بيانات الدخول غير صحيحة", "risk": result["risk_level"]}), 401


@app.route("/reset", methods=["GET", "POST"])
def reset():
    if request.method == "GET":
        session["reset_opened_at"] = time.time()
        return render_template("reset.html")

    data = request.json or request.form
    email = data.get("email", "")
    ip = get_client_ip()
    user_agent = request.headers.get("User-Agent", "")
    flags = []

    opened_at = session.get("reset_opened_at")
    if opened_at and time.time() - opened_at < 0.4:
        flags.append("fast_submit")

    payload = "reset_email_hash:" + str(hash(email))

    result = log_activity(
        ip=ip,
        endpoint="/reset",
        service="Reset Service",
        method="POST",
        user_agent=user_agent,
        payload_summary=payload,
        is_canary=0,
        flags=flags,
    )

    return jsonify({"status": "success", "message": "تم إرسال رابط الاستعادة (تجريبي).", "risk": result["risk_level"]}), 200


@app.route("/verify", methods=["GET", "POST"])
def verify():
    if request.method == "GET":
        session["verify_opened_at"] = time.time()
        return render_template("verify.html", expected_token=EXPECTED_SG_TOKEN)

    data = request.json or request.form
    token = data.get("token", "")
    nid = data.get("national_id", "")
    sg_token = data.get("sg_token", "")

    ip = get_client_ip()
    user_agent = request.headers.get("User-Agent", "")
    flags = []

    opened_at = session.get("verify_opened_at")
    if opened_at and time.time() - opened_at < 0.4:
        flags.append("fast_submit")

    if "<script" in token.lower() or "<script" in nid.lower():
        flags.append("suspicious_input")

    is_canary = 1 if sg_token != EXPECTED_SG_TOKEN else 0

    payload = "verify_nid_end:" + (nid[-4:] if len(nid) > 4 else "****")

    result = log_activity(
        ip=ip,
        endpoint="/verify",
        service="Verify Service",
        method="POST",
        user_agent=user_agent,
        payload_summary=payload,
        is_canary=is_canary,
        flags=flags,
    )

    if is_canary:
        return jsonify({"status": "failed", "message": "تم رصد نشاط غير طبيعي في طلب التحقق.", "risk": result["risk_level"]}), 403

    if token == "valid-token-123":
        return jsonify({"status": "success", "message": "تم التحقق من الهوية", "risk": result["risk_level"]}), 200

    return jsonify({"status": "failed", "message": "الرمز غير صحيح", "risk": result["risk_level"]}), 403


@app.route("/admin/portal", methods=["GET", "POST"])
def admin_trap():
    ip = get_client_ip()
    user_agent = request.headers.get("User-Agent", "")

    if request.method == "GET":
        log_activity(ip, "/admin/portal", "Canary Admin Trap", "GET", user_agent, "trap_view", is_canary=1, flags=["trap"])
        return render_template("admin_trap.html")

    log_activity(ip, "/admin/portal", "Canary Admin Trap", "POST", user_agent, "trap_submit", is_canary=1, flags=["trap"])
    return jsonify({"error": "ACCESS DENIED", "code": 403}), 403


@app.route("/config", methods=["GET"])
@app.route("/.env", methods=["GET"])
@app.route("/database.sql", methods=["GET"])
@app.route("/backup.zip", methods=["GET"])
@app.route("/api/users", methods=["GET"])
@app.route("/admin", methods=["GET"])
@app.route("/admin/login", methods=["GET"])
def hidden_file_traps():
    ip = get_client_ip()
    user_agent = request.headers.get("User-Agent", "")
    path = request.path

    log_activity(ip, path, "Canary File Trap", "GET", user_agent, "suspicious_file_probing", is_canary=1, flags=["trap"])
    return jsonify({"error": "Forbidden", "message": "You have been flagged."}), 403


@app.route("/debug/error_log", methods=["GET"])
def fake_debug_error():
    ip = get_client_ip()
    user_agent = request.headers.get("User-Agent", "")

    log_activity(ip, "/debug/error_log", "Fake Debug Trap", "GET", user_agent, "debug_page_access", is_canary=1, flags=["trap"])
    return render_template("debug_error.html")


@app.route("/downloads/passwords.xlsx", methods=["GET"])
@app.route("/downloads/db_backup_final.sql", methods=["GET"])
@app.route("/downloads/government_records_2024.zip", methods=["GET"])
def honey_downloads():
    ip = get_client_ip()
    user_agent = request.headers.get("User-Agent", "")

    path = request.path
    log_activity(ip, path, "Honey Download Trap", "GET", user_agent, "honey_file_access", is_canary=1, flags=["trap"])
    return jsonify({"error": "Restricted", "message": "This resource is monitored."}), 403



@app.route("/admin/dashboard", methods=["GET"])
def admin_dashboard():
    key = request.args.get("key")
    if key != ADMIN_DASHBOARD_KEY:
        return "Unauthorized", 401

    events = load_recent_events()

    risk_counts = Counter(e.get("risk_level", "Unknown") for e in events)
    total_events = len(events)
    blocked_ips_count = len(BLOCKED_IPS)

    attack_events = [
        e for e in events
        if e.get("risk_level") in ("Critical", "High", "Medium")
    ]

    attack_events_count = len(attack_events)

    attacks_by_endpoint = Counter(
        e.get("endpoint", "غير معروف") for e in attack_events
    )

    top_paths = attacks_by_endpoint.most_common(7)
    attack_paths_labels = [p or "غير معروف" for p, _ in top_paths]
    attack_paths_counts = [c for _, c in top_paths]

    ordered_levels = ["Critical", "High", "Medium", "Low", "Blocked", "Unknown"]

    risk_chart_labels = []
    risk_chart_values = []

    for lvl in ordered_levels:
        if risk_counts.get(lvl, 0) > 0:
            risk_chart_labels.append(lvl)
            risk_chart_values.append(risk_counts[lvl])

    return render_template(
        "dashboard.html",
        events=events,
        risk_counts=risk_counts,
        total_events=total_events,
        blocked_ips_count=blocked_ips_count,
        admin_key=ADMIN_DASHBOARD_KEY,
        attack_paths_labels=attack_paths_labels,
        attack_paths_counts=attack_paths_counts,
        attack_events_count=attack_events_count,
        risk_chart_labels=risk_chart_labels,
        risk_chart_values=risk_chart_values
    )


@app.route("/ai/chat", methods=["POST"])
def ai_chat():
    data = request.json or {}
    message = data.get("message", "").strip()
    if not message:
        return jsonify({"reply": "الرجاء كتابة سؤال أو استفسار."}), 400
    try:
        reply, count = chat_with_ai(message)
        return jsonify({"reply": reply, "events_count": count})
    except Exception as e:
        return jsonify({"reply": "حدث خطأ أثناء معالجة طلب الذكاء الاصطناعي: " + str(e)}), 500


@app.route("/ai/insights", methods=["GET"])
def ai_insights():
    return render_template("ai_insights.html")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
