from flask import Flask, request, jsonify, render_template_string, make_response
import uuid, hashlib, os, threading, time, random, string
import psycopg2, psycopg2.extras
from datetime import datetime, timedelta

app = Flask(__name__)
KEY_EXPIRE_HOURS = 12
ADMIN_TOKEN = os.environ.get("ADMIN_TOKEN", "CHANGE_THIS_SECRET")
DATABASE_URL = os.environ.get("DATABASE_URL", "")

# ─── DATABASE ────────────────────────────────────────────────────────────────

def get_db():
    conn = psycopg2.connect(DATABASE_URL, cursor_factory=psycopg2.extras.RealDictCursor)
    return conn

def init_db():
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS keys (
                id        SERIAL PRIMARY KEY,
                key       TEXT UNIQUE NOT NULL,
                ip_hash   TEXT NOT NULL,
                username  TEXT DEFAULT NULL,
                created   TEXT NOT NULL,
                expires   TEXT NOT NULL,
                first_used TEXT DEFAULT NULL
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS sessions (
                session_id  TEXT PRIMARY KEY,
                ip_hash     TEXT NOT NULL,
                created     TEXT NOT NULL,
                used        INTEGER DEFAULT 0
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS tokens (
                token     TEXT PRIMARY KEY,
                created   TEXT NOT NULL,
                used      INTEGER DEFAULT 0
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS key_logs (
                id        SERIAL PRIMARY KEY,
                key       TEXT NOT NULL,
                username  TEXT DEFAULT NULL,
                ip_hash   TEXT NOT NULL,
                created   TEXT NOT NULL,
                expires   TEXT NOT NULL,
                deleted_at TEXT NOT NULL,
                reason    TEXT DEFAULT 'expired'
            )
        """)
        conn.commit()

init_db()

# ─── AUTO CLEANUP ─────────────────────────────────────────────────────────────

def auto_cleanup():
    while True:
        time.sleep(900)  # 15 phút
        try:
            now = datetime.utcnow().isoformat()
            with get_db() as conn:
                cur = conn.cursor()
                cur.execute("SELECT key, username, ip_hash, created, expires FROM keys WHERE expires < %s AND NOT expires LIKE '9999%' AND expires != 'pending'", (now,))
                expired_keys = cur.fetchall()
                for ek in expired_keys:
                    cur.execute("""INSERT INTO key_logs (key, username, ip_hash, created, expires, deleted_at, reason)
                        VALUES (%s,%s,%s,%s,%s,%s,'auto_cleanup')""",
                        (ek["key"], ek["username"], ek["ip_hash"], ek["created"], ek["expires"], now))
                cur.execute("DELETE FROM keys WHERE expires < %s AND NOT expires LIKE '9999%' AND expires != 'pending'", (now,))
                c1 = cur.rowcount
                cur.execute("DELETE FROM tokens WHERE used=1 OR created < %s",
                    ((datetime.utcnow() - timedelta(minutes=30)).isoformat(),))
                c2 = cur.rowcount
                conn.commit()
                print(f"[CLEANUP] keys: {c1}, tokens: {c2}")
        except Exception as e:
            print(f"[CLEANUP ERROR] {e}")

threading.Thread(target=auto_cleanup, daemon=True).start()

def keep_alive():
    while True:
        time.sleep(600)
        try:
            import urllib.request
            urllib.request.urlopen("https://bnhub.xyz/ping")
        except:
            pass

threading.Thread(target=keep_alive, daemon=True).start()

def get_secret_path():
    hour = datetime.utcnow().strftime("%Y%m%d%H")
    return hashlib.md5((hour + "bnhub_secret").encode()).hexdigest()[:12]

@app.route("/secret")
def get_secret():
    return jsonify({"path": get_secret_path()})

@app.route("/ping")
def ping():
    return "pong", 200

# ─── HELPER ──────────────────────────────────────────────────────────────────

def hash_ip(ip):
    return hashlib.sha256(ip.encode()).hexdigest()[:24]

def generate_key():
    chars = string.ascii_uppercase + string.digits
    parts = [''.join(random.choices(chars, k=8)) for _ in range(8)]
    return '-'.join(parts)

def get_real_ip():
    return request.headers.get("X-Forwarded-For", request.remote_addr).split(",")[0].strip()

def check_admin():
    return request.args.get("token") == ADMIN_TOKEN

# ─── ROUTES ──────────────────────────────────────────────────────────────────

# Script Roblox gọi cái này để tạo token rồi mở link Link4Sub
# VD: http://IP:5000/gentoken → trả về {"token": "XYZ", "url": "https://link4sub..."}
@app.route("/gentoken")
def gentoken():
    token = str(uuid.uuid4()).replace("-", "")
    now = datetime.utcnow().isoformat()
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute("INSERT INTO tokens (token, created) VALUES (%s,%s)", (token, now))
        conn.commit()
    getkey_url = f"https://bnhub.xyz/getkey?t={token}"
    return jsonify({"token": token, "url": getkey_url})

# Trang get key — chỉ vào được nếu có token hợp lệ chưa dùng
# Trang trung gian — Link4Sub redirect về đây
# Tạo session cookie rồi redirect về /getkey
@app.route("/checkpoint")
def checkpoint():
    secret = get_secret_path()
    resp = make_response(render_template_string(REDIRECT_PAGE, url=f"/{secret}"))
    return resp

@app.route("/<path:secret_path>")
def secret_getkey(secret_path):
    if secret_path != get_secret_path():
        return render_template_string(ERROR_PAGE, msg="Truy cập không hợp lệ! | Vui lòng lấy key từ script.")

    ip = get_real_ip()
    ip_hash = hash_ip(ip)
    now = datetime.utcnow()

    with get_db() as conn:
        cur = conn.cursor()
        cur.execute("DELETE FROM keys WHERE ip_hash=%s AND expires < %s", (ip_hash, now.isoformat()))
        conn.commit()

        cur.execute("SELECT * FROM keys WHERE ip_hash=%s ORDER BY created DESC LIMIT 1", (ip_hash,))
        row = cur.fetchone()

        if row:
            expires_dt = datetime.fromisoformat(row["expires"])
            hours_left = max(0, int((expires_dt - now).total_seconds() // 3600))
            return render_template_string(HTML_PAGE,
                key=row["key"], status="old",
                expires=row["expires"][:16].replace("T", " "), days_left=f"{hours_left} giờ"
            )

        new_key = generate_key()
        cur.execute("SELECT 1 FROM keys WHERE key=%s", (new_key,))
        while cur.fetchone():
            new_key = generate_key()
            cur.execute("SELECT 1 FROM keys WHERE key=%s", (new_key,))

        # expires = "pending" — chưa dùng thì chưa tính giờ
        cur.execute(
            "INSERT INTO keys (key, ip_hash, created, expires) VALUES (%s,%s,%s,%s)",
            (new_key, ip_hash, now.isoformat(), "pending")
        )
        conn.commit()

    return render_template_string(HTML_PAGE,
        key=new_key, status="new",
        expires="Chưa kích hoạt", days_left=f"{KEY_EXPIRE_HOURS} giờ (khi dùng)"
    )

# API check key cho Roblox script
@app.route("/checkkey")
def checkkey():
    key = request.args.get("key", "").strip().upper()
    username = request.args.get("user", "").strip()
    if not key:
        return jsonify({"valid": False, "reason": "no_key"})

    now = datetime.utcnow().isoformat()
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute("SELECT * FROM keys WHERE key=%s", (key,))
        row = cur.fetchone()

    if not row:
        return jsonify({"valid": False, "reason": "invalid"})

    # Key chưa dùng lần nào → kích hoạt ngay, bắt đầu tính giờ
    if row["expires"] == "pending":
        expires_str = (datetime.utcnow() + timedelta(hours=KEY_EXPIRE_HOURS)).isoformat()
        with get_db() as conn:
            cur = conn.cursor()
            cur.execute("UPDATE keys SET expires=%s, first_used=%s WHERE key=%s",
                        (expires_str, now, key))
            conn.commit()
        row = dict(row)
        row["expires"] = expires_str

    if row["expires"] < now:
        with get_db() as conn:
            cur = conn.cursor()
            cur.execute("""INSERT INTO key_logs (key, username, ip_hash, created, expires, deleted_at, reason)
                VALUES (%s,%s,%s,%s,%s,%s,'expired')""",
                (row["key"], row["username"], row["ip_hash"], row["created"], row["expires"], now))
            cur.execute("DELETE FROM keys WHERE key=%s", (key,))
            conn.commit()
        return jsonify({"valid": False, "reason": "expired"})

    # Key vĩnh viễn (expires = 9999) → không check username, dùng được nhiều acc
    is_permanent = row["expires"].startswith("9999")
    if not is_permanent:
        # Lần đầu dùng key → lưu username
        if not row["username"]:
            if username:
                with get_db() as conn:
                    cur = conn.cursor()
                    cur.execute("UPDATE keys SET username=%s WHERE key=%s", (username, key))
                    conn.commit()
        else:
            # Đã có username → check phải đúng
            if username.lower() != row["username"].lower():
                return jsonify({"valid": False, "reason": "wrong_user", "msg": "Key này đã được dùng bởi tài khoản khác!"})

    return jsonify({"valid": True, "expires": row["expires"][:10]})

# ─── ADMIN ───────────────────────────────────────────────────────────────────

# Xem tất cả key: /admin/keys?token=...
@app.route("/admin/keys")
def admin_keys():
    if not check_admin():
        return jsonify({"error": "unauthorized"}), 403
    now = datetime.utcnow().isoformat()
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute("SELECT * FROM keys ORDER BY created DESC")
        rows = cur.fetchall()
    active = []
    expired = []
    for r in rows:
        is_permanent = r["expires"].startswith("9999")
        is_pending = r["expires"] == "pending"
        is_expired = not is_pending and not is_permanent and r["expires"] < now
        entry = {
            "key": r["key"],
            "username": r["username"] or "chua dung",
            "created": r["created"][:16].replace("T", " "),
            "expires": "VINH VIEN" if is_permanent else ("Chua kich hoat" if is_pending else r["expires"][:16].replace("T", " ")),
        }
        if is_expired:
            expired.append(entry)
        else:
            active.append(entry)
    from collections import OrderedDict
    result = OrderedDict()
    result["tong_tat_ca"] = len(active) + len(expired)
    result["tong_active"] = len(active)
    result["KEY DANG HOAT DONG"] = active
    result["tong_expired"] = len(expired)
    result["KEY HET HAN"] = expired
    return app.response_class(
        response=__import__("json").dumps(result, ensure_ascii=False, indent=2),
        mimetype="application/json"
    )

# Xóa key thủ công: /admin/revoke?token=...&key=XXXX-XXXX-XXXX-XXXX
@app.route("/admin/revoke")
def admin_revoke():
    if not check_admin():
        return jsonify({"error": "unauthorized"}), 403
    key = request.args.get("key", "").upper()
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute("SELECT * FROM keys WHERE key=%s", (key,))
        row = cur.fetchone()
        if row:
            cur.execute("""INSERT INTO key_logs (key, username, ip_hash, created, expires, deleted_at, reason)
                VALUES (%s,%s,%s,%s,%s,%s,'admin_revoke')""",
                (row["key"], row["username"], row["ip_hash"], row["created"], row["expires"], datetime.utcnow().isoformat()))
        cur.execute("DELETE FROM keys WHERE key=%s", (key,))
        conn.commit()
    return jsonify({"ok": True, "deleted": key})

# Thêm key thủ công: /admin/addkey?token=...&key=XXXX&permanent=1
@app.route("/admin/addkey")
def admin_addkey():
    if not check_admin():
        return jsonify({"error": "unauthorized"}), 403
    key = request.args.get("key", "").upper().strip()
    permanent = request.args.get("permanent", "0") == "1"
    if not key:
        # Tự tạo key ngẫu nhiên nếu không truyền
        chars = string.ascii_uppercase + string.digits
        key = "-".join("".join(random.choices(chars, k=8)) for _ in range(8))
    # Nếu vĩnh viễn thì expires = 9999-12-31
    if permanent:
        expires = "9999-12-31T00:00:00"
    else:
        expires = (datetime.utcnow() + timedelta(hours=KEY_EXPIRE_HOURS)).isoformat()
    ip_hash = "admin"
    try:
        with get_db() as conn:
            cur = conn.cursor()
            cur.execute(
                "INSERT INTO keys (key, ip_hash, username, created, expires) VALUES (%s,%s,%s,%s,%s) ON CONFLICT (key) DO UPDATE SET expires=EXCLUDED.expires, ip_hash=EXCLUDED.ip_hash",
                (key, ip_hash, None, datetime.utcnow().isoformat(), expires)
            )
            conn.commit()
        return jsonify({"ok": True, "key": key, "permanent": permanent, "expires": expires})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Xóa tất cả key hết hạn ngay: /admin/cleanup?token=...
@app.route("/admin/cleanup")
def admin_cleanup():
    if not check_admin():
        return jsonify({"error": "unauthorized"}), 403
    now = datetime.utcnow().isoformat()
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute("DELETE FROM keys WHERE expires < %s", (now,))
        deleted = cur.rowcount
        conn.commit()
    return jsonify({"ok": True, "deleted": deleted})

# Lịch sử key đã xóa: /admin/key_logs?token=...
@app.route("/admin/key_logs")
def admin_key_logs():
    if not check_admin():
        return jsonify({"error": "unauthorized"}), 403
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute("SELECT * FROM key_logs ORDER BY deleted_at DESC LIMIT 200")
        rows = cur.fetchall()
    result = []
    for r in rows:
        result.append({
            "key": r["key"],
            "username": r["username"] or "chua_dung",
            "created": r["created"][:16].replace("T", " "),
            "expires": r["expires"][:16].replace("T", " "),
            "deleted_at": r["deleted_at"][:16].replace("T", " "),
            "reason": r["reason"]
        })
    return app.response_class(
        response=__import__("json").dumps({"total": len(result), "logs": result}, ensure_ascii=False, indent=2),
        mimetype="application/json"
    )

# Thống kê: /admin/stats?token=...
@app.route("/admin/stats")
def admin_stats():
    if not check_admin():
        return jsonify({"error": "unauthorized"}), 403
    now = datetime.utcnow().isoformat()
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM keys"); total = cur.fetchone()[0]
        cur.execute("SELECT COUNT(*) FROM keys WHERE expires > %s", (now,)); active = cur.fetchone()[0]
        cur.execute("SELECT COUNT(*) FROM keys WHERE expires <= %s", (now,)); expired = cur.fetchone()[0]
    return jsonify({"total": total, "active": active, "expired": expired})

# ─── HTML ─────────────────────────────────────────────────────────────────────

REDIRECT_PAGE = """
<!DOCTYPE html><html><head>
<meta charset="UTF-8">
<meta http-equiv="refresh" content="0;url={{ url }}">
<title>Đang chuyển hướng...</title>
</head><body></body></html>
"""

ERROR_PAGE = """
<!DOCTYPE html><html lang="vi"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Lỗi</title>
<link href="https://fonts.googleapis.com/css2?family=Rajdhani:wght@600;700&display=swap" rel="stylesheet">
<style>
  body { background:#0a0a0f; color:#e0e0ff; font-family:'Rajdhani',sans-serif;
    display:flex; align-items:center; justify-content:center; min-height:100vh; }
  .card { background:#11111c; border:1px solid #ff1744; border-radius:16px;
    padding:48px 40px; width:420px; max-width:95vw; text-align:center; }
  h1 { font-size:28px; color:#ff1744; margin-bottom:16px; }
  p { color:#a0a0c0; font-size:15px; line-height:1.7; }
</style></head><body>
<div class="card">
  <h1>❌ Lỗi</h1>
  <p>{{ msg }}</p>
</div></body></html>
"""

HTML_PAGE = """
<!DOCTYPE html>
<html lang="vi">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>BN HUB | KEY SYSTEM</title>
<link href="https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Orbitron:wght@700;900&family=Rajdhani:wght@400;600;700&display=swap" rel="stylesheet">
<style>
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  :root {
    --bg: #020b18;
    --panel: #061220;
    --border: #0d3a5c;
    --blue: #00b4d8;
    --blue2: #90e0ef;
    --blue3: #caf0f8;
    --text: #e0f7ff;
    --muted: #4a7a99;
    --green: #00f5d4;
  }
  body {
    background: var(--bg) url("/staticbg.jpg") center bottom / cover no-repeat fixed;
    color: var(--text);
    font-family: 'Rajdhani', sans-serif;
    min-height: 100vh;
    display: flex;
    align-items: center;
    justify-content: center;
    overflow: hidden;
  }
  body::before {
    content: '';
    position: fixed; inset: 0;
    background: rgba(0,2,15,0.60);
    pointer-events: none;
    z-index: 0;
  }

  /* Scanlines */
  body::after {
    content: '';
    position: fixed; inset: 0;
    background: repeating-linear-gradient(
      0deg,
      transparent,
      transparent 2px,
      rgba(0,0,0,0.15) 2px,
      rgba(0,0,0,0.15) 4px
    );
    pointer-events: none;
    z-index: 999;
  }

  /* Grid nền */

  /* Orbs */
  .orb {
    position: fixed; width: 600px; height: 600px; border-radius: 50%;
    background: radial-gradient(circle, rgba(0,180,216,0.12), transparent 70%);
    top: -200px; left: -200px; pointer-events: none;
    animation: pulse 6s ease-in-out infinite;
  }
  .orb2 {
    width: 400px; height: 400px;
    right: -150px; bottom: -150px; left: auto; top: auto;
    background: radial-gradient(circle, rgba(144,224,239,0.08), transparent 70%);
    animation: pulse 8s ease-in-out infinite reverse;
  }
  @keyframes pulse { 0%,100%{opacity:1} 50%{opacity:0.5} }

  /* Card */
  .card {
    position: relative; z-index: 1;
    background: linear-gradient(135deg, #061220 0%, #120808 100%);
    border: 1px solid var(--blue);
    border-radius: 4px;
    padding: 48px 40px;
    width: 500px; max-width: 95vw;
    box-shadow:
      0 0 0 1px rgba(0,180,216,0.1),
      0 0 40px rgba(0,180,216,0.15),
      inset 0 0 60px rgba(0,180,216,0.03);
    animation: fadeUp 0.4s ease;
    clip-path: polygon(0 0, calc(100% - 20px) 0, 100% 20px, 100% 100%, 20px 100%, 0 calc(100% - 20px));
  }
  @keyframes fadeUp { from{opacity:0;transform:translateY(30px)} to{opacity:1;transform:translateY(0)} }

  /* Corner decorations */
  .card::before {
    content: '';
    position: absolute; top: -1px; right: 20px;
    width: 40px; height: 2px;
    background: var(--blue2);
    box-shadow: 0 0 8px var(--blue2);
  }
  .card::after {
    content: '';
    position: absolute; bottom: -1px; left: 20px;
    width: 40px; height: 2px;
    background: var(--blue);
    box-shadow: 0 0 8px var(--blue);
  }

  /* Header */
  .header { display: flex; align-items: center; gap: 12px; margin-bottom: 8px; }
  .logo {
    font-family: 'Orbitron', sans-serif;
    font-size: 22px; font-weight: 900;
    background: linear-gradient(90deg, var(--blue), var(--blue2));
    -webkit-background-clip: text; -webkit-text-fill-color: transparent;
    letter-spacing: 2px;
    text-shadow: none;
  }
  .badge {
    font-family: 'Share Tech Mono', monospace;
    font-size: 10px; color: var(--blue2);
    border: 1px solid rgba(0,180,216,0.3);
    border-radius: 2px;
    padding: 2px 8px; letter-spacing: 3px;
    text-transform: uppercase;
    box-shadow: 0 0 8px rgba(0,180,216,0.1);
  }

  .divider {
    height: 1px;
    background: linear-gradient(90deg, var(--blue), transparent);
    margin: 16px 0 24px;
    box-shadow: 0 0 8px rgba(0,180,216,0.3);
  }

  .sub {
    font-size: 13px; margin-bottom: 24px; letter-spacing: 1px;
  }
  .status-new { color: var(--green); }
  .status-old { color: var(--blue2); }

  /* Key box */
  .key-label {
    font-family: 'Share Tech Mono', monospace;
    font-size: 10px; color: var(--blue);
    letter-spacing: 3px; margin-bottom: 8px;
    text-transform: uppercase;
  }
  .key-box {
    background: #0a0608;
    border: 1px solid var(--blue);
    border-radius: 2px;
    padding: 14px 18px;
    margin-bottom: 16px;
    display: flex; align-items: center;
    justify-content: space-between; gap: 12px;
    box-shadow:
      0 0 20px rgba(0,180,216,0.1),
      inset 0 0 20px rgba(0,180,216,0.03);
    position: relative;
  }
  .key-box::before {
    content: '';
    position: absolute; top: 0; left: 0;
    width: 3px; height: 100%;
    background: linear-gradient(180deg, var(--blue), var(--blue2));
  }
  .key-text {
    font-family: 'Share Tech Mono', monospace;
    font-size: 13px; color: #fff;
    letter-spacing: 2px; word-break: break-all;
    line-height: 1.6;
  }
  .copy-btn {
    background: transparent;
    border: 1px solid var(--blue);
    border-radius: 2px;
    color: var(--blue);
    font-family: 'Orbitron', sans-serif;
    font-weight: 700; font-size: 11px;
    padding: 8px 14px; cursor: pointer;
    white-space: nowrap;
    transition: all 0.2s;
    letter-spacing: 1px;
    text-transform: uppercase;
  }
  .copy-btn:hover {
    background: var(--blue); color: #000;
    box-shadow: 0 0 16px rgba(0,180,216,0.5);
  }
  .copy-btn.copied {
    background: var(--green); border-color: var(--green); color: #000;
    box-shadow: 0 0 16px rgba(0,245,212,0.4);
  }

  /* Info chips */
  .info-row { display: flex; gap: 10px; margin-bottom: 24px; }
  .chip {
    flex: 1;
    background: rgba(0,180,216,0.04);
    border: 1px solid rgba(0,180,216,0.2);
    border-radius: 2px; padding: 10px 14px;
    position: relative;
  }
  .chip span {
    display: block; color: var(--muted);
    font-family: 'Share Tech Mono', monospace;
    font-size: 9px; letter-spacing: 2px; margin-bottom: 4px;
  }
  .chip strong { color: var(--blue2); font-size: 15px; font-weight: 700; }

  hr { border: none; border-top: 1px solid rgba(0,180,216,0.15); margin: 20px 0; }

  .notice {
    background: rgba(0,180,216,0.04);
    border: 1px solid rgba(0,180,216,0.15);
    border-left: 2px solid var(--blue2);
    border-radius: 2px; padding: 12px 16px;
    font-size: 13px; color: var(--muted); line-height: 1.8;
  }
  .notice b { color: var(--text); }

  /* Glitch title */
  .glitch {
    font-family: 'Orbitron', sans-serif;
    font-size: 26px; font-weight: 900;
    color: #fff;
    position: relative;
    margin-bottom: 4px;
    text-shadow: 0 0 20px rgba(0,180,216,0.5);
  }
  .glitch::before, .glitch::after {
    content: attr(data-text);
    position: absolute; top: 0; left: 0;
    width: 100%;
  }
  .glitch::before {
    color: var(--blue); clip: rect(0,0,0,0);
    animation: glitch1 3s infinite linear;
  }
  .glitch::after {
    color: var(--blue2); clip: rect(0,0,0,0);
    animation: glitch2 3s infinite linear;
  }
  @keyframes glitch1 {
    0%,94%,100%{clip:rect(0,9999px,0,0)}
    95%{clip:rect(0,9999px,30px,0); transform:translate(-2px,0)}
    97%{clip:rect(20px,9999px,40px,0); transform:translate(2px,0)}
  }
  @keyframes glitch2 {
    0%,96%,100%{clip:rect(0,9999px,0,0)}
    97%{clip:rect(10px,9999px,25px,0); transform:translate(2px,0)}
    99%{clip:rect(30px,9999px,50px,0); transform:translate(-2px,0)}
  }
</style>
</head>
<body>
<div class="orb"></div>
<div class="orb orb2"></div>
<div class="card">
  <div class="header">
    <img src="/logo.png" style="width:38px;height:38px;border-radius:8px;object-fit:cover;box-shadow:0 0 12px rgba(0,180,216,0.4);flex-shrink:0;" alt="N">
    <div class="logo">BN HUB</div>
    <div class="badge">KEY SYSTEM</div>
  </div>
  <div class="divider"></div>
  <div class="glitch" data-text="ACCESS KEY">ACCESS KEY</div>
  <p class="sub">
    {% if status == "new" %}<span class="status-new">▶ KEY MỚI ĐÃ ĐƯỢC TẠO CHO BẠN</span>
    {% else %}<span class="status-old">▶ KEY CỦA BẠN VẪN CÒN HIỆU LỰC</span>{% endif %}
  </p>
  <div class="key-label">// YOUR ACCESS KEY</div>
  <div class="key-box">
    <span class="key-text" id="keyText">{{ key }}</span>
    <button class="copy-btn" id="copyBtn" onclick="copyKey()">COPY</button>
  </div>
  <div class="info-row">
    <div class="chip"><span>EXPIRES</span><strong>{{ expires }}</strong></div>
    <div class="chip"><span>TIME LEFT</span><strong>{{ days_left }}</strong></div>
  </div>
  <hr>
  <div class="notice">
    <b>HƯỚNG DẪN:</b><br>
    Copy key → Mở script trong Roblox → Dán vào ô nhập key → Nhấn Xác nhận.<br>
    Key tự động gia hạn khi bạn vào lại link này sau khi hết hạn.
  </div>
</div>
<canvas id="bg3d" style="position:fixed;top:0;left:0;width:100%;height:100%;z-index:0;pointer-events:none;"></canvas>
<script>
// 3D Particles
const canvas = document.getElementById('bg3d');
const ctx = canvas.getContext('2d');
canvas.width = window.innerWidth;
canvas.height = window.innerHeight;
window.addEventListener('resize', () => { canvas.width = window.innerWidth; canvas.height = window.innerHeight; });

const particles = Array.from({length: 80}, () => ({
  x: Math.random() * canvas.width,
  y: Math.random() * canvas.height,
  z: Math.random() * 1000,
  vx: (Math.random() - 0.5) * 0.3,
  vy: (Math.random() - 0.5) * 0.3,
  vz: Math.random() * 0.5 + 0.1,
}));

const lines = Array.from({length: 12}, () => ({
  x: Math.random() * canvas.width,
  y: Math.random() * canvas.height,
  w: Math.random() * 80 + 20,
  speed: Math.random() * 1.5 + 0.5,
  opacity: Math.random() * 0.3 + 0.05,
}));

function drawParticles() {
  ctx.clearRect(0, 0, canvas.width, canvas.height);
  const cx = canvas.width / 2, cy = canvas.height / 2, fov = 500;

  // Scan lines flying
  lines.forEach(l => {
    l.y += l.speed;
    if (l.y > canvas.height) { l.y = -5; l.x = Math.random() * canvas.width; }
    ctx.beginPath();
    ctx.strokeStyle = `rgba(0,180,216,${l.opacity})`;
    ctx.lineWidth = 1;
    ctx.moveTo(l.x, l.y);
    ctx.lineTo(l.x + l.w, l.y);
    ctx.stroke();
  });

  // 3D particles
  particles.forEach(p => {
    p.z -= p.vz;
    p.x += p.vx;
    p.y += p.vy;
    if (p.z <= 0) p.z = 1000;
    if (p.x < 0 || p.x > canvas.width) p.vx *= -1;
    if (p.y < 0 || p.y > canvas.height) p.vy *= -1;

    const scale = fov / (fov + p.z);
    const sx = (p.x - cx) * scale + cx;
    const sy = (p.y - cy) * scale + cy;
    const size = scale * 2.5;
    const alpha = scale * 0.6;

    ctx.beginPath();
    ctx.arc(sx, sy, size, 0, Math.PI * 2);
    ctx.fillStyle = `rgba(0,${Math.floor(180 + scale*60)},216,${alpha})`;
    ctx.fill();
  });

  // Connect nearby
  for (let i = 0; i < particles.length; i++) {
    const a = particles[i];
    const sa = fov / (fov + a.z);
    const ax = (a.x - cx) * sa + cx;
    const ay = (a.y - cy) * sa + cy;
    for (let j = i+1; j < particles.length; j++) {
      const b = particles[j];
      const sb = fov / (fov + b.z);
      const bx = (b.x - cx) * sb + cx;
      const by = (b.y - cy) * sb + cy;
      const dist = Math.hypot(ax-bx, ay-by);
      if (dist < 80) {
        ctx.beginPath();
        ctx.strokeStyle = `rgba(0,180,216,${0.08 * (1 - dist/80)})`;
        ctx.lineWidth = 0.5;
        ctx.moveTo(ax, ay);
        ctx.lineTo(bx, by);
        ctx.stroke();
      }
    }
  }

  requestAnimationFrame(drawParticles);
}
drawParticles();

// Card 3D tilt
const card = document.querySelector('.card');
document.addEventListener('mousemove', e => {
  const rect = card.getBoundingClientRect();
  const cx = rect.left + rect.width/2;
  const cy = rect.top + rect.height/2;
  const dx = (e.clientX - cx) / (window.innerWidth/2);
  const dy = (e.clientY - cy) / (window.innerHeight/2);
  card.style.transform = `perspective(1000px) rotateY(${dx*8}deg) rotateX(${-dy*8}deg) scale(1.02)`;
  card.style.boxShadow = `${-dx*20}px ${-dy*20}px 60px rgba(0,180,216,0.2), 0 0 40px rgba(0,180,216,0.15)`;
});
document.addEventListener('mouseleave', () => {
  card.style.transform = '';
  card.style.boxShadow = '';
});

// Copy
function copyKey() {
  navigator.clipboard.writeText(document.getElementById('keyText').innerText).then(() => {
    const btn = document.getElementById('copyBtn');
    btn.textContent = '✓ COPIED'; btn.classList.add('copied');
    setTimeout(() => { btn.textContent = 'COPY'; btn.classList.remove('copied'); }, 2000);
  });
}
</script>
</body>
</html>
"""

@app.route("/staticbg.jpg")
def serve_bg():
    from flask import send_file
    return send_file("staticbg.jpg", mimetype="image/jpeg")

@app.route("/logo.png")
def serve_logo():
    from flask import send_file
    return send_file("logo.png", mimetype="image/png")

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
