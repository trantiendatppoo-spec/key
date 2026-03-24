from flask import Flask, request, jsonify, render_template_string, make_response
import sqlite3, uuid, hashlib, os, threading, time, random, string
from datetime import datetime, timedelta

app = Flask(__name__)
DB = "keys.db"
KEY_EXPIRE_HOURS = 12
ADMIN_TOKEN = os.environ.get("ADMIN_TOKEN", "CHANGE_THIS_SECRET")

# ─── DATABASE ────────────────────────────────────────────────────────────────

def get_db():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with get_db() as db:
        db.execute("""
            CREATE TABLE IF NOT EXISTS keys (
                id        INTEGER PRIMARY KEY AUTOINCREMENT,
                key       TEXT UNIQUE NOT NULL,
                ip_hash   TEXT NOT NULL,
                username  TEXT DEFAULT NULL,
                created   TEXT NOT NULL,
                expires   TEXT NOT NULL
            )
        """)
        db.execute("""
            CREATE TABLE IF NOT EXISTS sessions (
                session_id  TEXT PRIMARY KEY,
                ip_hash     TEXT NOT NULL,
                created     TEXT NOT NULL,
                used        INTEGER DEFAULT 0
            )
        """)
        db.execute("""
            CREATE TABLE IF NOT EXISTS tokens (
                token     TEXT PRIMARY KEY,
                created   TEXT NOT NULL,
                used      INTEGER DEFAULT 0
            )
        """)
        db.commit()

init_db()

# ─── AUTO CLEANUP ─────────────────────────────────────────────────────────────

def auto_cleanup():
    while True:
        time.sleep(3600)
        try:
            now = datetime.utcnow().isoformat()
            with get_db() as db:
                c1 = db.execute("DELETE FROM keys WHERE expires < ?", (now,))
                # Xóa token cũ hơn 30 phút hoặc đã dùng
                c2 = db.execute("DELETE FROM tokens WHERE used=1 OR created < ?",
                    ((datetime.utcnow() - timedelta(minutes=30)).isoformat(),))
                db.commit()
                print(f"[CLEANUP] keys: {c1.rowcount}, tokens: {c2.rowcount}")
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
    with get_db() as db:
        db.execute("INSERT INTO tokens (token, created) VALUES (?,?)", (token, now))
        db.commit()
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

    with get_db() as db:
        db.execute("DELETE FROM keys WHERE ip_hash=? AND expires < ?", (ip_hash, now.isoformat()))
        db.commit()

        row = db.execute(
            "SELECT * FROM keys WHERE ip_hash=? ORDER BY created DESC LIMIT 1", (ip_hash,)
        ).fetchone()

        if row:
            expires_dt = datetime.fromisoformat(row["expires"])
            hours_left = max(0, int((expires_dt - now).total_seconds() // 3600))
            return render_template_string(HTML_PAGE,
                key=row["key"], status="old",
                expires=row["expires"][:16].replace("T", " "), days_left=f"{hours_left} giờ"
            )

        new_key = generate_key()
        while db.execute("SELECT 1 FROM keys WHERE key=?", (new_key,)).fetchone():
            new_key = generate_key()

        expires_str = (now + timedelta(hours=KEY_EXPIRE_HOURS)).isoformat()
        db.execute(
            "INSERT INTO keys (key, ip_hash, created, expires) VALUES (?,?,?,?)",
            (new_key, ip_hash, now.isoformat(), expires_str)
        )
        db.commit()

    return render_template_string(HTML_PAGE,
        key=new_key, status="new",
        expires=expires_str[:16].replace("T", " "), days_left=f"{KEY_EXPIRE_HOURS} giờ"
    )

# API check key cho Roblox script
@app.route("/checkkey")
def checkkey():
    key = request.args.get("key", "").strip().upper()
    username = request.args.get("user", "").strip()
    if not key:
        return jsonify({"valid": False, "reason": "no_key"})

    now = datetime.utcnow().isoformat()
    with get_db() as db:
        row = db.execute("SELECT * FROM keys WHERE key=?", (key,)).fetchone()

    if not row:
        return jsonify({"valid": False, "reason": "invalid"})
    if row["expires"] < now:
        with get_db() as db:
            db.execute("DELETE FROM keys WHERE key=?", (key,))
            db.commit()
        return jsonify({"valid": False, "reason": "expired"})

    # Lần đầu dùng key → lưu username vào
    if not row["username"]:
        if username:
            with get_db() as db:
                db.execute("UPDATE keys SET username=? WHERE key=?", (username, key))
                db.commit()
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
    with get_db() as db:
        rows = db.execute("SELECT * FROM keys ORDER BY created DESC").fetchall()
    active = []
    expired = []
    for r in rows:
        is_permanent = r["expires"].startswith("9999")
        is_expired = r["expires"] < now
        entry = {
            "key": r["key"],
            "username": r["username"] or "chua dung",
            "created": r["created"][:16].replace("T", " "),
            "expires": "VINH VIEN" if is_permanent else r["expires"][:16].replace("T", " "),
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
    with get_db() as db:
        db.execute("DELETE FROM keys WHERE key=?", (key,))
        db.commit()
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
        with get_db() as db:
            db.execute(
                "INSERT OR REPLACE INTO keys (key, ip_hash, username, created, expires) VALUES (?,?,?,?,?)",
                (key, ip_hash, None, datetime.utcnow().isoformat(), expires)
            )
            db.commit()
        return jsonify({"ok": True, "key": key, "permanent": permanent, "expires": expires})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Xóa tất cả key hết hạn ngay: /admin/cleanup?token=...
@app.route("/admin/cleanup")
def admin_cleanup():
    if not check_admin():
        return jsonify({"error": "unauthorized"}), 403
    now = datetime.utcnow().isoformat()
    with get_db() as db:
        cur = db.execute("DELETE FROM keys WHERE expires < ?", (now,))
        db.commit()
    return jsonify({"ok": True, "deleted": cur.rowcount})

# Thống kê: /admin/stats?token=...
@app.route("/admin/stats")
def admin_stats():
    if not check_admin():
        return jsonify({"error": "unauthorized"}), 403
    now = datetime.utcnow().isoformat()
    with get_db() as db:
        total = db.execute("SELECT COUNT(*) FROM keys").fetchone()[0]
        active = db.execute("SELECT COUNT(*) FROM keys WHERE expires > ?", (now,)).fetchone()[0]
        expired = db.execute("SELECT COUNT(*) FROM keys WHERE expires <= ?", (now,)).fetchone()[0]
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
    --bg: #080608;
    --panel: #0e0a0e;
    --border: #3a1a1a;
    --red: #ff1744;
    --yellow: #ffd600;
    --orange: #ff6d00;
    --text: #fff0e0;
    --muted: #7a5a5a;
    --green: #76ff03;
  }
  body {
    background: var(--bg);
    color: var(--text);
    font-family: 'Rajdhani', sans-serif;
    min-height: 100vh;
    display: flex;
    align-items: center;
    justify-content: center;
    overflow: hidden;
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
  body::before {
    content: '';
    position: fixed; inset: 0;
    background-image:
      linear-gradient(rgba(255,23,68,0.04) 1px, transparent 1px),
      linear-gradient(90deg, rgba(255,23,68,0.04) 1px, transparent 1px);
    background-size: 50px 50px;
    pointer-events: none;
  }

  /* Orbs */
  .orb {
    position: fixed; width: 600px; height: 600px; border-radius: 50%;
    background: radial-gradient(circle, rgba(255,23,68,0.10), transparent 70%);
    top: -200px; left: -200px; pointer-events: none;
    animation: pulse 6s ease-in-out infinite;
  }
  .orb2 {
    width: 400px; height: 400px;
    right: -150px; bottom: -150px; left: auto; top: auto;
    background: radial-gradient(circle, rgba(255,214,0,0.08), transparent 70%);
    animation: pulse 8s ease-in-out infinite reverse;
  }
  @keyframes pulse { 0%,100%{opacity:1} 50%{opacity:0.5} }

  /* Card */
  .card {
    position: relative;
    background: linear-gradient(135deg, #0e0a0e 0%, #120808 100%);
    border: 1px solid var(--red);
    border-radius: 4px;
    padding: 48px 40px;
    width: 500px; max-width: 95vw;
    box-shadow:
      0 0 0 1px rgba(255,23,68,0.1),
      0 0 40px rgba(255,23,68,0.15),
      inset 0 0 60px rgba(255,23,68,0.03);
    animation: fadeUp 0.4s ease;
    clip-path: polygon(0 0, calc(100% - 20px) 0, 100% 20px, 100% 100%, 20px 100%, 0 calc(100% - 20px));
  }
  @keyframes fadeUp { from{opacity:0;transform:translateY(30px)} to{opacity:1;transform:translateY(0)} }

  /* Corner decorations */
  .card::before {
    content: '';
    position: absolute; top: -1px; right: 20px;
    width: 40px; height: 2px;
    background: var(--yellow);
    box-shadow: 0 0 8px var(--yellow);
  }
  .card::after {
    content: '';
    position: absolute; bottom: -1px; left: 20px;
    width: 40px; height: 2px;
    background: var(--red);
    box-shadow: 0 0 8px var(--red);
  }

  /* Header */
  .header { display: flex; align-items: center; gap: 12px; margin-bottom: 8px; }
  .logo {
    font-family: 'Orbitron', sans-serif;
    font-size: 22px; font-weight: 900;
    background: linear-gradient(90deg, var(--red), var(--yellow));
    -webkit-background-clip: text; -webkit-text-fill-color: transparent;
    letter-spacing: 2px;
    text-shadow: none;
  }
  .badge {
    font-family: 'Share Tech Mono', monospace;
    font-size: 10px; color: var(--yellow);
    border: 1px solid rgba(255,214,0,0.3);
    border-radius: 2px;
    padding: 2px 8px; letter-spacing: 3px;
    text-transform: uppercase;
    box-shadow: 0 0 8px rgba(255,214,0,0.1);
  }

  .divider {
    height: 1px;
    background: linear-gradient(90deg, var(--red), transparent);
    margin: 16px 0 24px;
    box-shadow: 0 0 8px rgba(255,23,68,0.3);
  }

  .sub {
    font-size: 13px; margin-bottom: 24px; letter-spacing: 1px;
  }
  .status-new { color: var(--green); }
  .status-old { color: var(--yellow); }

  /* Key box */
  .key-label {
    font-family: 'Share Tech Mono', monospace;
    font-size: 10px; color: var(--red);
    letter-spacing: 3px; margin-bottom: 8px;
    text-transform: uppercase;
  }
  .key-box {
    background: #0a0608;
    border: 1px solid var(--red);
    border-radius: 2px;
    padding: 14px 18px;
    margin-bottom: 16px;
    display: flex; align-items: center;
    justify-content: space-between; gap: 12px;
    box-shadow:
      0 0 20px rgba(255,23,68,0.1),
      inset 0 0 20px rgba(255,23,68,0.03);
    position: relative;
  }
  .key-box::before {
    content: '';
    position: absolute; top: 0; left: 0;
    width: 3px; height: 100%;
    background: linear-gradient(180deg, var(--red), var(--yellow));
  }
  .key-text {
    font-family: 'Share Tech Mono', monospace;
    font-size: 13px; color: #fff;
    letter-spacing: 2px; word-break: break-all;
    line-height: 1.6;
  }
  .copy-btn {
    background: transparent;
    border: 1px solid var(--red);
    border-radius: 2px;
    color: var(--red);
    font-family: 'Orbitron', sans-serif;
    font-weight: 700; font-size: 11px;
    padding: 8px 14px; cursor: pointer;
    white-space: nowrap;
    transition: all 0.2s;
    letter-spacing: 1px;
    text-transform: uppercase;
  }
  .copy-btn:hover {
    background: var(--red); color: #000;
    box-shadow: 0 0 16px rgba(255,23,68,0.5);
  }
  .copy-btn.copied {
    background: var(--green); border-color: var(--green); color: #000;
    box-shadow: 0 0 16px rgba(118,255,3,0.4);
  }

  /* Info chips */
  .info-row { display: flex; gap: 10px; margin-bottom: 24px; }
  .chip {
    flex: 1;
    background: rgba(255,23,68,0.04);
    border: 1px solid rgba(255,23,68,0.2);
    border-radius: 2px; padding: 10px 14px;
    position: relative;
  }
  .chip span {
    display: block; color: var(--muted);
    font-family: 'Share Tech Mono', monospace;
    font-size: 9px; letter-spacing: 2px; margin-bottom: 4px;
  }
  .chip strong { color: var(--yellow); font-size: 15px; font-weight: 700; }

  hr { border: none; border-top: 1px solid rgba(255,23,68,0.15); margin: 20px 0; }

  .notice {
    background: rgba(255,23,68,0.04);
    border: 1px solid rgba(255,23,68,0.15);
    border-left: 2px solid var(--yellow);
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
    text-shadow: 0 0 20px rgba(255,23,68,0.5);
  }
  .glitch::before, .glitch::after {
    content: attr(data-text);
    position: absolute; top: 0; left: 0;
    width: 100%;
  }
  .glitch::before {
    color: var(--red); clip: rect(0,0,0,0);
    animation: glitch1 3s infinite linear;
  }
  .glitch::after {
    color: var(--yellow); clip: rect(0,0,0,0);
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
<script>
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

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
