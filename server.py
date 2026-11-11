#!/usr/bin/env python3
"""HealthClaim Intelligence (HCI) - MVP backend. Python 3.9+ standard library only.
Run: python3 server.py   ->  http://localhost:8000   (login admin / admin123, change it!)"""
import csv, io, json, os, re, random, secrets, sqlite3, hashlib, datetime as dt
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler

DB = os.environ.get("HCI_DB", "hci.db")
PORT = int(os.environ.get("PORT", 8000))
STATIC = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")
STATUSES = ["Draft", "Submitted", "Under review", "Approved", "Rejected", "Paid"]
FIELDS = ["claim_no", "insurer", "patient_ref", "service_date", "service_code", "description",
          "claimed_amount", "submitted_date", "status", "approved_amount", "paid_amount", "rejection_reason"]
REJECT_MAP = {  # keyword -> category (edit freely; feeds Rejection Intelligence)
    "Missing documentation": ["document", "missing", "incomplete", "attach"],
    "Eligibility": ["eligib", "expired", "member", "inactive", "enrol"],
    "Duplicate billing": ["duplicate", "already"],
    "Tariff / pricing": ["tariff", "price", "amount", "rate"],
    "Coding error": ["code", "icd", "gdrg", "diagnos"],
    "Late submission": ["late", "deadline", "time limit"],
}
SCHEMA = """
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, username TEXT UNIQUE, salt TEXT, pw TEXT, role TEXT);
CREATE TABLE IF NOT EXISTS sessions(token TEXT PRIMARY KEY, user_id INTEGER, created TEXT);
CREATE TABLE IF NOT EXISTS claims(id INTEGER PRIMARY KEY, claim_no TEXT UNIQUE, insurer TEXT, patient_ref TEXT,
  service_date TEXT, service_code TEXT, description TEXT, claimed_amount REAL, submitted_date TEXT,
  status TEXT DEFAULT 'Draft', approved_amount REAL, paid_amount REAL, rejection_reason TEXT,
  rejection_category TEXT, flags TEXT DEFAULT '[]', created TEXT);
CREATE TABLE IF NOT EXISTS tariffs(id INTEGER PRIMARY KEY, insurer TEXT, code TEXT, amount REAL, UNIQUE(insurer, code));
CREATE TABLE IF NOT EXISTS rules(id INTEGER PRIMARY KEY, type TEXT, insurer TEXT, param TEXT, active INTEGER DEFAULT 1,
  source TEXT, effective_date TEXT, version INTEGER DEFAULT 1);
CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY, ts TEXT, user TEXT, action TEXT, detail TEXT);
"""

def now(): return dt.datetime.now(dt.timezone.utc).replace(tzinfo=None).isoformat(timespec="seconds")
def hpw(pw, salt): return hashlib.pbkdf2_hmac("sha256", pw.encode(), salt.encode(), 120_000).hex()

def conn():
    c = sqlite3.connect(DB); c.row_factory = sqlite3.Row; return c

def init():
    c = conn(); c.executescript(SCHEMA)
    if not c.execute("SELECT 1 FROM users").fetchone():
        salt = secrets.token_hex(8)
        c.execute("INSERT INTO users(username,salt,pw,role) VALUES('admin',?,?,'admin')",
                  (salt, hpw(os.environ.get("HCI_ADMIN_PW", "admin123"), salt)))
    if not c.execute("SELECT 1 FROM rules").fetchone():
        d = now()[:10]
        for t, ins, p, s in [
            ("required", "*", "insurer,patient_ref,service_date,service_code,claimed_amount", "Internal baseline"),
            ("positive", "*", "claimed_amount", "Internal baseline"),
            ("duplicate", "*", "patient_ref,service_code,service_date", "Internal baseline"),
            ("tariff", "*", "0", "Compares to uploaded tariff table (verify tariffs with insurer)"),
            ("deadline", "NHIA", "180", "PLACEHOLDER - verify real filing deadline with NHIA"),
            ("deadline", "*", "90", "PLACEHOLDER - verify with each insurer")]:
            c.execute("INSERT INTO rules(type,insurer,param,source,effective_date) VALUES(?,?,?,?,?)", (t, ins, p, s, d))
    c.commit(); c.close()

def categorise(reason):
    r = (reason or "").lower()
    if not r: return None
    for cat, kws in REJECT_MAP.items():
        if any(k in r for k in kws): return cat
    return "Other"

def num(v):
    try: return float(str(v).replace(",", "").replace("GH¢", "").strip())
    except Exception: return None

def pdate(v):
    try: return dt.date.fromisoformat(str(v)[:10])
    except Exception: return None

def validate_all(c):
    """Run active rules on every Draft/Rejected claim; store explainable flags. Humans decide - nothing auto-approves."""
    rules = [dict(r) for r in c.execute("SELECT * FROM rules WHERE active=1")]
    tariffs = {(r["insurer"].lower(), r["code"].lower()): r["amount"] for r in c.execute("SELECT * FROM tariffs")}
    claims = [dict(r) for r in c.execute("SELECT * FROM claims")]
    seen = {}
    for cl in claims:
        seen.setdefault((cl["patient_ref"], cl["service_code"], cl["service_date"]), []).append(cl["claim_no"])
    n = 0
    for cl in claims:
        if cl["status"] not in ("Draft", "Rejected"): continue
        flags = []
        for r in rules:
            if r["insurer"] not in ("*", cl["insurer"]): continue
            if r["type"] == "required":
                miss = [f for f in r["param"].split(",") if cl.get(f) in (None, "")]
                if miss: flags.append(("error", "Missing required field(s): " + ", ".join(miss)))
            elif r["type"] == "positive" and (cl["claimed_amount"] or 0) <= 0:
                flags.append(("error", "Claimed amount must be greater than zero"))
            elif r["type"] == "duplicate":
                dups = [x for x in seen[(cl["patient_ref"], cl["service_code"], cl["service_date"])] if x != cl["claim_no"]]
                if dups: flags.append(("error", "Possible duplicate of " + ", ".join(dups)))
            elif r["type"] == "tariff":
                t = tariffs.get(((cl["insurer"] or "").lower(), (cl["service_code"] or "").lower()))
                if t is not None and cl["claimed_amount"] is not None and abs(t - cl["claimed_amount"]) > 0.005:
                    flags.append(("warning", f"Claimed {cl['claimed_amount']:.2f} differs from tariff {t:.2f}"))
            elif r["type"] == "deadline":
                sd = pdate(cl["service_date"]); lim = int(r["param"])
                if sd and (dt.date.today() - sd).days > lim:
                    flags.append(("warning", f"Service is {(dt.date.today() - sd).days} days old; rule limit {lim} days ({r['insurer']})"))
        c.execute("UPDATE claims SET flags=? WHERE id=?", (json.dumps(flags), cl["id"])); n += 1
    return n

def import_claims(c, text):
    ok = skipped = 0; errors = []
    for i, row in enumerate(csv.DictReader(io.StringIO(text)), start=2):
        row = {(k or "").strip().lower(): (v or "").strip() for k, v in row.items()}
        if not row.get("claim_no"): errors.append(f"Row {i}: claim_no missing"); continue
        st = row.get("status") or "Draft"
        st = next((s for s in STATUSES if s.lower() == st.lower()), "Draft")
        try:
            c.execute("""INSERT INTO claims(claim_no,insurer,patient_ref,service_date,service_code,description,claimed_amount,
              submitted_date,status,approved_amount,paid_amount,rejection_reason,rejection_category,created)
              VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                      (row["claim_no"], row.get("insurer"), row.get("patient_ref"), row.get("service_date"),
                       row.get("service_code"), row.get("description"), num(row.get("claimed_amount")),
                       row.get("submitted_date"), st, num(row.get("approved_amount")), num(row.get("paid_amount")),
                       row.get("rejection_reason"), categorise(row.get("rejection_reason")), now()))
            ok += 1
        except sqlite3.IntegrityError: skipped += 1
    return {"imported": ok, "skipped_duplicates": skipped, "errors": errors[:20]}

def import_tariffs(c, text):
    n = 0
    for row in csv.DictReader(io.StringIO(text)):
        row = {(k or "").strip().lower(): (v or "").strip() for k, v in row.items()}
        a = num(row.get("amount"))
        if row.get("insurer") and row.get("code") and a is not None:
            c.execute("INSERT OR REPLACE INTO tariffs(insurer,code,amount) VALUES(?,?,?)", (row["insurer"], row["code"], a)); n += 1
    return {"tariffs_loaded": n}

def dashboard(c):
    cl = [dict(r) for r in c.execute("SELECT * FROM claims")]
    by = {s: {"count": 0, "claimed": 0.0} for s in STATUSES}
    for x in cl:
        b = by.setdefault(x["status"], {"count": 0, "claimed": 0.0}); b["count"] += 1; b["claimed"] += x["claimed_amount"] or 0
    decided = [x for x in cl if x["status"] in ("Approved", "Rejected", "Paid")]
    rej = [x for x in cl if x["status"] == "Rejected"]
    cats = {}
    for x in rej: cats[x["rejection_category"] or "Other"] = cats.get(x["rejection_category"] or "Other", 0) + 1
    ins = {}
    for x in cl:
        i = ins.setdefault(x["insurer"] or "?", {"claims": 0, "rejected": 0, "claimed": 0.0, "paid": 0.0})
        i["claims"] += 1; i["claimed"] += x["claimed_amount"] or 0; i["paid"] += x["paid_amount"] or 0
        i["rejected"] += x["status"] == "Rejected"
    disc = []; outstanding = 0.0; today = dt.date.today()
    for x in cl:
        ap, pd, cm = x["approved_amount"], x["paid_amount"] or 0, x["claimed_amount"] or 0
        if x["status"] in ("Approved", "Paid") and ap is not None:
            outstanding += max(ap - pd, 0)
            if abs(ap - pd) > 0.005 and x["status"] == "Paid":
                disc.append({"claim_no": x["claim_no"], "insurer": x["insurer"], "issue": "Paid differs from approved", "claimed": cm, "approved": ap, "paid": pd, "variance": round(pd - ap, 2)})
            elif x["status"] == "Approved" and pd == 0:
                disc.append({"claim_no": x["claim_no"], "insurer": x["insurer"], "issue": "Approved, no payment received", "claimed": cm, "approved": ap, "paid": 0, "variance": round(-ap, 2)})
            if ap < cm - 0.005 and x["status"] == "Paid" and abs(ap - pd) <= 0.005:
                disc.append({"claim_no": x["claim_no"], "insurer": x["insurer"], "issue": "Approved below claimed (adjustment)", "claimed": cm, "approved": ap, "paid": pd, "variance": round(ap - cm, 2)})
        sd = pdate(x["submitted_date"])
        if x["status"] in ("Submitted", "Under review") and sd and (today - sd).days > 60:
            outstanding += cm
            disc.append({"claim_no": x["claim_no"], "insurer": x["insurer"], "issue": f"Awaiting decision {(today - sd).days} days", "claimed": cm, "approved": None, "paid": 0, "variance": None})
    first_pass = [x for x in decided if x["status"] != "Rejected"]
    return {"total_claims": len(cl), "by_status": by,
            "rejection_rate": round(len(rej) / len(decided) * 100, 1) if decided else 0,
            "first_pass_acceptance": round(len(first_pass) / len(decided) * 100, 1) if decided else 0,
            "total_claimed": sum(x["claimed_amount"] or 0 for x in cl), "total_paid": sum(x["paid_amount"] or 0 for x in cl),
            "outstanding": round(outstanding, 2), "rejection_categories": cats, "by_insurer": ins, "discrepancies": disc,
            "flagged_drafts": sum(1 for x in cl if x["status"] in ("Draft", "Rejected") and json.loads(x["flags"] or "[]"))}

def seed(c):
    """Synthetic demo data only - never put real patient data in a demo."""
    random.seed(7); tar = {"G001": 120, "G002": 250, "G003": 80, "G004": 600, "G005": 45}
    for ins in ("NHIA", "Acme Private Insurance"):
        for k, v in tar.items(): c.execute("INSERT OR REPLACE INTO tariffs(insurer,code,amount) VALUES(?,?,?)", (ins, k, v))
    reasons = ["Missing documentation: lab report not attached", "Member eligibility expired", "Tariff exceeds approved rate",
               "Duplicate claim already processed", "Invalid diagnosis code", "Submitted after deadline"]
    rows = ["claim_no,insurer,patient_ref,service_date,service_code,description,claimed_amount,submitted_date,status,approved_amount,paid_amount,rejection_reason"]
    for i in range(1, 61):
        ins = random.choice(["NHIA", "NHIA", "Acme Private Insurance"]); code = random.choice(list(tar)); amt = tar[code]
        sd = dt.date.today() - dt.timedelta(days=random.randint(5, 150)); st = random.choice(STATUSES)
        if random.random() < .2: amt += 30
        ap = pd = rr = ""; sub = ""
        if st != "Draft": sub = (sd + dt.timedelta(days=3)).isoformat()
        if st == "Rejected": rr = random.choice(reasons)
        if st in ("Approved", "Paid"): ap = amt if random.random() > .25 else round(amt * .85, 2)
        if st == "Paid": pd = ap if random.random() > .2 else round(ap * .9, 2)
        pat = f"PT{random.randint(100, 140)}" if i != 60 else "PT101"
        rows.append(f"CLM{1000+i},{ins},{'' if i == 7 else pat},{sd},{code},Consultation/service,{amt},{sub},{st},{ap},{pd},{rr}")
    rows.append("CLM2000,NHIA,PT900,2026-10-01,G001,Dup test,120,,Draft,,,"); rows.append("CLM2001,NHIA,PT900,2026-10-01,G001,Dup test,120,,Draft,,,")
    return import_claims(c, "\n".join(rows))

class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def send(self, obj, code=200, extra=None):
        b = json.dumps(obj, default=str).encode(); self.send_response(code)
        self.send_header("Content-Type", "application/json"); self.send_header("Content-Length", str(len(b)))
        for k, v in (extra or {}).items(): self.send_header(k, v)
        self.end_headers(); self.wfile.write(b)
    def user(self, c):
        m = re.search(r"hci=([0-9a-f]+)", self.headers.get("Cookie", ""))
        if not m: return None
        return c.execute("SELECT u.* FROM sessions s JOIN users u ON u.id=s.user_id WHERE token=?", (m.group(1),)).fetchone()
    def body(self):
        n = int(self.headers.get("Content-Length", 0)); raw = self.rfile.read(n).decode() if n else ""
        try: return json.loads(raw) if raw else {}
        except Exception: return {}
    def do_GET(self): self.route("GET")
    def do_POST(self): self.route("POST")
    def do_PATCH(self): self.route("PATCH")
    def route(self, m):
        path = self.path.split("?")[0]
        if not path.startswith("/api/"):
            f = "index.html" if path in ("/", "") else path.lstrip("/")
            fp = os.path.normpath(os.path.join(STATIC, f))
            if not fp.startswith(STATIC) or not os.path.isfile(fp): return self.send({"error": "not found"}, 404)
            data = open(fp, "rb").read(); self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8" if fp.endswith(".html") else "application/octet-stream")
            self.send_header("Content-Length", str(len(data))); self.end_headers(); return self.wfile.write(data)
        c = conn()
        try:
            b = self.body()
            if path == "/api/login" and m == "POST":
                u = c.execute("SELECT * FROM users WHERE username=?", (b.get("username", ""),)).fetchone()
                if not u or not secrets.compare_digest(u["pw"], hpw(b.get("password", ""), u["salt"])):
                    return self.send({"error": "Invalid credentials"}, 401)
                t = secrets.token_hex(24); c.execute("INSERT INTO sessions VALUES(?,?,?)", (t, u["id"], now()))
                c.execute("INSERT INTO audit(ts,user,action,detail) VALUES(?,?,?,?)", (now(), u["username"], "login", "")); c.commit()
                return self.send({"username": u["username"], "role": u["role"]}, extra={"Set-Cookie": f"hci={t}; HttpOnly; SameSite=Strict; Path=/"})
            u = self.user(c)
            if not u: return self.send({"error": "Login required"}, 401)
            role = u["role"]; can_write = role in ("admin", "officer")
            def log(a, d=""): c.execute("INSERT INTO audit(ts,user,action,detail) VALUES(?,?,?,?)", (now(), u["username"], a, d)); c.commit()
            def need(ok):
                if not ok: self.send({"error": "Not permitted for your role"}, 403)
                return ok
            if path == "/api/me": return self.send({"username": u["username"], "role": role})
            if path == "/api/logout": c.execute("DELETE FROM sessions WHERE user_id=?", (u["id"],)); c.commit(); return self.send({"ok": 1})
            if path == "/api/claims" and m == "GET":
                return self.send([dict(r, flags=json.loads(r["flags"] or "[]")) for r in c.execute("SELECT * FROM claims ORDER BY id DESC")])
            if path == "/api/claims/import" and m == "POST":
                if not need(can_write): return
                r = import_claims(c, b.get("csv", "")); c.commit(); log("import_claims", json.dumps(r)); return self.send(r)
            if path == "/api/claims/validate" and m == "POST":
                if not need(can_write): return
                n = validate_all(c); c.commit(); log("validate", f"{n} claims checked"); return self.send({"checked": n})
            mm = re.fullmatch(r"/api/claims/(\d+)", path)
            if mm and m == "PATCH":
                if not need(can_write): return
                cur = c.execute("SELECT * FROM claims WHERE id=?", (mm.group(1),)).fetchone()
                if not cur: return self.send({"error": "not found"}, 404)
                st = b.get("status", cur["status"])
                if st not in STATUSES: return self.send({"error": "bad status"}, 400)
                reason = b.get("rejection_reason", cur["rejection_reason"])
                if st == "Rejected" and not reason: return self.send({"error": "Rejection reason required"}, 400)
                sub = cur["submitted_date"] or (now()[:10] if st == "Submitted" else None)
                c.execute("UPDATE claims SET status=?,approved_amount=?,paid_amount=?,rejection_reason=?,rejection_category=?,submitted_date=? WHERE id=?",
                          (st, num(b["approved_amount"]) if b.get("approved_amount") not in (None, "") else cur["approved_amount"],
                           num(b["paid_amount"]) if b.get("paid_amount") not in (None, "") else cur["paid_amount"],
                           reason, categorise(reason), sub, cur["id"]))
                c.commit(); log("update_claim", f"{cur['claim_no']}: {cur['status']} -> {st}"); return self.send({"ok": 1})
            if path == "/api/dashboard": return self.send(dashboard(c))
            if path == "/api/rules" and m == "GET": return self.send([dict(r) for r in c.execute("SELECT * FROM rules")])
            mm = re.fullmatch(r"/api/rules/(\d+)/toggle", path)
            if mm and m == "POST":
                if not need(role == "admin"): return
                c.execute("UPDATE rules SET active=1-active, version=version+1 WHERE id=?", (mm.group(1),)); c.commit(); log("toggle_rule", mm.group(1)); return self.send({"ok": 1})
            if path == "/api/rules" and m == "POST":
                if not need(role == "admin"): return
                c.execute("INSERT INTO rules(type,insurer,param,source,effective_date) VALUES(?,?,?,?,?)",
                          (b.get("type"), b.get("insurer", "*"), b.get("param", ""), b.get("source", ""), now()[:10])); c.commit(); log("add_rule", json.dumps(b)); return self.send({"ok": 1})
            if path == "/api/tariffs" and m == "GET": return self.send([dict(r) for r in c.execute("SELECT * FROM tariffs ORDER BY insurer,code")])
            if path == "/api/tariffs/import" and m == "POST":
                if not need(role == "admin"): return
                r = import_tariffs(c, b.get("csv", "")); c.commit(); log("import_tariffs", json.dumps(r)); return self.send(r)
            if path == "/api/seed" and m == "POST":
                if not need(role == "admin"): return
                r = seed(c); c.commit(); log("seed_demo", "synthetic data"); return self.send(r)
            if path == "/api/audit": 
                if not need(role == "admin"): return
                return self.send([dict(r) for r in c.execute("SELECT * FROM audit ORDER BY id DESC LIMIT 200")])
            if path == "/api/export" and m == "GET": return self.send([dict(r) for r in c.execute("SELECT * FROM claims")])
            self.send({"error": "not found"}, 404)
        finally: c.close()

if __name__ == "__main__":
    init(); print(f"HCI running on http://localhost:{PORT}  (admin / admin123 - change HCI_ADMIN_PW)")
    ThreadingHTTPServer(("0.0.0.0", PORT), H).serve_forever()
