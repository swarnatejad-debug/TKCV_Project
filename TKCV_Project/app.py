import math, os, random, re, secrets, smtplib, sqlite3, time
from datetime import datetime
from email.message import EmailMessage
from functools import wraps

from flask import (Flask, abort, flash, g, redirect, render_template,
                   request, session, url_for)
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer
from werkzeug.security import check_password_hash, generate_password_hash

BASE = os.path.dirname(os.path.abspath(__file__))
app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.getenv("SECRET_KEY", "dev-only-change-me"),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
)
DB_PATH = os.getenv("DATABASE", os.path.join(BASE, "exam.db"))
GMAIL_RE = re.compile(r"^[a-z0-9._%+-]+@gmail\.com$")
tokens = URLSafeTimedSerializer(app.config["SECRET_KEY"])


# ---------- database ----------
def db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


@app.teardown_appcontext
def close_db(_):
    conn = g.pop("db", None)
    if conn:
        conn.close()


def init_db():
    conn = sqlite3.connect(DB_PATH)
    with open(os.path.join(BASE, "schema.sql")) as f:
        conn.executescript(f.read())
    conn.close()


# ---------- security helpers ----------
@app.before_request
def csrf_protect():
    if request.method == "POST":
        sent = request.form.get("csrf_token", "")
        if not session.get("_csrf") or not secrets.compare_digest(session["_csrf"], sent):
            abort(400, "Form expired. Go back, reload the page and try again.")


@app.context_processor
def inject():
    session.setdefault("_csrf", secrets.token_hex(16))
    return {"csrf_token": session["_csrf"]}


@app.template_filter("when")
def when(ts):
    return datetime.fromtimestamp(ts).strftime("%d %b %Y, %H:%M") if ts else "-"


FAILS = {}  # login throttle: key -> (count, last_time)


def locked(key):
    n, t = FAILS.get(key, (0, 0))
    if n >= 5 and time.time() - t > 300:
        FAILS.pop(key, None)
        return False
    return n >= 5


def admin_required(f):
    @wraps(f)
    def wrapper(*a, **k):
        if "admin_id" not in session:
            return redirect(url_for("admin_login"))
        return f(*a, **k)
    return wrapper


def own_exam(exam_id):
    exam = db().execute("SELECT * FROM exams WHERE id=? AND admin_id=?",
                        (exam_id, session["admin_id"])).fetchone()
    if not exam:
        abort(404)
    return exam


def send_mail(to, subject, body):
    user, pw = os.getenv("GMAIL_USER"), os.getenv("GMAIL_APP_PASSWORD")
    if not (user and pw):  # dev mode: print instead of sending
        print(f"\n[DEV MAIL to {to}] {subject}\n{body}\n", flush=True)
        return
    msg = EmailMessage()
    msg["From"], msg["To"], msg["Subject"] = user, to, subject
    msg.set_content(body)
    with smtplib.SMTP_SSL("smtp.gmail.com", 465) as s:
        s.login(user, pw)
        s.send_message(msg)


# ---------- manual questions ----------
def parse_manual(text):
    """Questions pasted by the admin. Blocks separated by a blank line:
    Q: question / A) .. B) .. C) .. D) .. / Answer: B"""
    out = []
    for num, block in enumerate(re.split(r"\n\s*\n", text.replace("\r", "").strip()), 1):
        lines = [l.strip() for l in block.split("\n") if l.strip()]
        opts, ans, q = {}, None, []
        for l in lines:
            m = re.match(r"^\(?([A-Da-d])[\).:]\s*(.+)$", l)
            a = re.match(r"^answer\s*[:\-]?\s*\(?([A-Da-d])", l, re.I)
            if a:
                ans = a.group(1).upper()
            elif m and not ans:
                opts[m.group(1).upper()] = m.group(2).strip()
            elif not opts:
                q.append(re.sub(r"^(q(uestion)?\s*\d*\s*[:.)-]|\d+[.)])\s*", "", l, flags=re.I))
        if not q or sorted(opts) != list("ABCD") or not ans:
            raise ValueError(f"Question {num} needs a question line, options A-D and an 'Answer: X' line.")
        out.append({"text": " ".join(q), "opts": [opts[k] for k in "ABCD"], "correct": ans})
    return out


def score_bins(scores, total, parts=5):
    step = max(1, math.ceil(total / parts))
    n = max(1, math.ceil(total / step))
    labels = [f"{0 if i == 0 else i * step + 1}-{min((i + 1) * step, total)}" for i in range(n)]
    counts = [0] * n
    for s in scores:
        counts[0 if s <= 0 else min((s - 1) // step, n - 1)] += 1
    return labels, counts


# ---------- public ----------
@app.route("/")
def home():
    return render_template("home.html")


# ---------- admin auth ----------
@app.route("/admin/register", methods=["GET", "POST"])
def admin_register():
    invite = os.getenv("ADMIN_SIGNUP_CODE")
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        pw, pw2 = request.form.get("password", ""), request.form.get("confirm", "")
        err = None
        if not GMAIL_RE.match(email):
            err = "Use a Gmail address ending in @gmail.com."
        elif len(pw) < 8:
            err = "Password must be at least 8 characters."
        elif pw != pw2:
            err = "Passwords do not match."
        elif invite and not secrets.compare_digest(request.form.get("invite", "").encode(), invite.encode()):
            err = "Invite code is incorrect."
        elif db().execute("SELECT 1 FROM admins WHERE email=?", (email,)).fetchone():
            err = "That Gmail is already registered."
        if err:
            flash(err, "error")
        else:
            db().execute("INSERT INTO admins(email, password_hash, created_at) VALUES(?,?,?)",
                         (email, generate_password_hash(pw), int(time.time())))
            db().commit()
            flash("Account created. Sign in to continue.", "ok")
            return redirect(url_for("admin_login"))
    return render_template("admin_register.html", needs_code=bool(invite))


@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        key = f"{request.remote_addr}:{email}"
        if locked(key):
            flash("Too many attempts. Try again in 5 minutes.", "error")
        else:
            row = db().execute("SELECT * FROM admins WHERE email=?", (email,)).fetchone()
            if row and check_password_hash(row["password_hash"], request.form.get("password", "")):
                FAILS.pop(key, None)
                session.clear()
                session["admin_id"], session["admin_email"] = row["id"], row["email"]
                return redirect(url_for("dashboard"))
            n, _ = FAILS.get(key, (0, 0))
            FAILS[key] = (n + 1, time.time())
            flash("Gmail or password is incorrect.", "error")
    return render_template("admin_login.html")


@app.route("/admin/logout", methods=["POST"])
def admin_logout():
    session.clear()
    return redirect(url_for("home"))


@app.route("/admin/forgot", methods=["GET", "POST"])
def admin_forgot():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        row = db().execute("SELECT * FROM admins WHERE email=?", (email,)).fetchone()
        if row:
            tok = tokens.dumps({"id": row["id"], "h": row["password_hash"][-12:]}, salt="reset")
            link = (os.getenv("BASE_URL") or request.host_url.rstrip("/")) + url_for("admin_reset", token=tok)
            send_mail(email, "Reset your TKCV Exams password",
                      f"Open this link within 30 minutes to set a new password:\n{link}\n\n"
                      "If you did not ask for this, ignore this email.")
        flash("If that Gmail is registered, a reset link is on its way.", "ok")
        return redirect(url_for("admin_login"))
    return render_template("admin_forgot.html")


@app.route("/admin/reset/<token>", methods=["GET", "POST"])
def admin_reset(token):
    try:
        data = tokens.loads(token, salt="reset", max_age=1800)
    except (BadSignature, SignatureExpired):
        flash("This reset link is invalid or has expired.", "error")
        return redirect(url_for("admin_forgot"))
    row = db().execute("SELECT * FROM admins WHERE id=?", (data["id"],)).fetchone()
    if not row or row["password_hash"][-12:] != data["h"]:  # link already used
        flash("This reset link has already been used.", "error")
        return redirect(url_for("admin_forgot"))
    if request.method == "POST":
        pw, pw2 = request.form.get("password", ""), request.form.get("confirm", "")
        if len(pw) < 8 or pw != pw2:
            flash("Passwords must match and be at least 8 characters.", "error")
        else:
            db().execute("UPDATE admins SET password_hash=? WHERE id=?",
                         (generate_password_hash(pw), row["id"]))
            db().commit()
            flash("Password updated. Sign in with the new one.", "ok")
            return redirect(url_for("admin_login"))
    return render_template("admin_reset.html")


# ---------- admin: exams ----------
@app.route("/admin")
@admin_required
def dashboard():
    exams = db().execute(
        "SELECT e.*, (SELECT COUNT(*) FROM attempts a WHERE a.exam_id=e.id AND a.submitted_at IS NOT NULL) AS done "
        "FROM exams e WHERE admin_id=? ORDER BY e.id DESC", (session["admin_id"],)).fetchall()
    return render_template("dashboard.html", exams=exams)


@app.route("/admin/exam/new", methods=["GET", "POST"])
@admin_required
def exam_new():
    if request.method == "POST":
        f = request.form
        title = " ".join(f.get("title", "").split())[:200]
        code = f.get("subject_code", "").strip().upper()
        try:
            marks, mins = int(f.get("marks")), int(f.get("minutes"))
        except (TypeError, ValueError):
            marks = mins = 0
        qs, err = [], None
        if f.get("manual", "").strip():
            try:
                qs = parse_manual(f["manual"])
            except ValueError as e:
                err = str(e)
        if err:
            pass
        elif len(title) < 3:
            err = "Enter an exam title."
        elif not re.fullmatch(r"[A-Z0-9_-]{2,20}", code):
            err = "Subject code: 2-20 letters, numbers, - or _."
        elif not (1 <= marks <= 5 and 5 <= mins <= 180):
            err = "Marks per question 1-5, time 5-180 minutes."
        elif len(qs) > 50:
            err = "An exam can have at most 50 questions."
        elif db().execute("SELECT 1 FROM exams WHERE subject_code=?", (code,)).fetchone():
            err = "That subject code is already used."
        if err:
            flash(err, "error")
            return render_template("exam_new.html", form=f)
        cur = db().execute(
            "INSERT INTO exams(admin_id, topic, subject_code, num_questions, marks_per_q, duration_min, is_active, created_at) "
            "VALUES(?,?,?,?,?,?,1,?)", (session["admin_id"], title, code, len(qs), marks, mins, int(time.time())))
        db().executemany(
            "INSERT INTO questions(exam_id, text, opt_a, opt_b, opt_c, opt_d, correct) VALUES(?,?,?,?,?,?,?)",
            [(cur.lastrowid, q["text"], *q["opts"], q["correct"]) for q in qs])
        db().commit()
        if not qs:
            flash("Exam created. Add your questions below.", "ok")
        return redirect(url_for("exam_detail", exam_id=cur.lastrowid))
    return render_template("exam_new.html", form={})


@app.route("/admin/exam/<int:exam_id>")
@admin_required
def exam_detail(exam_id):
    import qrcode, qrcode.image.svg
    exam = own_exam(exam_id)
    qs = db().execute("SELECT * FROM questions WHERE exam_id=? ORDER BY id", (exam_id,)).fetchall()
    link = (os.getenv("BASE_URL") or request.host_url.rstrip("/")) + url_for("student_login", code=exam["subject_code"])
    qr = qrcode.make(link, image_factory=qrcode.image.svg.SvgPathImage, box_size=10, border=2)
    return render_template("exam_detail.html", exam=exam, qs=qs, link=link, locked=has_attempts(exam_id),
                           qr=qr.to_string(encoding="unicode"))


def sync_count(exam_id):
    db().execute("UPDATE exams SET num_questions=(SELECT COUNT(*) FROM questions WHERE exam_id=?) WHERE id=?",
                 (exam_id, exam_id))


def has_attempts(exam_id):
    return db().execute("SELECT 1 FROM attempts WHERE exam_id=?", (exam_id,)).fetchone() is not None


@app.route("/admin/exam/<int:exam_id>/question/add", methods=["POST"])
@admin_required
def question_add(exam_id):
    own_exam(exam_id)
    f = request.form
    text = " ".join(f.get("text", "").split())[:500]
    opts = [" ".join(f.get(k, "").split())[:200] for k in ("a", "b", "c", "d")]
    if has_attempts(exam_id):
        flash("Students have already joined, so questions can't change.", "error")
    elif not text or not all(opts) or f.get("correct") not in ("A", "B", "C", "D"):
        flash("Fill in the question, all four options and the correct answer.", "error")
    elif db().execute("SELECT COUNT(*) FROM questions WHERE exam_id=?", (exam_id,)).fetchone()[0] >= 50:
        flash("An exam can have at most 50 questions.", "error")
    else:
        db().execute("INSERT INTO questions(exam_id, text, opt_a, opt_b, opt_c, opt_d, correct) VALUES(?,?,?,?,?,?,?)",
                     (exam_id, text, *opts, f["correct"]))
        sync_count(exam_id)
        db().commit()
        flash("Question added.", "ok")
    return redirect(url_for("exam_detail", exam_id=exam_id))


@app.route("/admin/question/<int:q_id>/delete", methods=["POST"])
@admin_required
def question_delete(q_id):
    q = db().execute("SELECT q.exam_id FROM questions q JOIN exams e ON e.id=q.exam_id "
                     "WHERE q.id=? AND e.admin_id=?", (q_id, session["admin_id"])).fetchone()
    if not q:
        abort(404)
    if has_attempts(q["exam_id"]):
        flash("Students have already joined, so questions can't change.", "error")
    else:
        db().execute("DELETE FROM questions WHERE id=?", (q_id,))
        sync_count(q["exam_id"])
        db().commit()
        flash("Question deleted.", "ok")
    return redirect(url_for("exam_detail", exam_id=q["exam_id"]))


@app.route("/admin/exam/<int:exam_id>/toggle", methods=["POST"])
@admin_required
def exam_toggle(exam_id):
    exam = own_exam(exam_id)
    db().execute("UPDATE exams SET is_active=? WHERE id=?", (0 if exam["is_active"] else 1, exam_id))
    db().commit()
    return redirect(url_for("exam_detail", exam_id=exam_id))


@app.route("/admin/exam/<int:exam_id>/delete", methods=["POST"])
@admin_required
def exam_delete(exam_id):
    own_exam(exam_id)
    db().execute("DELETE FROM exams WHERE id=?", (exam_id,))
    db().commit()
    flash("Exam deleted.", "ok")
    return redirect(url_for("dashboard"))


@app.route("/admin/exam/<int:exam_id>/results")
@admin_required
def exam_results(exam_id):
    exam = own_exam(exam_id)
    total = exam["num_questions"] * exam["marks_per_q"]
    rows = db().execute(
        "SELECT * FROM attempts WHERE exam_id=? ORDER BY submitted_at IS NULL, score DESC, name", (exam_id,)).fetchall()
    scores = [r["score"] for r in rows if r["submitted_at"]]
    labels, counts = score_bins(scores, total)
    stats = {"done": len(scores), "started": len(rows),
             "avg": round(sum(scores) / len(scores), 1) if scores else 0,
             "high": max(scores) if scores else 0}
    return render_template("results.html", exam=exam, rows=rows, total=total,
                           labels=labels, counts=counts, stats=stats)


@app.route("/admin/attempt/<int:attempt_id>/delete", methods=["POST"])
@admin_required
def attempt_delete(attempt_id):
    a = db().execute("SELECT a.exam_id FROM attempts a JOIN exams e ON e.id=a.exam_id "
                     "WHERE a.id=? AND e.admin_id=?", (attempt_id, session["admin_id"])).fetchone()
    if not a:
        abort(404)
    db().execute("DELETE FROM attempts WHERE id=?", (attempt_id,))
    db().commit()
    flash("Attempt removed. The student can log in again.", "ok")
    return redirect(url_for("exam_results", exam_id=a["exam_id"]))


# ---------- student ----------
@app.route("/student/login", methods=["GET", "POST"])
def student_login():
    if request.method == "POST":
        f = request.form
        name = " ".join(f.get("name", "").split())[:80]
        usn = f.get("usn", "").strip().upper()
        roll = f.get("roll_no", "").strip()[:20]
        phone = f.get("phone", "").strip()
        code = f.get("subject_code", "").strip().upper()
        err = exam = None
        if len(name) < 2:
            err = "Enter your full name."
        elif not re.fullmatch(r"[A-Z0-9]{5,20}", usn):
            err = "USN should be 5-20 letters and numbers."
        elif not roll:
            err = "Enter your roll number."
        elif not re.fullmatch(r"\d{10}", phone):
            err = "Phone number should be 10 digits."
        else:
            exam = db().execute("SELECT * FROM exams WHERE subject_code=?", (code,)).fetchone()
            if not exam or not exam["is_active"]:
                err = "No open exam found for that subject code."
            elif exam["num_questions"] < 1:
                err = "This exam has no questions yet."
        if not err:
            try:
                cur = db().execute(
                    "INSERT INTO attempts(exam_id, name, usn, roll_no, phone, started_at, score) VALUES(?,?,?,?,?,?,0)",
                    (exam["id"], name, usn, roll, phone, int(time.time())))
                db().commit()
                session.clear()
                session["attempt_id"] = cur.lastrowid
                return redirect(url_for("student_exam"))
            except sqlite3.IntegrityError:
                err = "This USN has already taken this exam. Ask your admin to reset it."
        flash(err, "error")
        return render_template("student_login.html", form=f, code=code)
    return render_template("student_login.html", form={}, code=request.args.get("code", "").upper()[:20])


def current_attempt():
    aid = session.get("attempt_id")
    if not aid:
        return None
    return db().execute(
        "SELECT a.*, e.topic, e.subject_code, e.num_questions, e.marks_per_q, e.duration_min "
        "FROM attempts a JOIN exams e ON e.id=a.exam_id WHERE a.id=?", (aid,)).fetchone()


@app.route("/student/exam")
def student_exam():
    a = current_attempt()
    if not a:
        return redirect(url_for("student_login"))
    if a["submitted_at"]:
        return redirect(url_for("student_result"))
    rows = db().execute("SELECT * FROM questions WHERE exam_id=?", (a["exam_id"],)).fetchall()
    qs = [{"id": r["id"], "text": r["text"],
           "options": list(zip("ABCD", (r["opt_a"], r["opt_b"], r["opt_c"], r["opt_d"])))} for r in rows]
    random.Random(a["id"]).shuffle(qs)  # same order on refresh, different per student
    remaining = max(0, a["duration_min"] * 60 - (int(time.time()) - a["started_at"]))
    return render_template("exam.html", a=a, qs=qs, remaining=remaining)


@app.route("/student/submit", methods=["POST"])
def student_submit():
    a = current_attempt()
    if not a:
        return redirect(url_for("student_login"))
    if a["submitted_at"]:
        return redirect(url_for("student_result"))
    late = int(time.time()) - a["started_at"] > a["duration_min"] * 60 + 60
    correct, picked = 0, []
    for q in db().execute("SELECT id, correct FROM questions WHERE exam_id=?", (a["exam_id"],)):
        ch = request.form.get(f"q{q['id']}", "")
        if ch in ("A", "B", "C", "D") and not late:
            picked.append((a["id"], q["id"], ch))
            correct += ch == q["correct"]
    db().executemany("INSERT INTO answers(attempt_id, question_id, chosen) VALUES(?,?,?)", picked)
    db().execute("UPDATE attempts SET submitted_at=?, score=? WHERE id=?",
                 (int(time.time()), correct * a["marks_per_q"], a["id"]))
    db().commit()
    return redirect(url_for("student_result"))


@app.route("/student/result")
def student_result():
    a = current_attempt()
    if not a:
        return redirect(url_for("student_login"))
    if not a["submitted_at"]:
        return redirect(url_for("student_exam"))
    total = a["num_questions"] * a["marks_per_q"]
    answered = db().execute("SELECT COUNT(*) FROM answers WHERE attempt_id=?", (a["id"],)).fetchone()[0]
    right = a["score"] // a["marks_per_q"]
    return render_template("result.html", a=a, total=total, pct=round(a["score"] * 100 / total, 1),
                           right=right, wrong=answered - right, skipped=a["num_questions"] - answered)


@app.route("/student/finish", methods=["POST"])
def student_finish():
    session.clear()
    return redirect(url_for("home"))


init_db()

if __name__ == "__main__":
    # host 0.0.0.0 lets phones on the same Wi-Fi scan the QR code; set BASE_URL to your PC's address
    app.run(host="0.0.0.0", port=5000, debug=os.getenv("FLASK_DEBUG") == "1")
