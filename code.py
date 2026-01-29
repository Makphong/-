from fastapi import FastAPI, HTTPException, Header, Request, Form, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from jose import jwt, JWTError
from passlib.context import CryptContext
from starlette.status import HTTP_303_SEE_OTHER
import sqlite3
import time
import uuid
import json
from pathlib import Path
from datetime import datetime

# ======================
# CONFIG
# ======================
SECRET_KEY = "supersecretkey"
ALGORITHM = "HS256"
SESSION_SECONDS = 60 * 60  # 1 hour

BASE_DIR = Path(__file__).resolve().parent
UPLOAD_DIR = BASE_DIR / "static" / "uploads"
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

MAX_FILES = 3
MAX_SIZE_PER_FILE = 10 * 1024 * 1024  # 10MB
ALLOWED_EXTS = {".jpg", ".jpeg", ".png", ".mp4"}

app = FastAPI()

# ======================
# CORS
# ======================
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ======================
# STATIC + TEMPLATES
# ======================
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))
app.mount("/static",
          StaticFiles(directory=str(BASE_DIR / "static")),
          name="static")


# ======================
# DATABASE
# ======================
def db():
    conn = sqlite3.connect(str(BASE_DIR / "complaints.db"))
    conn.row_factory = sqlite3.Row
    return conn


def ensure_schema():
    conn = db()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT,
            role TEXT
        )
        """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS complaints (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            location TEXT,
            description TEXT,
            status TEXT,
            created_at REAL
        )
        """)
    conn.commit()

    existing_cols = [
        r["name"]
        for r in conn.execute("PRAGMA table_info(complaints)").fetchall()
    ]
    add_cols = [
        ("item_type", "TEXT"),
        ("building", "TEXT"),
        ("floor", "TEXT"),
        ("room", "TEXT"),
        ("attachments", "TEXT"),
    ]
    for col, coltype in add_cols:
        if col not in existing_cols:
            conn.execute(f"ALTER TABLE complaints ADD COLUMN {col} {coltype}")
    conn.commit()


ensure_schema()

# ======================
# PASSWORD HASHING
# ======================
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)


def get_user(username: str):
    conn = db()
    row = conn.execute(
        "SELECT username, password, role FROM users WHERE username = ?",
        (username, ),
    ).fetchone()
    return dict(row) if row else None


# ======================
# SEED USERS (idempotent)
# ======================
def seed_user(username: str, password: str, role: str):
    conn = db()
    try:
        conn.execute(
            "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
            (username, hash_password(password), role),
        )
        conn.commit()
    except Exception:
        pass


seed_user("admin", "admin123", "admin")
seed_user("user", "user123", "user")


# ======================
# JWT HELPERS
# ======================
def create_token(username: str, role: str) -> str:
    now = int(time.time())
    payload = {
        "sub": username,
        "role": role,
        "iat": now,
        "exp": now + SESSION_SECONDS,  # 1 hour expiry
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def decode_token(token: str) -> dict:
    try:
        return jwt.decode(token, SECRET_KEY,
                          algorithms=[ALGORITHM])  # validates exp
    except JWTError:
        raise HTTPException(401, "Invalid or expired token")


def get_current_user(request: Request, authorization: str | None) -> dict:
    token = None
    if authorization and authorization.startswith("Bearer "):
        token = authorization.split(" ", 1)[1]
    else:
        token = request.cookies.get("access_token")

    if not token:
        raise HTTPException(401, "Not authenticated")

    return decode_token(token)


def fmt_th_date(ts: float | None) -> str:
    if not ts:
        return "-"
    dt = datetime.fromtimestamp(ts)
    return dt.strftime("%d/%m/%Y %H:%M")


# ======================
# FILE UPLOAD HELPERS
# ======================
def _validate_ext(filename: str) -> str:
    ext = Path(filename).suffix.lower()
    if ext == ".jpeg":
        ext = ".jpg"
    if ext not in ALLOWED_EXTS:
        raise HTTPException(400, "ไฟล์ต้องเป็น .jpg .png .mp4 เท่านั้น")
    return ext


async def save_upload_file(username: str, file: UploadFile) -> str:
    ext = _validate_ext(file.filename)
    user_dir = UPLOAD_DIR / username
    user_dir.mkdir(parents=True, exist_ok=True)

    safe_name = f"{int(time.time())}_{uuid.uuid4().hex}{ext}"
    dest_path = user_dir / safe_name

    size = 0
    try:
        with open(dest_path, "wb") as out:
            while True:
                chunk = await file.read(1024 * 1024)
                if not chunk:
                    break
                size += len(chunk)
                if size > MAX_SIZE_PER_FILE:
                    raise HTTPException(400, "ไฟล์ต้องไม่เกิน 10MB ต่อไฟล์")
                out.write(chunk)
    except HTTPException:
        if dest_path.exists():
            dest_path.unlink(missing_ok=True)
        raise

    return f"/static/uploads/{username}/{safe_name}"


# ======================
# SECURITY / ROLE GUARD (Fix Back cross-role)
# ======================
PUBLIC_PATHS = {"/", "/login", "/login-system", "/logout"}


def _is_static(path: str) -> bool:
    return path.startswith("/static")


def _no_store(resp: Response) -> Response:
    resp.headers[
        "Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    resp.headers["Pragma"] = "no-cache"
    resp.headers["Expires"] = "0"
    return resp


def _redirect(url: str) -> RedirectResponse:
    resp = RedirectResponse(url, status_code=HTTP_303_SEE_OTHER)
    return _no_store(resp)


def _logout_redirect() -> RedirectResponse:
    resp = RedirectResponse("/login", status_code=HTTP_303_SEE_OTHER)
    resp.delete_cookie("access_token")
    resp.delete_cookie("logged_in")
    resp.delete_cookie("user_role")
    return _no_store(resp)


@app.middleware("http")
async def role_guard_middleware(request: Request, call_next):
    path = request.url.path

    if _is_static(path):
        return await call_next(request)

    # Root redirect is handled by route, but keep safe
    if path == "/":
        return _redirect("/login")

    # Public paths allowed without auth
    if path in PUBLIC_PATHS:
        resp = await call_next(request)
        return _no_store(resp)

    # Any other route requires auth
    token = request.cookies.get("access_token")
    if not token:
        return _logout_redirect()

    try:
        user = decode_token(token)
    except HTTPException:
        return _logout_redirect()

    role = user.get("role")

    # Role-based routing guard
    if path.startswith("/admin") and role != "admin":
        return _redirect("/user/send")
    if path.startswith("/user") and role != "user":
        return _redirect("/admin")

    resp = await call_next(request)
    return _no_store(resp)


# ======================
# ROUTES
# ======================
@app.get("/", response_class=HTMLResponse)
def root():
    return _redirect("/login")


@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request, authorization: str | None = Header(None)):
    # If logged in, redirect to correct home
    token = request.cookies.get("access_token")
    if token:
        try:
            user = decode_token(token)
            if user.get("role") == "admin":
                return _redirect("/admin")
            if user.get("role") == "user":
                return _redirect("/user/send")
        except Exception:
            pass

    error = request.query_params.get("error")
    resp = templates.TemplateResponse("login.html", {
        "request": request,
        "error": error
    })
    return _no_store(resp)


@app.get("/logout")
def logout():
    return _logout_redirect()


@app.post("/login-system")
def login_system(
        request: Request,
        username: str = Form(...),
        password: str = Form(...),
):
    user = get_user(username)
    if not user or not verify_password(password, user["password"]):
        return _redirect("/login?error=1")

    token = create_token(user["username"], user["role"])
    redirect_to = "/admin/dashboard" if user[
        "role"] == "admin" else "/user/send"

    resp = RedirectResponse(url=redirect_to, status_code=HTTP_303_SEE_OTHER)

    # token cookie (persist 1 hour)
    resp.set_cookie(
        "access_token",
        token,
        httponly=True,
        samesite="lax",
        max_age=SESSION_SECONDS,
    )
    # readable cookies for client-side guard
    resp.set_cookie("logged_in",
                    "1",
                    httponly=False,
                    samesite="lax",
                    max_age=SESSION_SECONDS)
    resp.set_cookie(
        "user_role",
        user["role"],
        httponly=False,
        samesite="lax",
        max_age=SESSION_SECONDS,
    )

    return _no_store(resp)


# backward compatible routes
@app.get("/complaints")
def complaints_redirect():
    return _redirect("/user/send")


@app.get("/status")
def status_redirect():
    return _redirect("/user/track")


# ======================
# USER DASHBOARD: SEND TAB
# ======================
@app.get("/user/send", response_class=HTMLResponse)
def user_send_page(request: Request, authorization: str | None = Header(None)):
    user = get_current_user(request, authorization)
    if user.get("role") != "user":
        return _redirect("/admin")

    submitted = request.query_params.get("submitted")
    resp = templates.TemplateResponse(
        "user_send.html",
        {
            "request": request,
            "username": user["sub"],
            "submitted": submitted
        },
    )
    return _no_store(resp)


# ======================
# USER DASHBOARD: TRACK TAB
# ======================
@app.get("/user/track", response_class=HTMLResponse)
def user_track_page(request: Request,
                    authorization: str | None = Header(None)):
    user = get_current_user(request, authorization)
    if user.get("role") != "user":
        return _redirect("/admin")

    conn = db()
    rows = conn.execute(
        """
    SELECT id, created_at, location, status
    FROM complaints
    WHERE username = ?
    ORDER BY created_at DESC
    """,
        (user["sub"], ),
    ).fetchall()

    complaints = []
    for r in rows:
        d = dict(r)
        d["created_at_fmt"] = fmt_th_date(d.get("created_at"))
        d["username"] = user["sub"]
        complaints.append(d)

    resp = templates.TemplateResponse(
        "user_track.html",
        {
            "request": request,
            "username": user["sub"],
            "complaints": complaints
        },
    )
    return _no_store(resp)


# ======================
# USER: DETAIL
# ======================
@app.get("/user/complaint/{complaint_id}/detail")
def user_complaint_detail_json(request: Request,
                               complaint_id: int,
                               authorization: str | None = Header(None)):
    user = get_current_user(request, authorization)
    if user.get("role") != "user":
        return _redirect("/admin")

    conn = db()
    row = conn.execute(
        "SELECT * FROM complaints WHERE id = ? AND username = ?",
        (complaint_id, user["sub"]),
    ).fetchone()

    if not row:
        raise HTTPException(404, "Not found")

    c = dict(row)
    c["created_at_fmt"] = fmt_th_date(c.get("created_at"))

    try:
        attachments_list = json.loads(c.get("attachments") or "[]")
    except Exception:
        attachments_list = []

    # ส่งเฉพาะที่ UI ใช้
    return {
        "id": c.get("id"),
        "created_at_fmt": c.get("created_at_fmt"),
        "username": c.get("username"),
        "location": c.get("location"),
        "status": c.get("status"),
        "item_type": c.get("item_type"),
        "description": c.get("description"),
        "attachments": attachments_list,
    }


@app.get("/user/complaint/{complaint_id}", response_class=HTMLResponse)
def user_complaint_detail(request: Request,
                          complaint_id: int,
                          authorization: str | None = Header(None)):
    user = get_current_user(request, authorization)
    if user.get("role") != "user":
        return _redirect("/admin")

    conn = db()
    row = conn.execute(
        "SELECT * FROM complaints WHERE id = ? AND username = ?",
        (complaint_id, user["sub"]),
    ).fetchone()
    if not row:
        raise HTTPException(404, "Not found")

    c = dict(row)
    c["created_at_fmt"] = fmt_th_date(c.get("created_at"))
    try:
        c["attachments_list"] = json.loads(c.get("attachments") or "[]")
    except Exception:
        c["attachments_list"] = []

    resp = templates.TemplateResponse("user_detail.html", {
        "request": request,
        "username": user["sub"],
        "c": c
    })
    return _no_store(resp)


# ======================
# SUBMIT COMPLAINT (with files) + building order
# ======================
@app.post("/submit-complaint")
async def submit_complaint(
        request: Request,
        item_type: str = Form(...),
        building: str = Form(...),
        floor: str = Form(...),
        room: str = Form(...),
        description: str = Form(...),
        files: list[UploadFile] = File(default=[]),
        authorization: str | None = Header(None),
):
    user = get_current_user(request, authorization)
    if user.get("role") != "user":
        return _redirect("/admin")

    if files and len(files) > MAX_FILES:
        raise HTTPException(400, "แนบไฟล์ได้สูงสุด 3 ไฟล์")

    saved_paths = []
    for f in files:
        if not f.filename:
            continue
        saved_paths.append(await save_upload_file(user["sub"], f))

    location_text = f"{building} - {floor} - {room}"

    conn = db()
    conn.execute(
        """
        INSERT INTO complaints (username, location, description, status, created_at, item_type, building, floor, room, attachments)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            user["sub"],
            location_text,
            description,
            "รอดำเนินการ",
            time.time(),
            item_type,
            building,
            floor,
            room,
            json.dumps(saved_paths, ensure_ascii=False),
        ),
    )
    conn.commit()

    return _redirect("/user/send?submitted=1")


# ======================
# ADMIN
# ======================
@app.get("/admin")
def admin_root():
    return _redirect("/admin/dashboard")


@app.get("/admin/dashboard", response_class=HTMLResponse)
def admin_dashboard_page(request: Request,
                         authorization: str | None = Header(None)):
    user = get_current_user(request, authorization)
    if user.get("role") != "admin":
        return _redirect("/user/send")

    resp = templates.TemplateResponse("admin_dashboard.html", {
        "request": request,
        "username": user["sub"]
    })
    return _no_store(resp)


@app.get("/admin/complaints", response_class=HTMLResponse)
def admin_complaints_page(request: Request,
                          authorization: str | None = Header(None)):
    user = get_current_user(request, authorization)
    if user.get("role") != "admin":
        return _redirect("/user/send")

    conn = db()
    rows = conn.execute(
        "SELECT * FROM complaints ORDER BY created_at DESC").fetchall()

    complaints = []
    for r in rows:
        d = dict(r)
        d["created_at_fmt"] = fmt_th_date(d.get("created_at"))
        try:
            d["attachments_list"] = json.loads(d.get("attachments") or "[]")
        except Exception:
            d["attachments_list"] = []
        complaints.append(d)

    resp = templates.TemplateResponse(
        "admin.html",
        {
            "request": request,
            "username": user["sub"],
            "complaints": complaints
        },
    )
    return _no_store(resp)


@app.post("/admin/update-status")
def admin_update_status(
        request: Request,
        complaint_id: int = Form(...),
        status: str = Form(...),
        authorization: str | None = Header(None),
):
    user = get_current_user(request, authorization)
    if user.get("role") != "admin":
        return _redirect("/user/send")

    conn = db()
    conn.execute("UPDATE complaints SET status = ? WHERE id = ?",
                 (status, complaint_id))
    conn.commit()

    return _redirect("/admin/complaints")


@app.get("/admin/complaints")
def admin_view_complaints(request: Request,
                          authorization: str | None = Header(None)):
    user = get_current_user(request, authorization)
    if user.get("role") != "admin":
        raise HTTPException(403, "Admins only")

    conn = db()
    rows = conn.execute(
        "SELECT * FROM complaints ORDER BY created_at DESC").fetchall()
    return [dict(r) for r in rows]


@app.get("/admin/complaint/{complaint_id}/detail")
def admin_complaint_detail_json(request: Request,
                                complaint_id: int,
                                authorization: str | None = Header(None)):
    user = get_current_user(request, authorization)
    if user.get("role") != "admin":
        raise HTTPException(403, "Admins only")

    conn = db()
    row = conn.execute(
        "SELECT * FROM complaints WHERE id = ?",
        (complaint_id, ),
    ).fetchone()

    if not row:
        raise HTTPException(404, "Not found")

    c = dict(row)
    c["created_at_fmt"] = fmt_th_date(c.get("created_at"))

    try:
        attachments_list = json.loads(c.get("attachments") or "[]")
    except Exception:
        attachments_list = []

    return {
        "id": c.get("id"),
        "created_at_fmt": c.get("created_at_fmt"),
        "username": c.get("username"),
        "location": c.get("location"),
        "status": c.get("status"),
        "item_type": c.get("item_type"),
        "description": c.get("description"),
        "attachments": attachments_list,
    }


def _range_to_days(r: str) -> int:
    r = (r or "week").lower()
    if r == "week":
        return 7
    if r == "month":
        return 30
    if r in ("3month", "three_month", "quarter"):
        return 90
    if r == "year":
        return 365
    return 7


def _start_ts_days(days: int) -> float:
    return time.time() - (days * 24 * 60 * 60)


def _parse_building_from_location(loc: str) -> str:
    if not loc:
        return "-"
    if " - " in loc:
        return loc.split(" - ")[0].strip()
    return loc.strip()


@app.get("/admin/dashboard/summary")
def admin_dashboard_summary(request: Request,
                            range: str = "week",
                            authorization: str | None = Header(None)):
    user = get_current_user(request, authorization)
    if user.get("role") != "admin":
        raise HTTPException(403, "Admins only")

    days = _range_to_days(range)
    start_ts = _start_ts_days(days)

    conn = db()

    # today count (นับวันนี้ตั้งแต่ 00:00)
    now = datetime.now()
    today_start = datetime(now.year, now.month, now.day).timestamp()

    today_count = conn.execute(
        "SELECT COUNT(*) AS c FROM complaints WHERE created_at >= ?",
        (today_start, ),
    ).fetchone()["c"]

    # unresolved total (ไม่เสร็จสิ้น และไม่ยกเลิก)
    unresolved_total = conn.execute(
        """
        SELECT COUNT(*) AS c
        FROM complaints
        WHERE status NOT IN ('เสร็จสิ้น', 'ยกเลิก')
        """, ).fetchone()["c"]

    # series: counts per day within range
    rows = conn.execute(
        """
        SELECT strftime('%Y-%m-%d', datetime(created_at, 'unixepoch', 'localtime')) AS d,
               COUNT(*) AS c
        FROM complaints
        WHERE created_at >= ?
        GROUP BY d
        ORDER BY d ASC
        """,
        (start_ts, ),
    ).fetchall()

    series = [{"date": r["d"], "count": r["c"]} for r in rows]

    # build daily map for locations (for candlestick)
    loc_rows = conn.execute(
        """
        SELECT strftime('%Y-%m-%d', datetime(created_at, 'unixepoch', 'localtime')) AS d,
               COALESCE(building, '') AS building,
               COALESCE(location, '') AS location,
               COUNT(*) AS c
        FROM complaints
        WHERE created_at >= ?
        GROUP BY d, building, location
        ORDER BY d ASC
        """,
        (start_ts, ),
    ).fetchall()

    # collect all dates in range (based on series span; if empty, still return empty)
    dates = [s["date"] for s in series]
    date_set = set(dates)

    # build location -> date -> count
    loc_map = {}
    for r in loc_rows:
        b = (r["building"] or "").strip()
        if not b:
            b = _parse_building_from_location(r["location"])
        if not b:
            b = "-"
        d = r["d"]
        if d not in date_set:
            # ถ้า series ไม่มีวันนั้น (rare) ก็ยังเก็บไว้
            date_set.add(d)
        loc_map.setdefault(b, {})
        loc_map[b][d] = loc_map[b].get(d, 0) + int(r["c"])

    dates_sorted = sorted(list(date_set))
    if not dates_sorted:
        dates_sorted = []

    # candlestick data: x=building, y=[open, high, low, close]
    candles = []
    for b, day_counts in loc_map.items():
        counts = [day_counts.get(d, 0)
                  for d in dates_sorted] if dates_sorted else []
        if not counts:
            continue
        open_v = counts[0]
        close_v = counts[-1]
        high_v = max(counts)
        low_v = min(counts)
        candles.append({"x": b, "y": [open_v, high_v, low_v, close_v]})

    return {
        "range": range,
        "today_count": today_count,
        "unresolved_total": unresolved_total,
        "series": series,
        "candles": candles,
        "dates": dates_sorted,
    }


@app.get("/admin/dashboard/location-breakdown")
def admin_dashboard_location_breakdown(
        request: Request,
        range: str,
        building: str,
        authorization: str | None = Header(None),
):
    user = get_current_user(request, authorization)
    if user.get("role") != "admin":
        raise HTTPException(403, "Admins only")

    days = _range_to_days(range)
    start_ts = _start_ts_days(days)

    conn = db()
    rows = conn.execute(
        """
        SELECT COALESCE(item_type, '-') AS item_type,
               COUNT(*) AS c
        FROM complaints
        WHERE created_at >= ?
          AND (COALESCE(building,'') = ? OR (COALESCE(building,'')='' AND COALESCE(location,'') LIKE ?))
        GROUP BY item_type
        ORDER BY c DESC
        """,
        (start_ts, building, f"{building}%"),
    ).fetchall()

    return {
        "building": building,
        "range": range,
        "items": [{
            "item_type": r["item_type"],
            "count": r["c"]
        } for r in rows],
    }
