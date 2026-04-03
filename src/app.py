"""
Sizzle API — Lightweight handler for Cloudflare Workers Python.
No FastAPI/Pydantic to stay under the 1000ms startup CPU limit.
Uses only: json, uuid, secrets, httpx, jwt (PyJWT).
"""
import json
import re
import secrets
import string
import uuid
from datetime import datetime, timedelta, timezone
from workers import Response


# ── Helpers ─────────────────────────────────────────────────

# _cors_req will be set per-request so helpers can read the origin
_cors_req = None

def _cors():
    origin = ""
    if _cors_req:
        origin = _cors_req.headers.get("origin", "")
    allow = origin if origin in ALLOWED_ORIGINS else ALLOWED_ORIGINS[0]
    return {"Access-Control-Allow-Origin": allow, "Access-Control-Allow-Methods": "GET,POST,PUT,DELETE,OPTIONS", "Access-Control-Allow-Headers": "Content-Type,Authorization", "Access-Control-Allow-Credentials": "true"}

def _json(data, status=200):
    h = {"Content-Type": "application/json", **_cors()}
    return Response(json.dumps(data, default=str), status=status, headers=h)


def _err(msg, status=400):
    return _json({"detail": msg}, status)


async def _body(request):
    try:
        text = await request.text()
        return json.loads(text) if text else {}
    except Exception:
        return {}


def _qs(request):
    """Parse query string params from URL."""
    url = request.url
    if "?" not in url:
        return {}
    qs = url.split("?", 1)[1]
    params = {}
    for part in qs.split("&"):
        if "=" in part:
            k, v = part.split("=", 1)
            params[k] = v
    return params


# ── Supabase client (inline, no separate module needed) ─────

class DB:
    def __init__(self, url, key):
        self.base = f"{url}/rest/v1"
        self.headers = {
            "apikey": key,
            "Authorization": f"Bearer {key}",
            "Content-Type": "application/json",
            "Prefer": "return=representation",
        }

    async def select(self, table, columns="*", filters=None, order=None,
                     limit=None, offset=None, single=False):
        import httpx
        params = {"select": columns}
        if filters:
            params.update(filters)
        if order:
            params["order"] = order
        if limit:
            params["limit"] = str(limit)
        if offset:
            params["offset"] = str(offset)
        h = {**self.headers}
        if single:
            h["Accept"] = "application/vnd.pgrst.object+json"
        async with httpx.AsyncClient() as c:
            r = await c.get(f"{self.base}/{table}", headers=h, params=params)
            if r.status_code == 406 and single:
                return None
            r.raise_for_status()
            return r.json()

    async def insert(self, table, data):
        import httpx
        async with httpx.AsyncClient() as c:
            r = await c.post(f"{self.base}/{table}", headers=self.headers, json=data)
            r.raise_for_status()
            return r.json()

    async def update(self, table, data, filters):
        import httpx
        async with httpx.AsyncClient() as c:
            r = await c.patch(f"{self.base}/{table}", headers=self.headers,
                              json=data, params=filters)
            r.raise_for_status()
            return r.json()

    async def delete(self, table, filters):
        import httpx
        async with httpx.AsyncClient() as c:
            r = await c.delete(f"{self.base}/{table}", headers=self.headers,
                               params=filters)
            r.raise_for_status()

    async def count(self, table, filters=None):
        import httpx
        h = {**self.headers, "Prefer": "count=exact", "Range-Unit": "items", "Range": "0-0"}
        params = {"select": "id"}
        if filters:
            params.update(filters)
        async with httpx.AsyncClient() as c:
            r = await c.get(f"{self.base}/{table}", headers=h, params=params)
            r.raise_for_status()
            cr = r.headers.get("content-range", "*/0")
            total = cr.split("/")[-1]
            return int(total) if total != "*" else 0


# ── Auth helpers ────────────────────────────────────────────

def _gen_otp():
    return "".join([str(secrets.randbelow(10)) for _ in range(6)])


async def _store_otp(kv, ident, otp, ttl=300):
    await kv.put(f"otp:{ident}", otp, expirationTtl=ttl)


async def _verify_otp(kv, ident, otp):
    import hmac
    stored = await kv.get(f"otp:{ident}")
    if stored and hmac.compare_digest(str(stored), otp):
        await kv.delete(f"otp:{ident}")
        return True
    return False


async def _rate_limit(kv, ident):
    key = f"otp_rate:{ident}"
    c = await kv.get(key)
    count = int(c) if c else 0
    if count >= 5:
        return False
    await kv.put(key, str(count + 1), expirationTtl=300)
    return True


def _mk_token(uid, role, secret, days):
    import jwt
    return jwt.encode({"sub": uid, "role": role, "type": "access" if days == 7 else "refresh",
                        "exp": datetime.now(timezone.utc) + timedelta(days=days),
                        "iat": datetime.now(timezone.utc)}, secret, algorithm="HS256")


def _decode(token, secret):
    import jwt as pyjwt
    try:
        return pyjwt.decode(token, secret, algorithms=["HS256"])
    except Exception:
        return None


async def _get_user(request, db, secret):
    auth = request.headers.get("authorization", "")
    if not auth.startswith("Bearer "):
        return None
    p = _decode(auth[7:], secret)
    if not p or p.get("type") != "access":
        return None
    u = await db.select("users", filters={"id": f"eq.{p['sub']}"}, single=True)
    if not u or not u.get("is_active", True):
        return None
    return u


async def _require(request, env, role=None):
    db = DB(str(env.SUPABASE_URL), str(env.SUPABASE_SERVICE_ROLE_KEY))
    secret = str(env.JWT_SECRET_KEY)
    user = await _get_user(request, db, secret)
    if not user:
        return None, None, None, _err("Invalid or expired token", 401)
    if role and user.get("role") != role:
        return None, None, None, _err(f"{role} access required", 403)
    return user, db, secret, None


async def _send_email(api_key, from_addr, to, otp):
    if not api_key:
        return True
    import httpx
    try:
        async with httpx.AsyncClient() as c:
            r = await c.post("https://api.resend.com/emails",
                             headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
                             json={"from": from_addr, "to": [to],
                                   "subject": f"Your Sizzle verification code: {otp}",
                                   "html": f"<h2>Your Sizzle OTP</h2><p style='font-size:32px;font-weight:bold;letter-spacing:8px;'>{otp}</p><p>Valid for 5 minutes. Never share this code.</p>"})
            return r.status_code == 200
    except Exception:
        return True


# ── Generators ──────────────────────────────────────────────

def _ref():
    return "SZ-" + "".join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(8))

def _refcode(name):
    p = (name or "SZ")[:4].upper().replace(" ", "")
    return p + "".join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(6))

def _gccode():
    return "SZ-" + "".join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(10))


# ── Static data ─────────────────────────────────────────────

CUISINES = ["north_indian","south_indian","chinese","italian","continental","thai","japanese","mexican","mediterranean","mughlai","street_food","desserts","beverages","fusion"]

OCCASIONS = {"house_party":{"name":"House Party","icon":"🏠"},"birthday":{"name":"Birthday","icon":"🎂"},"anniversary":{"name":"Anniversary","icon":"💍"},"date_night":{"name":"Date Night","icon":"💕"},"family_dinner":{"name":"Family Dinner","icon":"👨‍👩‍👧"},"pooja":{"name":"Pooja","icon":"🙏"},"general":{"name":"General","icon":"🍽️"}}

PLANS = {"monthly":{"name":"Monthly","price":299,"discount_pct":10,"credits":100,"days":30},"quarterly":{"name":"Quarterly","price":749,"discount_pct":15,"credits":300,"days":90},"yearly":{"name":"Yearly","price":2499,"discount_pct":20,"credits":1000,"days":365}}

LEVELS = {1:"Foodie",2:"Gourmet",3:"Connoisseur",4:"Master Chef",5:"Legend"}
THRESHOLDS = {1:0,2:200,3:500,4:1000,5:2500}
BADGES = {"first_booking":{"name":"First Bite","icon":"🍽️"},"first_review":{"name":"Critic","icon":"⭐"},"gold_member":{"name":"Gold Member","icon":"👑"},"referrer":{"name":"Ambassador","icon":"🤝"}}

THEMES = [{"id":"birthday","name":"Birthday","icon":"🎂"},{"id":"anniversary","name":"Anniversary","icon":"💍"},{"id":"thank_you","name":"Thank You","icon":"🙏"},{"id":"congrats","name":"Congratulations","icon":"🎉"},{"id":"love","name":"With Love","icon":"❤️"}]


# ── Wallet / Gamification helpers ───────────────────────────

async def _get_wallet(db, uid):
    w = await db.select("wallets", filters={"user_id": f"eq.{uid}"}, single=True)
    if not w:
        w = (await db.insert("wallets", {"id": str(uuid.uuid4()), "user_id": uid, "balance": 0, "total_earned": 0, "total_spent": 0}))[0]
    return w

async def _credit(db, uid, amt, reason, desc, ref_id=None):
    w = await _get_wallet(db, uid)
    await db.update("wallets", {"balance": w["balance"] + amt, "total_earned": w["total_earned"] + amt}, {"id": f"eq.{w['id']}"})
    await db.insert("wallet_transactions", {"id": str(uuid.uuid4()), "wallet_id": w["id"], "user_id": uid, "type": "credit", "amount": amt, "reason": reason, "description": desc, "reference_id": ref_id})

async def _get_gam(db, uid):
    g = await db.select("gamification_profiles", filters={"user_id": f"eq.{uid}"}, single=True)
    if not g:
        g = (await db.insert("gamification_profiles", {"id": str(uuid.uuid4()), "user_id": uid, "points": 0, "level": 1, "badges": [], "total_bookings_count": 0, "streak_count": 0, "total_spent": 0}))[0]
    return g

def _gam_resp(g):
    lv = g.get("level", 1)
    pts = g.get("points", 0)
    nxt = min(lv + 1, 5)
    prog = min(100, int((pts - THRESHOLDS.get(lv, 0)) / max(1, THRESHOLDS.get(nxt, 2500) - THRESHOLDS.get(lv, 0)) * 100))
    return {"points": pts, "level": lv, "level_name": LEVELS.get(lv, "Foodie"), "progress_pct": prog, "next_level_points": THRESHOLDS.get(nxt, 2500), "badges": g.get("badges", []), "total_bookings_count": g.get("total_bookings_count", 0), "streak_count": g.get("streak_count", 0)}


# ── CORS ────────────────────────────────────────────────────

ALLOWED_ORIGINS = ["https://www.sizzzle.me","https://sizzzle.me","https://sizzleapp.pages.dev","capacitor://localhost","http://localhost","http://localhost:5173","http://localhost:8000"]


# ── Router ──────────────────────────────────────────────────

ROUTES = []

def route(method, pattern):
    """Register a route. Pattern uses {param} syntax."""
    regex = re.compile("^" + re.sub(r"\{(\w+)\}", r"(?P<\1>[^/]+)", pattern) + "$")
    def decorator(fn):
        ROUTES.append((method, regex, fn))
        return fn
    return decorator


async def handle_request(request, env):
    global _cors_req
    _cors_req = request

    # CORS preflight
    if request.method == "OPTIONS":
        return Response("", status=204, headers=_cors())

    path = "/" + request.url.split("//", 1)[1].split("/", 1)[1].split("?")[0] if "//" in request.url else request.url.split("?")[0]

    for method, regex, handler in ROUTES:
        if request.method == method:
            m = regex.match(path)
            if m:
                try:
                    return await handler(request, env, **m.groupdict())
                except Exception as e:
                    return _err(str(e), 500)

    return _err("Not found", 404)
    return r


# ══════════════════════════════════════════════════════════════
# ROUTES
# ══════════════════════════════════════════════════════════════

@route("GET", "/")
async def root(req, env):
    return _json({"status": "healthy", "app": "Sizzle", "version": "1.0.0"})

@route("GET", "/api/v1/health")
async def health(req, env):
    return _json({"status": "healthy"})

# ── AUTH ────────────────────────────────────────────────────

@route("POST", "/api/v1/auth/send-otp")
async def send_otp(req, env):
    d = await _body(req)
    ident = d.get("email") or d.get("phone")
    if not ident:
        return _err("Email or phone required")
    kv = env.OTP_STORE
    if not await _rate_limit(kv, ident):
        return _err("Too many OTP requests. Try again in 5 minutes.", 429)
    otp = _gen_otp()
    await _store_otp(kv, ident, otp)
    if d.get("email"):
        rk = str(getattr(env, "RESEND_API_KEY", ""))
        ef = str(getattr(env, "EMAIL_FROM", "Sizzle <onboarding@resend.dev>"))
        await _send_email(rk, ef, d["email"], otp)
    return _json({"message": "OTP sent successfully", "identifier": ident})

@route("POST", "/api/v1/auth/verify-otp")
async def verify_otp_ep(req, env):
    d = await _body(req)
    ident = d.get("email") or d.get("phone")
    if not ident:
        return _err("Email or phone required")
    kv = env.OTP_STORE
    db = DB(str(env.SUPABASE_URL), str(env.SUPABASE_SERVICE_ROLE_KEY))
    if not await _verify_otp(kv, ident, d.get("otp", "")):
        return _err("Invalid or expired OTP")
    filters = {"email": f"eq.{d['email']}"} if d.get("email") else {"phone": f"eq.{d['phone']}"}
    user = await db.select("users", filters=filters, single=True)
    is_new = False
    if not user:
        is_new = True
        ud = {"id": str(uuid.uuid4()), "role": "customer", "is_active": True, "is_gold": False}
        if d.get("email"): ud["email"] = d["email"]
        if d.get("phone"): ud["phone"] = d["phone"]
        user = (await db.insert("users", ud))[0]
    secret = str(env.JWT_SECRET_KEY)
    return _json({"access_token": _mk_token(user["id"], user["role"], secret, 7), "refresh_token": _mk_token(user["id"], user["role"], secret, 30), "user_role": user["role"], "is_new_user": is_new})

@route("POST", "/api/v1/auth/refresh")
async def refresh(req, env):
    d = await _body(req)
    secret = str(env.JWT_SECRET_KEY)
    p = _decode(d.get("refresh_token", ""), secret)
    if not p or p.get("type") != "refresh":
        return _err("Invalid refresh token", 401)
    db = DB(str(env.SUPABASE_URL), str(env.SUPABASE_SERVICE_ROLE_KEY))
    user = await db.select("users", filters={"id": f"eq.{p['sub']}"}, single=True)
    if not user:
        return _err("User not found", 401)
    return _json({"access_token": _mk_token(user["id"], user["role"], secret, 7), "refresh_token": _mk_token(user["id"], user["role"], secret, 30), "user_role": user["role"]})

# ── CUSTOMER ────────────────────────────────────────────────

@route("GET", "/api/v1/customer/profile")
async def get_profile(req, env):
    u, db, s, err = await _require(req, env)
    if err: return err
    return _json(u)

@route("PUT", "/api/v1/customer/profile")
async def update_profile(req, env):
    u, db, s, err = await _require(req, env)
    if err: return err
    d = await _body(req)
    upd = {k: v for k, v in d.items() if k in ("name", "phone", "dob", "avatar_url") and v is not None}
    if not upd:
        return _json(u)
    r = await db.update("users", upd, {"id": f"eq.{u['id']}"})
    return _json(r[0] if r else u)

@route("GET", "/api/v1/customer/addresses")
async def list_addrs(req, env):
    u, db, s, err = await _require(req, env)
    if err: return err
    return _json(await db.select("addresses", filters={"user_id": f"eq.{u['id']}"}, order="is_default.desc"))

@route("POST", "/api/v1/customer/addresses")
async def add_addr(req, env):
    u, db, s, err = await _require(req, env)
    if err: return err
    d = await _body(req)
    if d.get("is_default"):
        await db.update("addresses", {"is_default": False}, {"user_id": f"eq.{u['id']}", "is_default": "eq.true"})
    addr = {"id": str(uuid.uuid4()), "user_id": u["id"], **{k: d.get(k) for k in ("label","full_address","city","state","pincode","latitude","longitude","is_default")}}
    return _json((await db.insert("addresses", addr))[0], 201)

@route("POST", "/api/v1/customer/bookings")
async def create_booking(req, env):
    u, db, s, err = await _require(req, env, "customer")
    if err: return err
    d = await _body(req)
    addr = await db.select("addresses", filters={"id": f"eq.{d['address_id']}", "user_id": f"eq.{u['id']}"}, single=True)
    if not addr:
        return _err("Address not found")
    base = 399.0
    if d.get("chef_id"):
        cp = await db.select("chef_profiles", filters={"user_id": f"eq.{d['chef_id']}"}, single=True)
        if cp: base = cp.get("hourly_rate", 399.0)
    dur = d.get("duration_hours", 2)
    gc = d.get("guest_count", 2)
    chef_cost = base * dur
    guest_surcharge = max(0, gc - 4) * 49.0 * dur
    hr = int(d.get("time_slot", "12:00").split(":")[0])
    peak = 1.2 if 18 <= hr <= 21 else 1.0
    sub = (chef_cost + guest_surcharge) * peak
    pf = round(sub * 0.05, 2)
    gst = round((sub + pf) * 0.05, 2)
    total = round(sub + pf + gst, 2)
    bk = {"id": str(uuid.uuid4()), "customer_id": u["id"], "chef_id": d.get("chef_id"), "address_id": d["address_id"], "booking_date": d["booking_date"], "time_slot": d.get("time_slot"), "duration_hours": dur, "guest_count": gc, "occasion": d.get("occasion", "general"), "cuisine_preferences": d.get("cuisine_preferences"), "selected_dishes": d.get("selected_dishes"), "menu_package_id": d.get("menu_package_id"), "add_ons": d.get("add_ons"), "special_requests": d.get("special_requests"), "total_amount": total, "wallet_amount_used": 0, "discount_amount": 0, "status": "pending", "booking_ref": _ref(), "rating_submitted": False}
    r = (await db.insert("bookings", bk))[0]
    r["customer_name"] = u.get("name")
    r["address_text"] = addr.get("full_address")
    return _json(r, 201)

@route("GET", "/api/v1/customer/bookings")
async def list_bookings(req, env):
    u, db, s, err = await _require(req, env, "customer")
    if err: return err
    q = _qs(req)
    page = int(q.get("page", "1"))
    pp = int(q.get("per_page", "20"))
    total = await db.count("bookings", {"customer_id": f"eq.{u['id']}"})
    bks = await db.select("bookings", filters={"customer_id": f"eq.{u['id']}"}, order="created_at.desc", limit=pp, offset=(page - 1) * pp)
    return _json({"bookings": bks, "total": total, "page": page, "per_page": pp})

@route("GET", "/api/v1/customer/bookings/{bid}")
async def get_booking(req, env, bid=""):
    u, db, s, err = await _require(req, env, "customer")
    if err: return err
    b = await db.select("bookings", filters={"id": f"eq.{bid}", "customer_id": f"eq.{u['id']}"}, single=True)
    if not b: return _err("Booking not found", 404)
    return _json(b)

# ── MENU ────────────────────────────────────────────────────

@route("GET", "/api/v1/menu/cuisines")
async def cuisines(req, env):
    return _json([{"id": c, "name": c.replace("_", " ").title()} for c in CUISINES])

@route("GET", "/api/v1/menu/occasions")
async def occasions(req, env):
    return _json([{"id": k, **v} for k, v in OCCASIONS.items()])

@route("GET", "/api/v1/menu/dishes")
async def dishes(req, env):
    db = DB(str(env.SUPABASE_URL), str(env.SUPABASE_SERVICE_ROLE_KEY))
    q = _qs(req)
    f = {"is_available": "eq.true"}
    if q.get("cuisine"): f["cuisine"] = f"eq.{q['cuisine']}"
    if q.get("search"): f["name"] = f"ilike.*{q['search']}*"
    page = int(q.get("page", "1"))
    pp = int(q.get("per_page", "20"))
    total = await db.count("dishes", f)
    ds = await db.select("dishes", filters=f, order="is_signature.desc,created_at.desc", limit=pp, offset=(page - 1) * pp)
    return _json({"dishes": ds, "total": total, "page": page, "per_page": pp})

# ── WALLET ──────────────────────────────────────────────────

@route("GET", "/api/v1/wallet")
async def wallet(req, env):
    u, db, s, err = await _require(req, env)
    if err: return err
    return _json(await _get_wallet(db, u["id"]))

@route("GET", "/api/v1/wallet/transactions")
async def wallet_txns(req, env):
    u, db, s, err = await _require(req, env)
    if err: return err
    w = await _get_wallet(db, u["id"])
    q = _qs(req)
    lim = int(q.get("limit", "50"))
    txns = await db.select("wallet_transactions", filters={"user_id": f"eq.{u['id']}"}, order="created_at.desc", limit=lim)
    return _json({"transactions": txns, "balance": w["balance"], "total": len(txns)})

# ── GAMIFICATION ────────────────────────────────────────────

@route("GET", "/api/v1/gamification/profile")
async def gam_profile(req, env):
    u, db, s, err = await _require(req, env)
    if err: return err
    return _json(_gam_resp(await _get_gam(db, u["id"])))

@route("GET", "/api/v1/gamification/badges")
async def gam_badges(req, env):
    return _json([{"id": k, **v} for k, v in BADGES.items()])

@route("GET", "/api/v1/gamification/levels")
async def gam_levels(req, env):
    return _json([{"id": k, "name": v, "min_points": THRESHOLDS[k]} for k, v in LEVELS.items()])

# ── SUBSCRIPTION ────────────────────────────────────────────

@route("GET", "/api/v1/subscription/plans")
async def sub_plans(req, env):
    return _json([{"plan": k, **v, "features": [f"{v['discount_pct']}% off all bookings", f"₹{v['credits']} wallet credits", "Priority chef matching", "Exclusive gold member badges", "Free cancellation"]} for k, v in PLANS.items()])

@route("GET", "/api/v1/subscription")
async def sub_get(req, env):
    u, db, s, err = await _require(req, env)
    if err: return err
    subs = await db.select("subscriptions", filters={"user_id": f"eq.{u['id']}"}, order="created_at.desc", limit=1)
    if not subs:
        return _json({"active": False, "subscription": None})
    return _json({"active": subs[0].get("status") == "active", "subscription": subs[0]})

@route("POST", "/api/v1/subscription/subscribe")
async def sub_create(req, env):
    u, db, s, err = await _require(req, env)
    if err: return err
    d = await _body(req)
    plan = d.get("plan")
    if plan not in PLANS:
        return _err("Invalid plan")
    det = PLANS[plan]
    ex = await db.select("subscriptions", filters={"user_id": f"eq.{u['id']}", "status": "eq.active"}, single=True)
    if ex: return _err("You already have an active subscription")
    now = datetime.now(timezone.utc).isoformat()
    exp = (datetime.now(timezone.utc) + timedelta(days=det["days"])).isoformat()
    sub = {"id": str(uuid.uuid4()), "user_id": u["id"], "plan": plan, "status": "active", "price_paid": det["price"], "discount_pct": det["discount_pct"], "credits_granted": det["credits"], "starts_at": now, "expires_at": exp}
    r = await db.insert("subscriptions", sub)
    await db.update("users", {"is_gold": True}, {"id": f"eq.{u['id']}"})
    if det["credits"] > 0:
        await _credit(db, u["id"], det["credits"], "subscription_reward", f"Sizzle Gold {det['name']} credits")
    return _json({"message": f"Welcome to Sizzle Gold {det['name']}!", "subscription": r[0] if r else sub, "wallet_credits": det["credits"]})

@route("POST", "/api/v1/subscription/cancel")
async def sub_cancel(req, env):
    u, db, s, err = await _require(req, env)
    if err: return err
    subs = await db.select("subscriptions", filters={"user_id": f"eq.{u['id']}", "status": "eq.active"})
    if not subs: return _err("No active subscription found", 404)
    now = datetime.now(timezone.utc).isoformat()
    await db.update("subscriptions", {"status": "cancelled", "cancelled_at": now}, {"id": f"eq.{subs[0]['id']}"})
    await db.update("users", {"is_gold": False}, {"id": f"eq.{u['id']}"})
    return _json({"message": "Subscription cancelled. You'll retain benefits until expiry."})

# ── REVIEWS ─────────────────────────────────────────────────

@route("POST", "/api/v1/reviews")
async def submit_review(req, env):
    u, db, s, err = await _require(req, env)
    if err: return err
    d = await _body(req)
    bk = await db.select("bookings", filters={"id": f"eq.{d['booking_id']}"}, single=True)
    if not bk: return _err("Booking not found", 404)
    if bk["customer_id"] != u["id"]: return _err("Not your booking", 403)
    if bk.get("status") != "completed": return _err("Can only review completed bookings")
    existing = await db.select("reviews", filters={"booking_id": f"eq.{d['booking_id']}"}, single=True)
    if existing: return _err("Already reviewed")
    rv = {"id": str(uuid.uuid4()), "booking_id": d["booking_id"], "customer_id": u["id"], "chef_id": bk.get("chef_id"), "rating": d["rating"], "food_rating": d.get("food_rating"), "hygiene_rating": d.get("hygiene_rating"), "punctuality_rating": d.get("punctuality_rating"), "comment": d.get("comment"), "photo_urls": d.get("photo_urls")}
    await db.insert("reviews", rv)
    await db.update("bookings", {"rating_submitted": True}, {"id": f"eq.{d['booking_id']}"})
    g = await _get_gam(db, u["id"])
    badges = list(g.get("badges") or [])
    if "first_review" not in badges: badges.append("first_review")
    await db.update("gamification_profiles", {"points": g["points"] + 20, "badges": badges}, {"id": f"eq.{g['id']}"})
    return _json({"id": rv["id"], "rating": d["rating"], "message": "Thanks for your review! +20 points earned"}, 201)

# ── REFERRAL ────────────────────────────────────────────────

@route("GET", "/api/v1/referral")
async def referral_get(req, env):
    u, db, s, err = await _require(req, env)
    if err: return err
    ref = await db.select("referrals", filters={"referrer_id": f"eq.{u['id']}"}, single=True)
    if not ref:
        code = _refcode(u.get("name"))
        ref = (await db.insert("referrals", {"id": str(uuid.uuid4()), "referrer_id": u["id"], "referral_code": code, "total_referrals": 0, "total_earned": 0}))[0]
    convs = await db.select("referral_uses", filters={"referral_id": f"eq.{ref['id']}"})
    return _json({"referral_code": ref["referral_code"], "total_referrals": ref["total_referrals"], "total_earned": ref["total_earned"], "share_message": f"Use my code {ref['referral_code']} to get ₹100 off on Sizzle!", "conversions": convs})

@route("POST", "/api/v1/referral/apply")
async def referral_apply(req, env):
    u, db, s, err = await _require(req, env)
    if err: return err
    d = await _body(req)
    existing = await db.select("referral_uses", filters={"referred_user_id": f"eq.{u['id']}"}, single=True)
    if existing: return _err("You've already used a referral code")
    code = d.get("code", "").upper().strip()
    ref = await db.select("referrals", filters={"referral_code": f"eq.{code}"}, single=True)
    if not ref: return _err("Invalid referral code", 404)
    if ref["referrer_id"] == u["id"]: return _err("Can't use your own code")
    use = {"id": str(uuid.uuid4()), "referral_id": ref["id"], "referred_user_id": u["id"], "status": "completed", "referrer_reward": 150.0, "referee_discount": 100.0}
    await db.insert("referral_uses", use)
    await db.update("referrals", {"total_referrals": ref["total_referrals"] + 1, "total_earned": ref["total_earned"] + 150.0}, {"id": f"eq.{ref['id']}"})
    await _credit(db, ref["referrer_id"], 150.0, "referral_bonus", f"Referral bonus — someone joined!")
    await _credit(db, u["id"], 100.0, "referral_reward", f"Welcome bonus — referred by code {code}")
    await db.update("users", {"referred_by_code": code}, {"id": f"eq.{u['id']}"})
    return _json({"message": "Referral applied! ₹100 added to your wallet", "wallet_credit": 100.0})

# ── GIFT CARDS ──────────────────────────────────────────────

@route("GET", "/api/v1/gift-cards/themes")
async def gc_themes(req, env):
    return _json(THEMES)

@route("POST", "/api/v1/gift-cards")
async def gc_buy(req, env):
    u, db, s, err = await _require(req, env)
    if err: return err
    d = await _body(req)
    amt = d.get("amount", 0)
    if amt < 100 or amt > 25000: return _err("Amount must be ₹100 - ₹25,000")
    code = _gccode()
    exp = (datetime.now(timezone.utc) + timedelta(days=365)).isoformat()
    card = {"id": str(uuid.uuid4()), "purchaser_id": u["id"], "code": code, "amount": amt, "balance": amt, "recipient_name": d.get("recipient_name"), "recipient_email": d.get("recipient_email"), "message": d.get("message"), "theme": d.get("theme", "congrats"), "status": "active", "expires_at": exp}
    c = (await db.insert("gift_cards", card))[0]
    c["share_text"] = f"You've received a ₹{int(amt)} Sizzle Gift Card! Use code {code} to redeem."
    return _json(c, 201)

@route("POST", "/api/v1/gift-cards/redeem")
async def gc_redeem(req, env):
    u, db, s, err = await _require(req, env)
    if err: return err
    d = await _body(req)
    code = d.get("code", "").upper().strip()
    card = await db.select("gift_cards", filters={"code": f"eq.{code}"}, single=True)
    if not card: return _err("Invalid gift card code", 404)
    if card.get("status") != "active": return _err(f"Gift card is {card.get('status')}")
    if card.get("balance", 0) <= 0: return _err("Gift card has no balance")
    amt = card["balance"]
    await db.update("gift_cards", {"balance": 0, "status": "redeemed", "redeemed_by_id": u["id"]}, {"id": f"eq.{card['id']}"})
    await _credit(db, u["id"], amt, "gift_card_redeem", f"Gift card {code} redeemed", card["id"])
    return _json({"message": f"₹{int(amt)} added to your wallet!", "amount": amt})

@route("GET", "/api/v1/gift-cards/my-cards")
async def gc_mine(req, env):
    u, db, s, err = await _require(req, env)
    if err: return err
    return _json(await db.select("gift_cards", filters={"purchaser_id": f"eq.{u['id']}"}, order="created_at.desc"))

# ── PAYMENTS ────────────────────────────────────────────────

@route("POST", "/api/v1/payments/initiate")
async def pay(req, env):
    u, db, s, err = await _require(req, env, "customer")
    if err: return err
    d = await _body(req)
    bk = await db.select("bookings", filters={"id": f"eq.{d['booking_id']}"}, single=True)
    if not bk: return _err("Booking not found", 404)
    if bk["customer_id"] != u["id"]: return _err("Not your booking", 403)
    return _json({"success": True, "message": "Payment simulation — demo mode", "booking_id": d["booking_id"], "amount": bk.get("total_amount", 0)})

# ── CHEF ────────────────────────────────────────────────────

@route("GET", "/api/v1/chef/profile")
async def chef_profile(req, env):
    u, db, s, err = await _require(req, env, "chef")
    if err: return err
    p = await db.select("chef_profiles", filters={"user_id": f"eq.{u['id']}"}, single=True)
    av = await db.select("chef_availability", filters={"chef_profile_id": f"eq.{p['id']}"}) if p else []
    return _json({"user": u, "profile": p, "availability": av})

@route("PUT", "/api/v1/chef/profile")
async def chef_update(req, env):
    u, db, s, err = await _require(req, env, "chef")
    if err: return err
    d = await _body(req)
    p = await db.select("chef_profiles", filters={"user_id": f"eq.{u['id']}"}, single=True)
    upd = {k: v for k, v in d.items() if k in ("bio","specialties","experience_years","hourly_rate","is_verified","is_available") and v is not None}
    if not p:
        p = (await db.insert("chef_profiles", {"id": str(uuid.uuid4()), "user_id": u["id"], **upd}))[0]
    elif upd:
        r = await db.update("chef_profiles", upd, {"id": f"eq.{p['id']}"})
        p = r[0] if r else p
    av = await db.select("chef_availability", filters={"chef_profile_id": f"eq.{p['id']}"})
    return _json({"user": u, "profile": p, "availability": av})

@route("POST", "/api/v1/chef/availability")
async def chef_avail(req, env):
    u, db, s, err = await _require(req, env, "chef")
    if err: return err
    d = await _body(req)
    p = await db.select("chef_profiles", filters={"user_id": f"eq.{u['id']}"}, single=True)
    if not p: return _err("Chef profile not found", 404)
    slot = {"id": str(uuid.uuid4()), "chef_profile_id": p["id"], "day_of_week": d["day_of_week"], "start_time": d["start_time"], "end_time": d["end_time"], "is_available": d.get("is_available", True)}
    return _json((await db.insert("chef_availability", slot))[0], 201)

@route("DELETE", "/api/v1/chef/availability/{slot_id}")
async def chef_avail_del(req, env, slot_id=""):
    u, db, s, err = await _require(req, env, "chef")
    if err: return err
    p = await db.select("chef_profiles", filters={"user_id": f"eq.{u['id']}"}, single=True)
    if not p: return _err("Chef profile not found", 404)
    await db.delete("chef_availability", {"id": f"eq.{slot_id}", "chef_profile_id": f"eq.{p['id']}"})
    return Response("", status=204, headers=_cors())

@route("GET", "/api/v1/chef/bookings")
async def chef_bookings(req, env):
    u, db, s, err = await _require(req, env, "chef")
    if err: return err
    q = _qs(req)
    f = {"chef_id": f"eq.{u['id']}"}
    if q.get("status"): f["status"] = f"eq.{q['status']}"
    page = int(q.get("page", "1"))
    pp = int(q.get("per_page", "20"))
    total = await db.count("bookings", f)
    bks = await db.select("bookings", filters=f, order="created_at.desc", limit=pp, offset=(page - 1) * pp)
    return _json({"bookings": bks, "total": total, "page": page, "per_page": pp})

@route("PUT", "/api/v1/chef/bookings/{bid}/status")
async def chef_bk_status(req, env, bid=""):
    u, db, s, err = await _require(req, env, "chef")
    if err: return err
    d = await _body(req)
    bk = await db.select("bookings", filters={"id": f"eq.{bid}", "chef_id": f"eq.{u['id']}"}, single=True)
    if not bk: return _err("Booking not found", 404)
    upd = {"status": d["status"]}
    if d.get("chef_notes"): upd["chef_notes"] = d["chef_notes"]
    r = await db.update("bookings", upd, {"id": f"eq.{bid}"})
    return _json(r[0] if r else bk)

# ── ADMIN ───────────────────────────────────────────────────

@route("GET", "/api/v1/admin/stats")
async def admin_stats(req, env):
    u, db, s, err = await _require(req, env, "admin")
    if err: return err
    tc = await db.count("users", {"role": "eq.customer"})
    th = await db.count("users", {"role": "eq.chef"})
    tb = await db.count("bookings")
    pend = await db.count("bookings", {"status": "eq.pending"})
    conf = await db.count("bookings", {"status": "eq.confirmed"})
    comp = await db.count("bookings", {"status": "eq.completed"})
    canc = await db.count("bookings", {"status": "eq.cancelled"})
    al = await db.count("locations", {"is_serviceable": "eq.true"})
    cb = await db.select("bookings", columns="total_amount", filters={"status": "eq.completed"})
    rev = sum(float(b.get("total_amount", 0)) for b in cb)
    return _json({"total_users": tc + th, "total_customers": tc, "total_chefs": th, "total_bookings": tb, "pending_bookings": pend, "confirmed_bookings": conf, "completed_bookings": comp, "cancelled_bookings": canc, "total_revenue": rev, "active_locations": al})

@route("GET", "/api/v1/admin/chefs")
async def admin_chefs(req, env):
    u, db, s, err = await _require(req, env, "admin")
    if err: return err
    chefs = await db.select("users", filters={"role": "eq.chef"}, order="created_at.desc")
    result = []
    for ch in chefs:
        p = await db.select("chef_profiles", filters={"user_id": f"eq.{ch['id']}"}, single=True)
        cd = {"id": ch["id"], "name": ch.get("name"), "email": ch.get("email"), "phone": ch.get("phone"), "chef_profile": None}
        if p:
            av = await db.select("chef_availability", filters={"chef_profile_id": f"eq.{p['id']}"})
            p["availability"] = av
            cd["chef_profile"] = p
        result.append(cd)
    return _json(result)

@route("POST", "/api/v1/admin/chefs")
async def admin_chef_create(req, env):
    u, db, s, err = await _require(req, env, "admin")
    if err: return err
    d = await _body(req)
    existing = await db.select("users", filters={"email": f"eq.{d['email']}"}, single=True)
    if existing: return _err("Email already registered")
    uid = str(uuid.uuid4())
    usr = {"id": uid, "name": d["name"], "email": d["email"], "phone": d.get("phone"), "role": "chef", "is_active": True, "is_gold": False}
    ur = await db.insert("users", usr)
    prof = {"id": str(uuid.uuid4()), "user_id": uid, "bio": d.get("bio"), "specialties": d.get("specialties"), "experience_years": d.get("experience_years"), "hourly_rate": d.get("hourly_rate", 399.0), "service_city": d.get("service_city"), "is_verified": False, "is_available": True}
    await db.insert("chef_profiles", prof)
    return _json(ur[0], 201)

@route("PUT", "/api/v1/admin/chefs/{cid}")
async def admin_chef_update(req, env, cid=""):
    u, db, s, err = await _require(req, env, "admin")
    if err: return err
    d = await _body(req)
    p = await db.select("chef_profiles", filters={"user_id": f"eq.{cid}"}, single=True)
    if not p: return _err("Chef profile not found", 404)
    upd = {k: v for k, v in d.items() if k in ("bio","specialties","experience_years","hourly_rate","is_verified","is_available") and v is not None}
    if upd: await db.update("chef_profiles", upd, {"id": f"eq.{p['id']}"})
    usr = await db.select("users", filters={"id": f"eq.{cid}"}, single=True)
    return _json(usr)

@route("GET", "/api/v1/admin/bookings")
async def admin_bookings(req, env):
    u, db, s, err = await _require(req, env, "admin")
    if err: return err
    q = _qs(req)
    f = {}
    if q.get("status"): f["status"] = f"eq.{q['status']}"
    page = int(q.get("page", "1"))
    pp = int(q.get("per_page", "20"))
    total = await db.count("bookings", f if f else None)
    bks = await db.select("bookings", filters=f if f else None, order="created_at.desc", limit=pp, offset=(page - 1) * pp)
    return _json({"bookings": bks, "total": total, "page": page, "per_page": pp})

@route("PUT", "/api/v1/admin/bookings/{bid}")
async def admin_bk_update(req, env, bid=""):
    u, db, s, err = await _require(req, env, "admin")
    if err: return err
    d = await _body(req)
    upd = {"status": d["status"]}
    if d.get("chef_notes"): upd["chef_notes"] = d["chef_notes"]
    r = await db.update("bookings", upd, {"id": f"eq.{bid}"})
    if not r: return _err("Booking not found", 404)
    return _json(r[0])

@route("GET", "/api/v1/admin/locations")
async def admin_locs(req, env):
    u, db, s, err = await _require(req, env, "admin")
    if err: return err
    locs = await db.select("locations", order="city.asc")
    for loc in locs:
        loc["service_areas"] = await db.select("service_areas", filters={"location_id": f"eq.{loc['id']}"})
    return _json(locs)

@route("POST", "/api/v1/admin/locations")
async def admin_loc_add(req, env):
    u, db, s, err = await _require(req, env, "admin")
    if err: return err
    d = await _body(req)
    loc = {"id": str(uuid.uuid4()), "city": d["city"], "state": d["state"], "is_serviceable": d.get("is_serviceable", True)}
    r = (await db.insert("locations", loc))[0]
    r["service_areas"] = []
    return _json(r, 201)

@route("PUT", "/api/v1/admin/locations/{lid}")
async def admin_loc_update(req, env, lid=""):
    u, db, s, err = await _require(req, env, "admin")
    if err: return err
    d = await _body(req)
    upd = {k: v for k, v in d.items() if k in ("city","state","is_serviceable") and v is not None}
    if not upd: return _err("No updates provided")
    r = await db.update("locations", upd, {"id": f"eq.{lid}"})
    if not r: return _err("Location not found", 404)
    r[0]["service_areas"] = await db.select("service_areas", filters={"location_id": f"eq.{lid}"})
    return _json(r[0])

@route("DELETE", "/api/v1/admin/locations/{lid}")
async def admin_loc_del(req, env, lid=""):
    u, db, s, err = await _require(req, env, "admin")
    if err: return err
    await db.delete("locations", {"id": f"eq.{lid}"})
    return Response("", status=204, headers=_cors())

@route("POST", "/api/v1/admin/locations/{lid}/areas")
async def admin_area_add(req, env, lid=""):
    u, db, s, err = await _require(req, env, "admin")
    if err: return err
    d = await _body(req)
    loc = await db.select("locations", filters={"id": f"eq.{lid}"}, single=True)
    if not loc: return _err("Location not found", 404)
    area = {"id": str(uuid.uuid4()), "location_id": lid, "name": d["name"], "city": d.get("city", loc.get("city", "")), "latitude": d.get("latitude"), "longitude": d.get("longitude"), "radius_km": d.get("radius_km", 10.0), "is_active": d.get("is_active", True)}
    return _json((await db.insert("service_areas", area))[0], 201)

@route("DELETE", "/api/v1/admin/service-areas/{aid}")
async def admin_area_del(req, env, aid=""):
    u, db, s, err = await _require(req, env, "admin")
    if err: return err
    await db.delete("service_areas", {"id": f"eq.{aid}"})
    return Response("", status=204, headers=_cors())
