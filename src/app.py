"""
Sizzle API — FastAPI app for Cloudflare Workers.
All routes in one file for CF Workers Python compatibility.
Uses Supabase PostgREST + Cloudflare KV instead of SQLAlchemy + Redis.
"""

import secrets
import string
import uuid
from datetime import datetime, timedelta, timezone

from fastapi import FastAPI, Request, HTTPException, status, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional

from supabase import SupabaseClient, init_client
from auth import (
    generate_otp, store_otp, verify_otp, check_rate_limit,
    send_email_otp, create_access_token, create_refresh_token,
    decode_token, get_current_user,
)

app = FastAPI(title="Sizzle API", version="1.0.0")

# CORS — restrict to known origins only
ALLOWED_ORIGINS = [
    "https://www.sizzzle.me",
    "https://sizzzle.me",
    "https://sizzleapp.pages.dev",
    "capacitor://localhost",
    "http://localhost",
    "http://localhost:5173",
    "http://localhost:8000",
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Helpers ─────────────────────────────────────────────────

def _env(request: Request):
    """Get Cloudflare env from request scope."""
    return request.scope["env"]


def _db(request: Request) -> SupabaseClient:
    env = _env(request)
    return init_client(str(env.SUPABASE_URL), str(env.SUPABASE_SERVICE_ROLE_KEY))


def _secret(request: Request) -> str:
    return str(_env(request).JWT_SECRET_KEY)


async def _require_user(request: Request, role: str | None = None) -> dict:
    db = _db(request)
    user = await get_current_user(request, db, _secret(request))
    if not user:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    if role and user.get("role") != role:
        raise HTTPException(status_code=403, detail=f"{role.title()} access required")
    return user


def _gen_booking_ref() -> str:
    chars = string.ascii_uppercase + string.digits
    return "SZ-" + "".join(secrets.choice(chars) for _ in range(8))


def _gen_referral_code(name: str | None) -> str:
    prefix = (name or "SZ")[:4].upper().replace(" ", "")
    suffix = "".join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(6))
    return f"{prefix}{suffix}"


def _gen_gift_card_code() -> str:
    return "SZ-" + "".join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(10))


# ── Schemas ─────────────────────────────────────────────────

class OTPRequest(BaseModel):
    email: Optional[str] = None
    phone: Optional[str] = None

class OTPVerify(BaseModel):
    email: Optional[str] = None
    phone: Optional[str] = None
    otp: str

class RefreshRequest(BaseModel):
    refresh_token: str

class ProfileUpdate(BaseModel):
    name: Optional[str] = None
    phone: Optional[str] = None
    dob: Optional[str] = None
    avatar_url: Optional[str] = None

class AddressCreate(BaseModel):
    label: Optional[str] = "Home"
    full_address: str
    city: str
    state: str
    pincode: str
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    is_default: Optional[bool] = False

class BookingCreate(BaseModel):
    address_id: str
    booking_date: str
    time_slot: str
    duration_hours: int = 2
    guest_count: int = 2
    chef_id: Optional[str] = None
    occasion: Optional[str] = "general"
    cuisine_preferences: Optional[list[str]] = None
    selected_dishes: Optional[dict] = None
    menu_package_id: Optional[str] = None
    add_ons: Optional[dict] = None
    special_requests: Optional[str] = None
    use_wallet: Optional[bool] = False

class ChefProfileUpdate(BaseModel):
    bio: Optional[str] = None
    specialties: Optional[list[str]] = None
    experience_years: Optional[int] = None
    hourly_rate: Optional[float] = None
    is_verified: Optional[bool] = None
    is_available: Optional[bool] = None

class AvailabilityCreate(BaseModel):
    day_of_week: str
    start_time: str
    end_time: str
    is_available: bool = True

class BookingStatusUpdate(BaseModel):
    status: str
    chef_notes: Optional[str] = None

class AdminChefCreate(BaseModel):
    name: str
    email: str
    phone: Optional[str] = None
    bio: Optional[str] = None
    specialties: Optional[list[str]] = None
    experience_years: Optional[int] = None
    hourly_rate: Optional[float] = 399.0
    service_city: Optional[str] = None

class LocationCreate(BaseModel):
    city: str
    state: str
    is_serviceable: bool = True

class LocationUpdate(BaseModel):
    city: Optional[str] = None
    state: Optional[str] = None
    is_serviceable: Optional[bool] = None

class ServiceAreaCreate(BaseModel):
    name: str
    city: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    radius_km: Optional[float] = 10.0
    is_active: bool = True

class SubscribeRequest(BaseModel):
    plan: str

class ReviewCreate(BaseModel):
    booking_id: str
    rating: int
    food_rating: Optional[int] = None
    hygiene_rating: Optional[int] = None
    punctuality_rating: Optional[int] = None
    comment: Optional[str] = None
    photo_urls: Optional[list[str]] = None

class ReferralApply(BaseModel):
    code: str

class GiftCardCreate(BaseModel):
    amount: float
    recipient_name: Optional[str] = None
    recipient_email: Optional[str] = None
    message: Optional[str] = None
    theme: str = "congrats"

class GiftCardRedeem(BaseModel):
    code: str

class PaymentInitiate(BaseModel):
    booking_id: str


# ── Health ──────────────────────────────────────────────────

@app.get("/")
async def root():
    return {"status": "healthy", "app": "Sizzle", "version": "1.0.0"}

@app.get("/api/v1/health")
async def health():
    return {"status": "healthy", "app": "Sizzle", "version": "1.0.0"}


# ══════════════════════════════════════════════════════════════
# AUTH
# ══════════════════════════════════════════════════════════════

@app.post("/api/v1/auth/send-otp")
async def send_otp(data: OTPRequest, request: Request):
    identifier = data.email or data.phone
    if not identifier:
        raise HTTPException(status_code=400, detail="Email or phone required")

    env = _env(request)
    kv = env.OTP_STORE

    if not await check_rate_limit(kv, identifier):
        raise HTTPException(status_code=429, detail="Too many OTP requests. Try again in 5 minutes.")

    otp = generate_otp()
    await store_otp(kv, identifier, otp)

    if data.email:
        resend_key = str(getattr(env, "RESEND_API_KEY", ""))
        email_from = str(getattr(env, "EMAIL_FROM", "Sizzle <onboarding@resend.dev>"))
        await send_email_otp(resend_key, email_from, data.email, otp)

    return {"message": "OTP sent successfully", "identifier": identifier}


@app.post("/api/v1/auth/verify-otp")
async def verify_otp_endpoint(data: OTPVerify, request: Request):
    identifier = data.email or data.phone
    if not identifier:
        raise HTTPException(status_code=400, detail="Email or phone required")

    env = _env(request)
    kv = env.OTP_STORE
    db = _db(request)

    is_valid = await verify_otp(kv, identifier, data.otp)
    if not is_valid:
        raise HTTPException(status_code=400, detail="Invalid or expired OTP")

    # Get or create user
    filters = {}
    if data.email:
        filters["email"] = f"eq.{data.email}"
    elif data.phone:
        filters["phone"] = f"eq.{data.phone}"

    user = await db.select("users", filters=filters, single=True)
    is_new = False

    if not user:
        is_new = True
        new_id = str(uuid.uuid4())
        user_data = {
            "id": new_id,
            "role": "customer",
            "is_active": True,
            "is_gold": False,
        }
        if data.email:
            user_data["email"] = data.email
        if data.phone:
            user_data["phone"] = data.phone
        result = await db.insert("users", user_data)
        user = result[0]

    secret = _secret(request)
    access_token = create_access_token(user["id"], user["role"], secret)
    refresh_token = create_refresh_token(user["id"], user["role"], secret)

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "user_role": user["role"],
        "is_new_user": is_new,
    }


@app.post("/api/v1/auth/refresh")
async def refresh_token(data: RefreshRequest, request: Request):
    secret = _secret(request)
    payload = decode_token(data.refresh_token, secret)
    if not payload or payload.get("type") != "refresh":
        raise HTTPException(status_code=401, detail="Invalid refresh token")

    db = _db(request)
    user = await db.select("users", filters={"id": f"eq.{payload['sub']}"}, single=True)
    if not user or not user.get("is_active", True):
        raise HTTPException(status_code=401, detail="User not found")

    access = create_access_token(user["id"], user["role"], secret)
    refresh = create_refresh_token(user["id"], user["role"], secret)
    return {
        "access_token": access,
        "refresh_token": refresh,
        "user_role": user["role"],
    }


# ══════════════════════════════════════════════════════════════
# CUSTOMER
# ══════════════════════════════════════════════════════════════

@app.get("/api/v1/customer/profile")
async def get_customer_profile(request: Request):
    user = await _require_user(request)
    return user


@app.put("/api/v1/customer/profile")
async def update_customer_profile(data: ProfileUpdate, request: Request):
    user = await _require_user(request)
    db = _db(request)
    update = data.model_dump(exclude_unset=True)
    if not update:
        return user
    result = await db.update("users", update, {"id": f"eq.{user['id']}"})
    return result[0] if result else user


# ── Addresses ───────────────────────────────────────────────

@app.get("/api/v1/customer/addresses")
async def list_addresses(request: Request):
    user = await _require_user(request)
    db = _db(request)
    return await db.select(
        "addresses",
        filters={"user_id": f"eq.{user['id']}"},
        order="is_default.desc",
    )


@app.post("/api/v1/customer/addresses", status_code=201)
async def add_address(data: AddressCreate, request: Request):
    user = await _require_user(request)
    db = _db(request)

    if data.is_default:
        await db.update(
            "addresses",
            {"is_default": False},
            {"user_id": f"eq.{user['id']}", "is_default": "eq.true"},
        )

    addr = {
        "id": str(uuid.uuid4()),
        "user_id": user["id"],
        **data.model_dump(),
    }
    result = await db.insert("addresses", addr)
    return result[0]


# ── Bookings ────────────────────────────────────────────────

@app.post("/api/v1/customer/bookings", status_code=201)
async def create_booking(data: BookingCreate, request: Request):
    user = await _require_user(request, role="customer")
    db = _db(request)

    # Verify address
    addr = await db.select(
        "addresses",
        filters={"id": f"eq.{data.address_id}", "user_id": f"eq.{user['id']}"},
        single=True,
    )
    if not addr:
        raise HTTPException(status_code=400, detail="Address not found")

    # Pricing
    base_rate = 399.0
    if data.chef_id:
        profile = await db.select(
            "chef_profiles",
            filters={"user_id": f"eq.{data.chef_id}"},
            single=True,
        )
        if profile:
            base_rate = profile.get("hourly_rate", 399.0)

    chef_cost = base_rate * data.duration_hours
    extra_guests = max(0, data.guest_count - 4)
    guest_surcharge = extra_guests * 49.0 * data.duration_hours

    hour = int(data.time_slot.split(":")[0])
    peak_mult = 1.2 if 18 <= hour <= 21 else 1.0
    subtotal = (chef_cost + guest_surcharge) * peak_mult
    platform_fee = round(subtotal * 0.05, 2)
    gst = round((subtotal + platform_fee) * 0.05, 2)
    total = round(subtotal + platform_fee + gst, 2)

    booking = {
        "id": str(uuid.uuid4()),
        "customer_id": user["id"],
        "chef_id": data.chef_id,
        "address_id": data.address_id,
        "booking_date": data.booking_date,
        "time_slot": data.time_slot,
        "duration_hours": data.duration_hours,
        "guest_count": data.guest_count,
        "occasion": data.occasion or "general",
        "cuisine_preferences": data.cuisine_preferences,
        "selected_dishes": data.selected_dishes,
        "menu_package_id": data.menu_package_id,
        "add_ons": data.add_ons,
        "special_requests": data.special_requests,
        "total_amount": total,
        "wallet_amount_used": 0,
        "discount_amount": 0,
        "status": "pending",
        "booking_ref": _gen_booking_ref(),
        "rating_submitted": False,
    }
    result = await db.insert("bookings", booking)
    b = result[0]

    # Enrich with names
    b["customer_name"] = user.get("name")
    b["chef_name"] = None
    b["address_text"] = addr.get("full_address")
    b["payment_status"] = None
    return b


@app.get("/api/v1/customer/bookings")
async def list_customer_bookings(
    request: Request,
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=50),
):
    user = await _require_user(request, role="customer")
    db = _db(request)

    total = await db.count("bookings", {"customer_id": f"eq.{user['id']}"})
    bookings = await db.select(
        "bookings",
        filters={"customer_id": f"eq.{user['id']}"},
        order="created_at.desc",
        limit=per_page,
        offset=(page - 1) * per_page,
    )
    return {"bookings": bookings, "total": total, "page": page, "per_page": per_page}


@app.get("/api/v1/customer/bookings/{booking_id}")
async def get_customer_booking(booking_id: str, request: Request):
    user = await _require_user(request, role="customer")
    db = _db(request)
    booking = await db.select(
        "bookings",
        filters={"id": f"eq.{booking_id}", "customer_id": f"eq.{user['id']}"},
        single=True,
    )
    if not booking:
        raise HTTPException(status_code=404, detail="Booking not found")
    return booking


# ══════════════════════════════════════════════════════════════
# MENU
# ══════════════════════════════════════════════════════════════

CUISINES = [
    "north_indian", "south_indian", "chinese", "italian", "continental",
    "thai", "japanese", "mexican", "mediterranean", "mughlai",
    "street_food", "desserts", "beverages", "fusion",
]

OCCASIONS = {
    "house_party": {"name": "House Party", "icon": "🏠", "color": "#F97316"},
    "birthday": {"name": "Birthday", "icon": "🎂", "color": "#EC4899"},
    "anniversary": {"name": "Anniversary", "icon": "💍", "color": "#EF4444"},
    "date_night": {"name": "Date Night", "icon": "💕", "color": "#F43F5E"},
    "family_dinner": {"name": "Family Dinner", "icon": "👨\u200d👩\u200d👧", "color": "#8B5CF6"},
    "pooja": {"name": "Pooja / Religious", "icon": "🙏", "color": "#F59E0B"},
    "baby_shower": {"name": "Baby Shower", "icon": "👶", "color": "#06B6D4"},
    "house_warming": {"name": "House Warming", "icon": "🏡", "color": "#10B981"},
    "kitty_party": {"name": "Kitty Party", "icon": "🎊", "color": "#D946EF"},
    "high_tea": {"name": "High Tea / Brunch", "icon": "☕", "color": "#78716C"},
    "corporate": {"name": "Corporate Event", "icon": "🏢", "color": "#3B82F6"},
    "wedding": {"name": "Wedding Event", "icon": "💒", "color": "#E11D48"},
    "weekend_brunch": {"name": "Weekend Brunch", "icon": "🍳", "color": "#F97316"},
    "cooking_class": {"name": "Cooking Class", "icon": "📚", "color": "#6366F1"},
    "general": {"name": "General", "icon": "🍽️", "color": "#6B7280"},
}


@app.get("/api/v1/menu/cuisines")
async def list_cuisines():
    return [{"id": c, "name": c.replace("_", " ").title()} for c in CUISINES]


@app.get("/api/v1/menu/occasions")
async def list_occasions():
    return [{"id": k, **v} for k, v in OCCASIONS.items()]


@app.get("/api/v1/menu/dishes")
async def browse_dishes(
    request: Request,
    cuisine: str | None = None,
    search: str | None = None,
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=50),
):
    db = _db(request)
    filters: dict[str, str] = {"is_available": "eq.true"}
    if cuisine:
        filters["cuisine"] = f"eq.{cuisine}"
    if search:
        filters["name"] = f"ilike.*{search}*"

    total = await db.count("dishes", filters)
    dishes = await db.select(
        "dishes",
        filters=filters,
        order="is_signature.desc,created_at.desc",
        limit=per_page,
        offset=(page - 1) * per_page,
    )
    return {"dishes": dishes, "total": total, "page": page, "per_page": per_page}


# ══════════════════════════════════════════════════════════════
# WALLET
# ══════════════════════════════════════════════════════════════

async def _get_or_create_wallet(db: SupabaseClient, user_id: str) -> dict:
    wallet = await db.select("wallets", filters={"user_id": f"eq.{user_id}"}, single=True)
    if not wallet:
        wallet_data = {
            "id": str(uuid.uuid4()),
            "user_id": user_id,
            "balance": 0,
            "total_earned": 0,
            "total_spent": 0,
        }
        result = await db.insert("wallets", wallet_data)
        wallet = result[0]
    return wallet


async def _credit_wallet(db: SupabaseClient, user_id: str, amount: float, reason: str, description: str, reference_id: str | None = None):
    wallet = await _get_or_create_wallet(db, user_id)
    new_balance = wallet["balance"] + amount
    new_earned = wallet["total_earned"] + amount
    await db.update("wallets", {"balance": new_balance, "total_earned": new_earned}, {"id": f"eq.{wallet['id']}"})
    txn = {
        "id": str(uuid.uuid4()),
        "wallet_id": wallet["id"],
        "user_id": user_id,
        "type": "credit",
        "amount": amount,
        "reason": reason,
        "description": description,
        "reference_id": reference_id,
    }
    await db.insert("wallet_transactions", txn)


@app.get("/api/v1/wallet")
async def get_wallet(request: Request):
    user = await _require_user(request)
    db = _db(request)
    wallet = await _get_or_create_wallet(db, user["id"])
    return wallet


@app.get("/api/v1/wallet/transactions")
async def get_wallet_transactions(request: Request, limit: int = Query(50, ge=1, le=200)):
    user = await _require_user(request)
    db = _db(request)
    wallet = await _get_or_create_wallet(db, user["id"])
    txns = await db.select(
        "wallet_transactions",
        filters={"user_id": f"eq.{user['id']}"},
        order="created_at.desc",
        limit=limit,
    )
    return {"transactions": txns, "balance": wallet["balance"], "total": len(txns)}


# ══════════════════════════════════════════════════════════════
# GAMIFICATION
# ══════════════════════════════════════════════════════════════

LEVEL_NAMES = {1: "Foodie", 2: "Gourmet", 3: "Connoisseur", 4: "Master Chef", 5: "Legend"}
LEVEL_THRESHOLDS = {1: 0, 2: 200, 3: 500, 4: 1000, 5: 2500}
BADGE_CATALOG = {
    "first_booking": {"name": "First Bite", "icon": "🍽️", "description": "Made your first booking"},
    "first_review": {"name": "Critic", "icon": "⭐", "description": "Left your first review"},
    "gold_member": {"name": "Gold Member", "icon": "👑", "description": "Subscribed to Sizzle Gold"},
    "referrer": {"name": "Ambassador", "icon": "🤝", "description": "Referred a friend"},
    "big_spender": {"name": "Big Spender", "icon": "💰", "description": "Spent ₹10,000+"},
    "streak_3": {"name": "Hat Trick", "icon": "🔥", "description": "3 bookings in a row"},
    "streak_7": {"name": "Weekly Regular", "icon": "🗓️", "description": "7 bookings streak"},
    "five_star": {"name": "Five Star", "icon": "🌟", "description": "Gave a 5-star review"},
}


async def _get_or_create_gamification(db: SupabaseClient, user_id: str) -> dict:
    gam = await db.select("gamification_profiles", filters={"user_id": f"eq.{user_id}"}, single=True)
    if not gam:
        gam_data = {
            "id": str(uuid.uuid4()),
            "user_id": user_id,
            "points": 0,
            "level": 1,
            "badges": [],
            "total_bookings_count": 0,
            "streak_count": 0,
            "total_spent": 0,
        }
        result = await db.insert("gamification_profiles", gam_data)
        gam = result[0]
    return gam


def _gamification_response(gam: dict) -> dict:
    level = gam.get("level", 1)
    points = gam.get("points", 0)
    next_level = min(level + 1, 5)
    next_threshold = LEVEL_THRESHOLDS.get(next_level, 2500)
    current_threshold = LEVEL_THRESHOLDS.get(level, 0)
    progress = min(100, int((points - current_threshold) / max(1, next_threshold - current_threshold) * 100))

    return {
        "points": points,
        "level": level,
        "level_name": LEVEL_NAMES.get(level, "Foodie"),
        "progress_pct": progress,
        "next_level_points": next_threshold,
        "badges": gam.get("badges", []),
        "total_bookings_count": gam.get("total_bookings_count", 0),
        "streak_count": gam.get("streak_count", 0),
        "total_spent": gam.get("total_spent", 0),
    }


@app.get("/api/v1/gamification/profile")
async def get_gamification_profile(request: Request):
    user = await _require_user(request)
    db = _db(request)
    gam = await _get_or_create_gamification(db, user["id"])
    return _gamification_response(gam)


@app.get("/api/v1/gamification/badges")
async def list_badges():
    return [{"id": k, **v} for k, v in BADGE_CATALOG.items()]


@app.get("/api/v1/gamification/levels")
async def list_levels():
    return [{"id": k, "name": v, "min_points": LEVEL_THRESHOLDS[k]} for k, v in LEVEL_NAMES.items()]


# ══════════════════════════════════════════════════════════════
# SUBSCRIPTION
# ══════════════════════════════════════════════════════════════

PLAN_DETAILS = {
    "monthly": {"name": "Monthly", "price": 299, "discount_pct": 10, "credits": 100, "duration_days": 30},
    "quarterly": {"name": "Quarterly", "price": 749, "discount_pct": 15, "credits": 300, "duration_days": 90},
    "yearly": {"name": "Yearly", "price": 2499, "discount_pct": 20, "credits": 1000, "duration_days": 365},
}


@app.get("/api/v1/subscription/plans")
async def list_plans():
    return [
        {
            "plan": plan,
            "name": d["name"],
            "price": d["price"],
            "discount_pct": d["discount_pct"],
            "credits": d["credits"],
            "duration_days": d["duration_days"],
            "features": [
                f"{d['discount_pct']}% off all bookings",
                f"₹{d['credits']} wallet credits",
                "Priority chef matching",
                "Exclusive gold member badges",
                "Free cancellation",
            ],
        }
        for plan, d in PLAN_DETAILS.items()
    ]


@app.get("/api/v1/subscription")
async def get_subscription(request: Request):
    user = await _require_user(request)
    db = _db(request)
    sub = await db.select(
        "subscriptions",
        filters={"user_id": f"eq.{user['id']}"},
        order="created_at.desc",
        limit=1,
    )
    if not sub:
        return {"active": False, "subscription": None}
    s = sub[0]
    return {"active": s.get("status") == "active", "subscription": s}


@app.post("/api/v1/subscription/subscribe")
async def subscribe(data: SubscribeRequest, request: Request):
    user = await _require_user(request)
    db = _db(request)

    if data.plan not in PLAN_DETAILS:
        raise HTTPException(status_code=400, detail="Invalid plan")

    details = PLAN_DETAILS[data.plan]

    # Check existing
    existing = await db.select(
        "subscriptions",
        filters={"user_id": f"eq.{user['id']}", "status": "eq.active"},
        single=True,
    )
    if existing:
        raise HTTPException(status_code=400, detail="You already have an active subscription")

    now = datetime.now(timezone.utc).isoformat()
    expires = (datetime.now(timezone.utc) + timedelta(days=details["duration_days"])).isoformat()

    sub = {
        "id": str(uuid.uuid4()),
        "user_id": user["id"],
        "plan": data.plan,
        "status": "active",
        "price_paid": details["price"],
        "discount_pct": details["discount_pct"],
        "credits_granted": details["credits"],
        "starts_at": now,
        "expires_at": expires,
    }
    result = await db.insert("subscriptions", sub)

    # Mark gold + credit wallet
    await db.update("users", {"is_gold": True}, {"id": f"eq.{user['id']}"})
    if details["credits"] > 0:
        await _credit_wallet(db, user["id"], details["credits"], "subscription_reward", f"Sizzle Gold {details['name']} credits")

    return {
        "message": f"🎉 Welcome to Sizzle Gold {details['name']}!",
        "subscription": result[0] if result else sub,
        "wallet_credits": details["credits"],
    }


@app.post("/api/v1/subscription/cancel")
async def cancel_subscription(request: Request):
    user = await _require_user(request)
    db = _db(request)

    subs = await db.select(
        "subscriptions",
        filters={"user_id": f"eq.{user['id']}", "status": "eq.active"},
    )
    if not subs:
        raise HTTPException(status_code=404, detail="No active subscription found")

    now = datetime.now(timezone.utc).isoformat()
    await db.update("subscriptions", {"status": "cancelled", "cancelled_at": now}, {"id": f"eq.{subs[0]['id']}"})
    await db.update("users", {"is_gold": False}, {"id": f"eq.{user['id']}"})
    return {"message": "Subscription cancelled. You'll retain benefits until expiry."}


# ══════════════════════════════════════════════════════════════
# REVIEWS
# ══════════════════════════════════════════════════════════════

@app.post("/api/v1/reviews", status_code=201)
async def submit_review(data: ReviewCreate, request: Request):
    user = await _require_user(request)
    db = _db(request)

    booking = await db.select("bookings", filters={"id": f"eq.{data.booking_id}"}, single=True)
    if not booking:
        raise HTTPException(status_code=404, detail="Booking not found")
    if booking["customer_id"] != user["id"]:
        raise HTTPException(status_code=403, detail="Not your booking")
    if booking.get("status") != "completed":
        raise HTTPException(status_code=400, detail="Can only review completed bookings")

    existing = await db.select("reviews", filters={"booking_id": f"eq.{data.booking_id}"}, single=True)
    if existing:
        raise HTTPException(status_code=400, detail="Already reviewed this booking")

    review = {
        "id": str(uuid.uuid4()),
        "booking_id": data.booking_id,
        "customer_id": user["id"],
        "chef_id": booking.get("chef_id"),
        "rating": data.rating,
        "food_rating": data.food_rating,
        "hygiene_rating": data.hygiene_rating,
        "punctuality_rating": data.punctuality_rating,
        "comment": data.comment,
        "photo_urls": data.photo_urls,
    }
    await db.insert("reviews", review)
    await db.update("bookings", {"rating_submitted": True}, {"id": f"eq.{data.booking_id}"})

    # Award points
    gam = await _get_or_create_gamification(db, user["id"])
    badges = list(gam.get("badges") or [])
    if "first_review" not in badges:
        badges.append("first_review")
    await db.update("gamification_profiles", {"points": gam["points"] + 20, "badges": badges}, {"id": f"eq.{gam['id']}"})

    return {"id": review["id"], "booking_id": data.booking_id, "rating": data.rating, "message": "Thanks for your review! +20 Sizzle points earned 🎉"}


# ══════════════════════════════════════════════════════════════
# REFERRAL
# ══════════════════════════════════════════════════════════════

@app.get("/api/v1/referral")
async def get_referral(request: Request):
    user = await _require_user(request)
    db = _db(request)

    referral = await db.select("referrals", filters={"referrer_id": f"eq.{user['id']}"}, single=True)
    if not referral:
        code = _gen_referral_code(user.get("name"))
        ref_data = {
            "id": str(uuid.uuid4()),
            "referrer_id": user["id"],
            "referral_code": code,
            "total_referrals": 0,
            "total_earned": 0,
        }
        result = await db.insert("referrals", ref_data)
        referral = result[0]

    conversions = await db.select("referral_uses", filters={"referral_id": f"eq.{referral['id']}"})
    return {
        "referral_code": referral["referral_code"],
        "total_referrals": referral["total_referrals"],
        "total_earned": referral["total_earned"],
        "share_message": f"🍳 Use my code {referral['referral_code']} to get ₹100 off on Sizzle! Book a chef at home. Download now!",
        "conversions": conversions,
    }


@app.post("/api/v1/referral/apply")
async def apply_referral(data: ReferralApply, request: Request):
    user = await _require_user(request)
    db = _db(request)

    existing = await db.select("referral_uses", filters={"referred_user_id": f"eq.{user['id']}"}, single=True)
    if existing:
        raise HTTPException(status_code=400, detail="You've already used a referral code")

    code = data.code.upper().strip()
    referral = await db.select("referrals", filters={"referral_code": f"eq.{code}"}, single=True)
    if not referral:
        raise HTTPException(status_code=404, detail="Invalid referral code")
    if referral["referrer_id"] == user["id"]:
        raise HTTPException(status_code=400, detail="You can't use your own referral code")

    use = {
        "id": str(uuid.uuid4()),
        "referral_id": referral["id"],
        "referred_user_id": user["id"],
        "status": "completed",
        "referrer_reward": 150.0,
        "referee_discount": 100.0,
    }
    await db.insert("referral_uses", use)

    await db.update("referrals", {
        "total_referrals": referral["total_referrals"] + 1,
        "total_earned": referral["total_earned"] + 150.0,
    }, {"id": f"eq.{referral['id']}"})

    await _credit_wallet(db, referral["referrer_id"], 150.0, "referral_bonus", f"Referral bonus — {user.get('name', 'a friend')} joined!")
    await _credit_wallet(db, user["id"], 100.0, "referral_reward", f"Welcome bonus — referred by code {code}")
    await db.update("users", {"referred_by_code": code}, {"id": f"eq.{user['id']}"})

    return {"message": "🎉 Referral applied! ₹100 added to your wallet", "wallet_credit": 100.0}


# ══════════════════════════════════════════════════════════════
# GIFT CARDS
# ══════════════════════════════════════════════════════════════

GIFT_THEMES = [
    {"id": "birthday", "name": "Birthday", "icon": "🎂", "color": "#EC4899"},
    {"id": "anniversary", "name": "Anniversary", "icon": "💍", "color": "#EF4444"},
    {"id": "thank_you", "name": "Thank You", "icon": "🙏", "color": "#10B981"},
    {"id": "congrats", "name": "Congratulations", "icon": "🎉", "color": "#F97316"},
    {"id": "love", "name": "With Love", "icon": "❤️", "color": "#E11D48"},
    {"id": "festive", "name": "Festival", "icon": "🪔", "color": "#F59E0B"},
    {"id": "housewarming", "name": "Housewarming", "icon": "🏡", "color": "#6366F1"},
]


@app.get("/api/v1/gift-cards/themes")
async def list_gift_themes():
    return GIFT_THEMES


@app.post("/api/v1/gift-cards", status_code=201)
async def purchase_gift_card(data: GiftCardCreate, request: Request):
    user = await _require_user(request)
    db = _db(request)

    if data.amount < 100 or data.amount > 25000:
        raise HTTPException(status_code=400, detail="Amount must be ₹100 - ₹25,000")

    code = _gen_gift_card_code()
    expires = (datetime.now(timezone.utc) + timedelta(days=365)).isoformat()

    card = {
        "id": str(uuid.uuid4()),
        "purchaser_id": user["id"],
        "code": code,
        "amount": data.amount,
        "balance": data.amount,
        "recipient_name": data.recipient_name,
        "recipient_email": data.recipient_email,
        "message": data.message,
        "theme": data.theme,
        "status": "active",
        "expires_at": expires,
    }
    result = await db.insert("gift_cards", card)
    c = result[0]
    c["share_text"] = f"🎁 You've received a ₹{int(data.amount)} Sizzle Gift Card! Use code {code} to redeem."
    return c


@app.post("/api/v1/gift-cards/redeem")
async def redeem_gift_card(data: GiftCardRedeem, request: Request):
    user = await _require_user(request)
    db = _db(request)

    code = data.code.upper().strip()
    card = await db.select("gift_cards", filters={"code": f"eq.{code}"}, single=True)
    if not card:
        raise HTTPException(status_code=404, detail="Invalid gift card code")
    if card.get("status") != "active":
        raise HTTPException(status_code=400, detail=f"Gift card is {card.get('status')}")
    if card.get("balance", 0) <= 0:
        raise HTTPException(status_code=400, detail="Gift card has no balance")

    amount = card["balance"]
    await db.update("gift_cards", {"balance": 0, "status": "redeemed", "redeemed_by_id": user["id"]}, {"id": f"eq.{card['id']}"})
    await _credit_wallet(db, user["id"], amount, "gift_card_redeem", f"Gift card {code} redeemed", reference_id=card["id"])

    return {"message": f"🎉 ₹{int(amount)} added to your wallet!", "amount": amount}


@app.get("/api/v1/gift-cards/my-cards")
async def my_gift_cards(request: Request):
    user = await _require_user(request)
    db = _db(request)
    return await db.select(
        "gift_cards",
        filters={"purchaser_id": f"eq.{user['id']}"},
        order="created_at.desc",
    )


# ══════════════════════════════════════════════════════════════
# PAYMENTS
# ══════════════════════════════════════════════════════════════

@app.post("/api/v1/payments/initiate")
async def initiate_payment(data: PaymentInitiate, request: Request):
    user = await _require_user(request, role="customer")
    db = _db(request)

    booking = await db.select("bookings", filters={"id": f"eq.{data.booking_id}"}, single=True)
    if not booking:
        raise HTTPException(status_code=404, detail="Booking not found")
    if booking["customer_id"] != user["id"]:
        raise HTTPException(status_code=403, detail="Not your booking")

    return {
        "success": True,
        "message": "Payment simulation — demo mode",
        "payment_url": None,
        "booking_id": data.booking_id,
        "amount": booking.get("total_amount", 0),
    }


# ══════════════════════════════════════════════════════════════
# CHEF
# ══════════════════════════════════════════════════════════════

@app.get("/api/v1/chef/profile")
async def get_chef_profile(request: Request):
    user = await _require_user(request, role="chef")
    db = _db(request)

    profile = await db.select("chef_profiles", filters={"user_id": f"eq.{user['id']}"}, single=True)
    availability = []
    if profile:
        availability = await db.select("chef_availability", filters={"chef_profile_id": f"eq.{profile['id']}"})

    return {"user": user, "profile": profile, "availability": availability}


@app.put("/api/v1/chef/profile")
async def update_chef_profile(data: ChefProfileUpdate, request: Request):
    user = await _require_user(request, role="chef")
    db = _db(request)

    profile = await db.select("chef_profiles", filters={"user_id": f"eq.{user['id']}"}, single=True)
    update_data = data.model_dump(exclude_unset=True)

    if not profile:
        profile_data = {"id": str(uuid.uuid4()), "user_id": user["id"], **update_data}
        result = await db.insert("chef_profiles", profile_data)
        profile = result[0]
    else:
        if update_data:
            result = await db.update("chef_profiles", update_data, {"id": f"eq.{profile['id']}"})
            profile = result[0] if result else profile

    availability = await db.select("chef_availability", filters={"chef_profile_id": f"eq.{profile['id']}"})
    return {"user": user, "profile": profile, "availability": availability}


@app.post("/api/v1/chef/availability", status_code=201)
async def add_chef_availability(data: AvailabilityCreate, request: Request):
    user = await _require_user(request, role="chef")
    db = _db(request)

    profile = await db.select("chef_profiles", filters={"user_id": f"eq.{user['id']}"}, single=True)
    if not profile:
        raise HTTPException(status_code=404, detail="Chef profile not found")

    slot = {
        "id": str(uuid.uuid4()),
        "chef_profile_id": profile["id"],
        "day_of_week": data.day_of_week,
        "start_time": data.start_time,
        "end_time": data.end_time,
        "is_available": data.is_available,
    }
    result = await db.insert("chef_availability", slot)
    return result[0]


@app.delete("/api/v1/chef/availability/{slot_id}", status_code=204)
async def delete_chef_availability(slot_id: str, request: Request):
    user = await _require_user(request, role="chef")
    db = _db(request)

    profile = await db.select("chef_profiles", filters={"user_id": f"eq.{user['id']}"}, single=True)
    if not profile:
        raise HTTPException(status_code=404, detail="Chef profile not found")
    await db.delete("chef_availability", {"id": f"eq.{slot_id}", "chef_profile_id": f"eq.{profile['id']}"})


@app.get("/api/v1/chef/bookings")
async def list_chef_bookings(
    request: Request,
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=50),
    status: str | None = None,
):
    user = await _require_user(request, role="chef")
    db = _db(request)

    filters: dict[str, str] = {"chef_id": f"eq.{user['id']}"}
    if status:
        filters["status"] = f"eq.{status}"
    total = await db.count("bookings", filters)
    bookings = await db.select(
        "bookings", filters=filters, order="created_at.desc",
        limit=per_page, offset=(page - 1) * per_page,
    )
    return {"bookings": bookings, "total": total, "page": page, "per_page": per_page}


@app.put("/api/v1/chef/bookings/{booking_id}/status")
async def update_chef_booking_status(booking_id: str, data: BookingStatusUpdate, request: Request):
    user = await _require_user(request, role="chef")
    db = _db(request)

    booking = await db.select("bookings", filters={"id": f"eq.{booking_id}", "chef_id": f"eq.{user['id']}"}, single=True)
    if not booking:
        raise HTTPException(status_code=404, detail="Booking not found")

    update = {"status": data.status}
    if data.chef_notes:
        update["chef_notes"] = data.chef_notes
    result = await db.update("bookings", update, {"id": f"eq.{booking_id}"})
    return result[0] if result else booking


# ══════════════════════════════════════════════════════════════
# ADMIN
# ══════════════════════════════════════════════════════════════

@app.get("/api/v1/admin/stats")
async def get_admin_stats(request: Request):
    await _require_user(request, role="admin")
    db = _db(request)

    total_customers = await db.count("users", {"role": "eq.customer"})
    total_chefs = await db.count("users", {"role": "eq.chef"})
    total_bookings = await db.count("bookings")
    pending = await db.count("bookings", {"status": "eq.pending"})
    confirmed = await db.count("bookings", {"status": "eq.confirmed"})
    completed = await db.count("bookings", {"status": "eq.completed"})
    cancelled = await db.count("bookings", {"status": "eq.cancelled"})
    active_locations = await db.count("locations", {"is_serviceable": "eq.true"})

    # Revenue from completed bookings
    completed_bookings = await db.select("bookings", columns="total_amount", filters={"status": "eq.completed"})
    total_revenue = sum(float(b.get("total_amount", 0)) for b in completed_bookings)

    return {
        "total_users": total_customers + total_chefs,
        "total_customers": total_customers,
        "total_chefs": total_chefs,
        "total_bookings": total_bookings,
        "pending_bookings": pending,
        "confirmed_bookings": confirmed,
        "completed_bookings": completed,
        "cancelled_bookings": cancelled,
        "total_revenue": total_revenue,
        "active_locations": active_locations,
    }


@app.get("/api/v1/admin/chefs")
async def list_admin_chefs(request: Request):
    await _require_user(request, role="admin")
    db = _db(request)

    chefs = await db.select("users", filters={"role": "eq.chef"}, order="created_at.desc")
    result = []
    for chef in chefs:
        profile = await db.select("chef_profiles", filters={"user_id": f"eq.{chef['id']}"}, single=True)
        chef_data = {
            "id": chef["id"],
            "name": chef.get("name"),
            "email": chef.get("email"),
            "phone": chef.get("phone"),
            "chef_profile": None,
        }
        if profile:
            availability = await db.select("chef_availability", filters={"chef_profile_id": f"eq.{profile['id']}"})
            profile["availability"] = availability
            chef_data["chef_profile"] = profile
        result.append(chef_data)
    return result


@app.post("/api/v1/admin/chefs", status_code=201)
async def create_admin_chef(data: AdminChefCreate, request: Request):
    await _require_user(request, role="admin")
    db = _db(request)

    existing = await db.select("users", filters={"email": f"eq.{data.email}"}, single=True)
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")

    user_id = str(uuid.uuid4())
    user = {
        "id": user_id,
        "name": data.name,
        "email": data.email,
        "phone": data.phone,
        "role": "chef",
        "is_active": True,
        "is_gold": False,
    }
    user_result = await db.insert("users", user)

    profile = {
        "id": str(uuid.uuid4()),
        "user_id": user_id,
        "bio": data.bio,
        "specialties": data.specialties,
        "experience_years": data.experience_years,
        "hourly_rate": data.hourly_rate,
        "service_city": data.service_city,
        "is_verified": False,
        "is_available": True,
    }
    await db.insert("chef_profiles", profile)
    return user_result[0]


@app.put("/api/v1/admin/chefs/{chef_id}")
async def update_admin_chef(chef_id: str, data: ChefProfileUpdate, request: Request):
    await _require_user(request, role="admin")
    db = _db(request)

    profile = await db.select("chef_profiles", filters={"user_id": f"eq.{chef_id}"}, single=True)
    if not profile:
        raise HTTPException(status_code=404, detail="Chef profile not found")

    update_data = data.model_dump(exclude_unset=True)
    if update_data:
        await db.update("chef_profiles", update_data, {"id": f"eq.{profile['id']}"})

    user = await db.select("users", filters={"id": f"eq.{chef_id}"}, single=True)
    return user


@app.get("/api/v1/admin/bookings")
async def list_admin_bookings(
    request: Request,
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=50),
    status: str | None = None,
):
    await _require_user(request, role="admin")
    db = _db(request)

    filters: dict[str, str] = {}
    if status:
        filters["status"] = f"eq.{status}"
    total = await db.count("bookings", filters)
    bookings = await db.select(
        "bookings", filters=filters, order="created_at.desc",
        limit=per_page, offset=(page - 1) * per_page,
    )
    return {"bookings": bookings, "total": total, "page": page, "per_page": per_page}


@app.put("/api/v1/admin/bookings/{booking_id}")
async def update_admin_booking(booking_id: str, data: BookingStatusUpdate, request: Request):
    await _require_user(request, role="admin")
    db = _db(request)

    update = {"status": data.status}
    if data.chef_notes:
        update["chef_notes"] = data.chef_notes
    result = await db.update("bookings", update, {"id": f"eq.{booking_id}"})
    if not result:
        raise HTTPException(status_code=404, detail="Booking not found")
    return result[0]


# ── Locations ───────────────────────────────────────────────

@app.get("/api/v1/admin/locations")
async def list_locations(request: Request):
    await _require_user(request, role="admin")
    db = _db(request)

    locations = await db.select("locations", order="city.asc")
    for loc in locations:
        loc["service_areas"] = await db.select("service_areas", filters={"location_id": f"eq.{loc['id']}"})
    return locations


@app.post("/api/v1/admin/locations", status_code=201)
async def add_location(data: LocationCreate, request: Request):
    await _require_user(request, role="admin")
    db = _db(request)

    loc = {"id": str(uuid.uuid4()), **data.model_dump()}
    result = await db.insert("locations", loc)
    r = result[0]
    r["service_areas"] = []
    return r


@app.put("/api/v1/admin/locations/{location_id}")
async def update_location(location_id: str, data: LocationUpdate, request: Request):
    await _require_user(request, role="admin")
    db = _db(request)

    update_data = data.model_dump(exclude_unset=True)
    if not update_data:
        raise HTTPException(status_code=400, detail="No updates provided")
    result = await db.update("locations", update_data, {"id": f"eq.{location_id}"})
    if not result:
        raise HTTPException(status_code=404, detail="Location not found")
    r = result[0]
    r["service_areas"] = await db.select("service_areas", filters={"location_id": f"eq.{location_id}"})
    return r


@app.delete("/api/v1/admin/locations/{location_id}", status_code=204)
async def delete_location(location_id: str, request: Request):
    await _require_user(request, role="admin")
    db = _db(request)
    await db.delete("locations", {"id": f"eq.{location_id}"})


@app.post("/api/v1/admin/locations/{location_id}/areas", status_code=201)
async def add_service_area(location_id: str, data: ServiceAreaCreate, request: Request):
    await _require_user(request, role="admin")
    db = _db(request)

    loc = await db.select("locations", filters={"id": f"eq.{location_id}"}, single=True)
    if not loc:
        raise HTTPException(status_code=404, detail="Location not found")

    area = {
        "id": str(uuid.uuid4()),
        "location_id": location_id,
        "name": data.name,
        "city": data.city or loc.get("city", ""),
        "latitude": data.latitude,
        "longitude": data.longitude,
        "radius_km": data.radius_km,
        "is_active": data.is_active,
    }
    result = await db.insert("service_areas", area)
    return result[0]


@app.delete("/api/v1/admin/service-areas/{area_id}", status_code=204)
async def delete_service_area(area_id: str, request: Request):
    await _require_user(request, role="admin")
    db = _db(request)
    await db.delete("service_areas", {"id": f"eq.{area_id}"})
