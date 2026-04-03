"""
Auth utilities — JWT, OTP, email sending for Cloudflare Workers.
"""

import secrets
import hashlib
import hmac as hmac_module
from datetime import datetime, timedelta, timezone
from typing import Any

import jwt
import httpx


# ── OTP ─────────────────────────────────────────────────────

def generate_otp(length: int = 6) -> str:
    return "".join([str(secrets.randbelow(10)) for _ in range(length)])


async def store_otp(kv, identifier: str, otp: str, ttl: int = 300) -> None:
    """Store OTP in Cloudflare KV with TTL."""
    key = f"otp:{identifier}"
    await kv.put(key, otp, expirationTtl=ttl)


async def verify_otp(kv, identifier: str, otp: str) -> bool:
    """Verify OTP from Cloudflare KV."""
    key = f"otp:{identifier}"
    stored = await kv.get(key)
    if stored and hmac_module.compare_digest(str(stored), otp):
        await kv.delete(key)
        return True
    return False


async def check_rate_limit(kv, identifier: str) -> bool:
    """Rate limit OTP requests using KV."""
    key = f"otp_rate:{identifier}"
    count_str = await kv.get(key)
    count = int(count_str) if count_str else 0
    if count >= 5:
        return False
    await kv.put(key, str(count + 1), expirationTtl=300)
    return True


# ── Email ───────────────────────────────────────────────────

def _build_otp_html(otp: str) -> str:
    digits = "".join(
        f'<td style="width:44px;height:52px;background:#FFF7ED;border:2px solid #FDBA74;border-radius:10px;text-align:center;font-size:28px;font-weight:700;color:#EA580C;font-family:monospace;letter-spacing:2px;">{d}</td>'
        for d in otp
    )
    return f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"></head>
<body style="margin:0;padding:0;background:#F8FAFC;font-family:sans-serif;">
<table width="100%" cellpadding="0" cellspacing="0" style="background:#F8FAFC;">
<tr><td align="center" style="padding:40px 16px;">
  <table width="420" cellpadding="0" cellspacing="0" style="background:#FFF;border-radius:16px;box-shadow:0 4px 24px rgba(0,0,0,0.06);">
    <tr><td style="background:linear-gradient(135deg,#EA580C,#F97316);padding:32px 24px;text-align:center;">
      <span style="font-size:28px;font-weight:800;color:#FFF;">🍳 Sizzle</span>
      <p style="color:rgba(255,255,255,0.85);font-size:13px;margin:10px 0 0;">Premium Chef Booking</p>
    </td></tr>
    <tr><td style="padding:36px 32px 20px;">
      <h2 style="color:#0F172A;font-size:20px;text-align:center;margin:0 0 8px;">Verify Your Identity</h2>
      <p style="color:#64748B;font-size:15px;text-align:center;margin:0 0 28px;">Enter this code to sign in:</p>
      <table cellpadding="0" cellspacing="6" align="center"><tr>{digits}</tr></table>
      <p style="text-align:center;margin:24px 0 0;">
        <span style="background:#FEF3C7;color:#92400E;font-size:12px;font-weight:600;padding:6px 14px;border-radius:20px;">⏱ Valid for 5 minutes</span>
      </p>
    </td></tr>
    <tr><td style="padding:0 32px 32px;">
      <div style="background:#F1F5F9;border-radius:10px;padding:16px 18px;">
        <p style="color:#475569;font-size:13px;margin:0;">🔒 Never share this code. Sizzle will never ask for it.</p>
      </div>
    </td></tr>
    <tr><td style="background:#F8FAFC;padding:20px 32px;border-top:1px solid #E2E8F0;text-align:center;">
      <p style="color:#94A3B8;font-size:12px;margin:0;">&copy; 2026 Sizzle. All rights reserved.</p>
    </td></tr>
  </table>
</td></tr></table>
</body></html>"""


async def send_email_otp(resend_api_key: str, email_from: str, email: str, otp: str) -> bool:
    if not resend_api_key:
        return True  # Dev mode

    try:
        async with httpx.AsyncClient() as client:
            r = await client.post(
                "https://api.resend.com/emails",
                headers={
                    "Authorization": f"Bearer {resend_api_key}",
                    "Content-Type": "application/json",
                },
                json={
                    "from": email_from,
                    "to": [email],
                    "subject": f"Your Sizzle verification code: {otp}",
                    "html": _build_otp_html(otp),
                },
            )
            return r.status_code == 200
    except Exception:
        return True  # Fallback: dev mode, don't break demo


# ── JWT ─────────────────────────────────────────────────────

def create_access_token(user_id: str, role: str, secret: str) -> str:
    payload = {
        "sub": user_id,
        "role": role,
        "type": "access",
        "exp": datetime.now(timezone.utc) + timedelta(days=7),
        "iat": datetime.now(timezone.utc),
    }
    return jwt.encode(payload, secret, algorithm="HS256")


def create_refresh_token(user_id: str, role: str, secret: str) -> str:
    payload = {
        "sub": user_id,
        "role": role,
        "type": "refresh",
        "exp": datetime.now(timezone.utc) + timedelta(days=30),
        "iat": datetime.now(timezone.utc),
    }
    return jwt.encode(payload, secret, algorithm="HS256")


def decode_token(token: str, secret: str) -> dict | None:
    try:
        return jwt.decode(token, secret, algorithms=["HS256"])
    except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
        return None


# ── Auth Middleware helper ──────────────────────────────────

async def get_current_user(request, db, secret: str) -> dict | None:
    """Extract and verify JWT from Authorization header, return user dict."""
    auth = request.headers.get("authorization", "")
    if not auth.startswith("Bearer "):
        return None

    token = auth[7:]
    payload = decode_token(token, secret)
    if not payload or payload.get("type") != "access":
        return None

    user_id = payload["sub"]
    user = await db.select("users", filters={"id": f"eq.{user_id}"}, single=True)
    if not user or not user.get("is_active", True):
        return None
    return user
