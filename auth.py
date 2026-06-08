"""登录 / 服务端会话 / RBAC 守门。

- 密码：stdlib pbkdf2_hmac(sha256)，格式 pbkdf2_sha256$iter$salt_hex$hash_hex。
- 会话：随机 token 存 sessions 表，cookie httpOnly+SameSite=Lax+Secure。
- 中间件：除白名单外所有路径都要登录；页面/敏感 API 再按权限码校验。
"""
import hashlib
import hmac
import os
import secrets

from fastapi import APIRouter, Request
from urllib.parse import quote
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from starlette.middleware.base import BaseHTTPMiddleware

import db

templates = Jinja2Templates(directory="templates")
COOKIE = "s2r_sess"
SECURE_COOKIE = os.getenv("S2R_COOKIE_SECURE", "1") != "0"  # report1 走 HTTPS，默认 Secure

PBKDF2_ITER = 200_000


def hash_password(pw: str) -> str:
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", pw.encode("utf-8"), salt, PBKDF2_ITER)
    return f"pbkdf2_sha256${PBKDF2_ITER}${salt.hex()}${dk.hex()}"


def verify_password(pw: str, stored: str) -> bool:
    try:
        algo, iter_s, salt_hex, hash_hex = stored.split("$")
        dk = hashlib.pbkdf2_hmac("sha256", pw.encode("utf-8"), bytes.fromhex(salt_hex), int(iter_s))
        return hmac.compare_digest(dk.hex(), hash_hex)
    except Exception:
        return False


# 白名单（无需登录）
PUBLIC_PREFIXES = ("/login", "/logout", "/favicon", "/health")

# 页面路径 → 权限码
_PAGE_PERMS = {path: code for code, _t, path, _g, _s in db.MENUS_SEED}

# API → 权限码（与所属页面同权限）。GET /api/sites 例外：各页下拉共用，仅需登录。
_API_PERMS = {
    ("POST", "/api/sites"): "page.settingsites",
    ("POST", "/api/site-test"): "page.settingsites",
    ("POST", "/api/report"): "page.usagerealtime",
    ("POST", "/api/finance"): "page.financemodel",
    ("POST", "/api/ops-aggregate"): "page.opsdingdongding",
    ("POST", "/api/ops-detail"): "page.opsdingdongding",
    ("POST", "/api/usage-cn-search"): "page.usagecnusersearch",
    ("POST", "/api/usage-cn-recharge"): "page.usagecnusersearch",
    ("POST", "/api/station-kpi"): "page.stationkpi",
    ("POST", "/api/account-health"): "page.accounthealth",
    ("POST", "/api/user-economy"): "page.usereconomy",
    ("POST", "/api/revenue"): "page.revenuereport",
    ("POST", "/api/model-profit"): "page.modelprofit",
    ("POST", "/api/alert-config"): "page.alertpush",
    ("GET", "/api/alert-config"): "page.alertpush",
    ("POST", "/api/alert-test"): "page.alertpush",
    ("POST", "/api/alert-check"): "page.alertpush",
}


def _required_perm(method: str, path: str) -> str | None:
    if path in _PAGE_PERMS:
        return _PAGE_PERMS[path]
    if (method, path) in _API_PERMS:
        return _API_PERMS[(method, path)]
    if path.startswith("/api/admin/users"):
        return "admin.users"
    if path.startswith("/api/admin/roles"):
        return "admin.roles"
    if path.startswith("/api/admin/menus"):
        return "admin.menus"
    if path.startswith("/api/admin/audit"):
        return "admin.audit"
    return None


def _is_public(path: str) -> bool:
    return any(path == p or path.startswith(p + "/") or path.startswith(p) for p in PUBLIC_PREFIXES)


class AuthMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        path = request.url.path
        request.state.user = None
        request.state.perms = set()

        token = request.cookies.get(COOKIE)
        user = await db.session_user(token) if token else None
        if user:
            request.state.user = user
            request.state.perms = await db.user_perms(user["id"])

        if _is_public(path):
            return await call_next(request)

        is_api = path.startswith("/api/")
        if not user:
            if is_api:
                return JSONResponse({"ok": False, "error": "未登录", "auth": False}, status_code=401)
            nxt = path
            if request.url.query:
                nxt = f"{path}?{request.url.query}"
            return RedirectResponse(url=f"/login?next={quote(nxt, safe='')}", status_code=302)

        # 强制改密（默认管理员 must_change_pwd=False，不触发）
        if user.get("must_change_pwd") and path not in ("/change-password",) and not is_api:
            return RedirectResponse(url="/change-password", status_code=302)

        perm = _required_perm(request.method, path)
        if perm and perm not in request.state.perms:
            if is_api:
                return JSONResponse({"ok": False, "error": "无权限"}, status_code=403)
            return HTMLResponse(_no_perm_html(), status_code=403)

        return await call_next(request)


def _no_perm_html() -> str:
    return ("<!doctype html><meta charset=utf-8><div style='font-family:sans-serif;padding:40px;color:#606266'>"
            "<h2>无访问权限</h2><p>你的角色无权访问该页面。</p>"
            "<p><a href='/portal' style='color:#409eff'>返回门户</a></p></div>")


def client_ip(request: Request) -> str:
    """取真实客户端 IP。sub2report 在 NPM 后面，直接 peer 是网关内网 IP，
    真实 IP 在转发头里（Cloudflare → CF-Connecting-IP；NPM → X-Real-IP / X-Forwarded-For）。"""
    h = request.headers
    for k in ("cf-connecting-ip", "x-real-ip"):
        v = h.get(k)
        if v and v.strip():
            return v.strip()
    xff = h.get("x-forwarded-for")
    if xff:
        first = xff.split(",")[0].strip()
        if first:
            return first
    return request.client.host if request.client else ""


def current_user(request: Request) -> dict | None:
    return getattr(request.state, "user", None)


def has_perm(request: Request, code: str) -> bool:
    return code in getattr(request.state, "perms", set())


router = APIRouter()


def _safe_next(n: str) -> str:
    """只允许站内相对路径，防开放重定向。"""
    n = (n or "").strip()
    if n.startswith("/") and not n.startswith("//"):
        return n
    return ""


@router.get("/login")
async def login_page(request: Request):
    nxt = _safe_next(request.query_params.get("next", ""))
    if current_user(request):
        return RedirectResponse(url=nxt or "/portal", status_code=302)
    return templates.TemplateResponse("login.html", {"request": request, "error": "", "next": nxt})


@router.post("/login")
async def login_submit(request: Request):
    form = await request.form()
    email = str(form.get("email", "")).strip()
    password = str(form.get("password", ""))
    nxt = _safe_next(str(form.get("next", "")))
    user = await db.user_by_email(email)
    ip = client_ip(request)
    if not user or user["status"] != "active" or not verify_password(password, user["password_hash"]):
        await db.audit("login_failed", user=user or {"email": email}, ip=ip)
        return templates.TemplateResponse("login.html", {"request": request, "error": "邮箱或密码错误", "next": nxt}, status_code=401)
    token = secrets.token_urlsafe(32)
    await db.session_create(token, user["id"], ip, request.headers.get("user-agent", "")[:300])
    await db.touch_login(user["id"])
    await db.audit("login", user=user, ip=ip)
    dest = "/change-password" if user.get("must_change_pwd") else (nxt or "/portal")
    resp = RedirectResponse(url=dest, status_code=302)
    resp.set_cookie(COOKIE, token, httponly=True, samesite="lax", secure=SECURE_COOKIE, max_age=7 * 86400, path="/")
    return resp


@router.get("/logout")
async def logout(request: Request):
    token = request.cookies.get(COOKIE)
    if token:
        await db.session_delete(token)
    resp = RedirectResponse(url="/login", status_code=302)
    resp.delete_cookie(COOKIE, path="/")
    return resp


@router.get("/change-password")
async def change_pw_page(request: Request):
    if not current_user(request):
        return RedirectResponse(url="/login", status_code=302)
    return templates.TemplateResponse("change_password.html", {"request": request, "error": "", "ok": False})


@router.post("/change-password")
async def change_pw_submit(request: Request):
    user = current_user(request)
    if not user:
        return RedirectResponse(url="/login", status_code=302)
    form = await request.form()
    old = str(form.get("old_password", ""))
    new = str(form.get("new_password", ""))
    if not verify_password(old, user["password_hash"]):
        return templates.TemplateResponse("change_password.html", {"request": request, "error": "原密码错误", "ok": False}, status_code=400)
    if len(new) < 6:
        return templates.TemplateResponse("change_password.html", {"request": request, "error": "新密码至少 6 位", "ok": False}, status_code=400)
    await db.set_password(user["id"], hash_password(new))
    await db.audit("change_password", user=user, ip=client_ip(request))
    return templates.TemplateResponse("change_password.html", {"request": request, "error": "", "ok": True})
